package dev.pushharbor.expo

import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPrivateKeySpec
import java.security.spec.ECPublicKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** RFC 8291 Web Push decryption (`aes128gcm`, RFC 8188). Pure JVM so it runs in unit tests. */
object Rfc8291 {
  private const val KEY_LEN = 65
  private const val HEADER_LEN = 21 + KEY_LEN

  fun generateKeyPair(): KeyPair =
    KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()

  private val curve: ECParameterSpec by lazy { (generateKeyPair().public as ECPublicKey).params }

  fun privateKey(d: ByteArray): ECPrivateKey =
    KeyFactory.getInstance("EC").generatePrivate(ECPrivateKeySpec(BigInteger(1, d), curve)) as ECPrivateKey

  fun publicKey(raw: ByteArray): ECPublicKey {
    require(raw.size == KEY_LEN && raw[0] == 4.toByte()) { "not an uncompressed P-256 point" }
    val point = ECPoint(BigInteger(1, raw.copyOfRange(1, 33)), BigInteger(1, raw.copyOfRange(33, 65)))
    return KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(point, curve)) as ECPublicKey
  }

  /** Uncompressed SEC1 encoding (`p256dh`). */
  fun rawPublicKey(key: ECPublicKey): ByteArray = byteArrayOf(4) + fixed32(key.w.affineX) + fixed32(key.w.affineY)

  /** Throws on any malformed, multi-record or unauthenticated message. */
  fun decrypt(body: ByteArray, uaPrivate: ECPrivateKey, uaPublic: ByteArray, authSecret: ByteArray): ByteArray {
    require(body.size > HEADER_LEN) { "too short" }
    val salt = body.copyOfRange(0, 16)
    val rs = ByteBuffer.wrap(body, 16, 4).int.toLong() and 0xffffffffL
    require((body[20].toInt() and 0xff) == KEY_LEN) { "keyid must be the sender's P-256 public key" }
    val asPublic = body.copyOfRange(21, HEADER_LEN)
    val record = body.copyOfRange(HEADER_LEN, body.size)
    // The relay only forwards single-record bodies (spec: send.md).
    require(rs >= 18 && record.size <= rs) { "only single-record messages are supported" }

    val ecdh = KeyAgreement.getInstance("ECDH").run {
      init(uaPrivate)
      doPhase(publicKey(asPublic), true)
      generateSecret()
    }
    val prkKey = hmac(authSecret, ecdh)
    val ikm = hmac(prkKey, "WebPush: info".toByteArray() + byteArrayOf(0) + uaPublic + asPublic + byteArrayOf(1))
    val prk = hmac(salt, ikm)
    val cek = hmac(prk, "Content-Encoding: aes128gcm".toByteArray() + byteArrayOf(0, 1)).copyOf(16)
    val nonce = hmac(prk, "Content-Encoding: nonce".toByteArray() + byteArrayOf(0, 1)).copyOf(12)

    val padded = Cipher.getInstance("AES/GCM/NoPadding").run {
      init(Cipher.DECRYPT_MODE, SecretKeySpec(cek, "AES"), GCMParameterSpec(128, nonce))
      doFinal(record)
    }
    val end = padded.indexOfLast { it != 0.toByte() }
    require(end >= 0 && padded[end] == 2.toByte()) { "missing last-record padding delimiter" }
    return padded.copyOf(end)
  }

  private fun hmac(key: ByteArray, data: ByteArray): ByteArray =
    Mac.getInstance("HmacSHA256").run {
      init(SecretKeySpec(key, "HmacSHA256"))
      doFinal(data)
    }

  private fun fixed32(n: BigInteger): ByteArray {
    val b = n.toByteArray()
    return if (b.size >= 32) b.copyOfRange(b.size - 32, b.size) else ByteArray(32 - b.size) + b
  }
}
