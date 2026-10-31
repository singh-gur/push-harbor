package dev.pushharbor.expo

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import java.security.KeyFactory
import java.security.KeyStore
import java.security.interfaces.ECPrivateKey
import java.security.spec.PKCS8EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

fun b64url(bytes: ByteArray): String = Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)

fun unb64url(value: String): ByteArray = Base64.decode(value, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)

/** One confirmed subscription. Secret material stays wrapped until [Subscriptions.secrets]. */
data class Subscription(
  /** Key ID, sent by the relay as `s` with every push; also the JS-facing subscription ID. */
  val keyId: String,
  val relayUrl: String,
  val endpointId: String,
  val endpoint: String,
  val senderKey: String,
  /** FCM Firebase Installation ID the relay currently delivers to. */
  val target: String,
  val p256dh: String,
  /** PKCS#8 private key + 16-byte auth secret, encrypted with a non-exportable Keystore AES key. */
  val wrapped: String,
) {
  fun toJson(): JSONObject = JSONObject()
    .put("keyId", keyId).put("relayUrl", relayUrl).put("endpointId", endpointId).put("endpoint", endpoint)
    .put("senderKey", senderKey).put("target", target).put("p256dh", p256dh).put("wrapped", wrapped)

  companion object {
    fun fromJson(j: JSONObject) = Subscription(
      j.getString("keyId"), j.getString("relayUrl"), j.getString("endpointId"), j.getString("endpoint"),
      j.getString("senderKey"), j.getString("target"), j.getString("p256dh"), j.getString("wrapped"),
    )
  }
}

class Secrets(val private: ECPrivateKey, val public: ByteArray, val auth: ByteArray)

/**
 * Subscriptions in app-private SharedPreferences. The private key and auth secret are encrypted
 * with an AES-GCM key that never leaves the Android Keystore (API 23+), so a copy of the app's
 * files (e.g. a backup) is useless; ECDH itself runs in software after unwrapping.
 * shortcut: software ECDH on unwrapped keys; Keystore-native ECDH (API 31+) would keep the
 * private key in secure hardware, worth it if the threat model ever needs it.
 */
object Subscriptions {
  private const val PREFS = "pushharbor"
  private const val KEY_ALIAS = "pushharbor_wrap"

  private fun prefs(context: Context) = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

  @Synchronized
  fun all(context: Context): List<Subscription> {
    val raw = prefs(context).getString("subscriptions", null) ?: return emptyList()
    val array = JSONArray(raw)
    return (0 until array.length()).map { Subscription.fromJson(array.getJSONObject(it)) }
  }

  fun find(context: Context, keyId: String) = all(context).firstOrNull { it.keyId == keyId }

  @Synchronized
  fun put(context: Context, subscription: Subscription) {
    val rest = all(context).filter { it.keyId != subscription.keyId }
    save(context, rest + subscription)
  }

  @Synchronized
  fun remove(context: Context, keyId: String) = save(context, all(context).filter { it.keyId != keyId })

  private fun save(context: Context, list: List<Subscription>) {
    val array = JSONArray().apply { list.forEach { put(it.toJson()) } }
    prefs(context).edit().putString("subscriptions", array.toString()).commit()
  }

  /** Wraps a fresh key pair's private key and auth secret for storage. */
  fun wrap(privatePkcs8: ByteArray, auth: ByteArray): String {
    val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, wrappingKey()) }
    val plain = byteArrayOf(auth.size.toByte()) + auth + privatePkcs8
    return b64url(cipher.iv + cipher.doFinal(plain))
  }

  /** Null when the wrapping key is gone (app data restored on another device, Keystore reset). */
  fun secrets(subscription: Subscription): Secrets? = try {
    val raw = unb64url(subscription.wrapped)
    val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply {
      init(Cipher.DECRYPT_MODE, wrappingKey(create = false), GCMParameterSpec(128, raw.copyOfRange(0, 12)))
    }
    val plain = cipher.doFinal(raw, 12, raw.size - 12)
    val authLen = plain[0].toInt()
    val auth = plain.copyOfRange(1, 1 + authLen)
    val private = KeyFactory.getInstance("EC")
      .generatePrivate(PKCS8EncodedKeySpec(plain.copyOfRange(1 + authLen, plain.size))) as ECPrivateKey
    Secrets(private, unb64url(subscription.p256dh), auth)
  } catch (e: Exception) {
    null
  }

  @Synchronized
  private fun wrappingKey(create: Boolean = true): SecretKey {
    val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    (store.getKey(KEY_ALIAS, null) as? SecretKey)?.let { return it }
    check(create) { "wrapping key missing" }
    return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").run {
      init(
        KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
          .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
          .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
          .setKeySize(256)
          .build(),
      )
      generateKey()
    }
  }
}
