package dev.pushharbor.spike

import android.content.Context
import android.util.Base64
import java.security.KeyFactory
import java.security.SecureRandom
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.PKCS8EncodedKeySpec

fun b64url(bytes: ByteArray): String = Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)

fun unb64url(value: String): ByteArray = Base64.decode(value, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)

class Keys(val private: ECPrivateKey, val public: ByteArray, val auth: ByteArray)

/** App-private storage for the subscription keys and spike counters. */
object Store {
  // shortcut: plain app-private SharedPreferences; PH-7 should move the private key to the Android Keystore (ECDH needs API 31+)
  private fun prefs(context: Context) = context.getSharedPreferences("pushharbor_spike", Context.MODE_PRIVATE)

  @Synchronized
  fun keys(context: Context): Keys {
    val p = prefs(context)
    if (!p.contains("private")) {
      val pair = Rfc8291.generateKeyPair()
      val auth = ByteArray(16).also { SecureRandom().nextBytes(it) }
      p.edit()
        .putString("private", b64url(pair.private.encoded))
        .putString("public", b64url(Rfc8291.rawPublicKey(pair.public as ECPublicKey)))
        .putString("auth", b64url(auth))
        .commit()
    }
    val private = KeyFactory.getInstance("EC")
      .generatePrivate(PKCS8EncodedKeySpec(unb64url(p.getString("private", null)!!))) as ECPrivateKey
    return Keys(private, unb64url(p.getString("public", null)!!), unb64url(p.getString("auth", null)!!))
  }

  @Synchronized
  fun record(context: Context, outcome: String) {
    val p = prefs(context)
    p.edit()
      .putInt(outcome, p.getInt(outcome, 0) + 1)
      .putString("last", outcome)
      .putLong("lastAt", System.currentTimeMillis())
      .commit()
  }

  fun stats(context: Context): Map<String, Any?> {
    val p = prefs(context)
    return mapOf(
      "shown" to p.getInt("shown", 0),
      "dropped" to p.getInt("dropped", 0),
      "ignored" to p.getInt("ignored", 0),
      "noPermission" to p.getInt("no-permission", 0),
      "last" to p.getString("last", null),
      "lastAt" to p.getLong("lastAt", 0),
    )
  }
}
