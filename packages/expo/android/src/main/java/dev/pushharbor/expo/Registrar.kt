package dev.pushharbor.expo

import android.content.Context
import android.util.Log
import com.google.android.gms.tasks.Tasks
import com.google.firebase.installations.FirebaseInstallations
import com.google.firebase.messaging.FirebaseMessaging
import org.json.JSONObject
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.security.SecureRandom
import java.security.interfaces.ECPublicKey
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

/** Error surfaced to JS as a rejected promise with [code]. */
class PushharborException(val code: String, message: String) : Exception(message)

/**
 * Registration with challenge proof of possession (spec: registration.md). Blocking; call from
 * [executor]. Runs natively so target rotation also works without the JS runtime.
 */
object Registrar {
  private const val TAG = "Pushharbor"
  /** How long to wait for each challenge push before asking for a resend (spec: 30 s). */
  private const val CHALLENGE_WAIT_SECS = 30L
  private const val MAX_CHALLENGE_SENDS = 3

  val executor = Executors.newSingleThreadExecutor()

  /** Registrations this app started and has not finished: only these challenges are answered. */
  private val pending = ConcurrentHashMap<String, CompletableFuture<String>>()

  /** Called by [PushService] for every challenge push. */
  fun onChallenge(rid: String, nonce: String) {
    pending[rid]?.complete(nonce)
  }

  /** The device's current FCM target (Firebase Installation ID). */
  fun currentTarget(): String {
    Tasks.await(FirebaseMessaging.getInstance().register(), 30, TimeUnit.SECONDS)
    return Tasks.await(FirebaseInstallations.getInstance().id, 30, TimeUnit.SECONDS)
  }

  /** New subscription bound to the server's VAPID key [senderKey]. */
  fun register(context: Context, relayUrl: String, senderKey: String): Subscription {
    val relay = relayUrl.trimEnd('/')
    val target = currentTarget()
    val pair = Rfc8291.generateKeyPair()
    val auth = ByteArray(16).also { SecureRandom().nextBytes(it) }
    val keyId = b64url(ByteArray(12).also { SecureRandom().nextBytes(it) })
    val confirmed = challengeFlow(relay, target, keyId, senderKey, replaces = null)
    val subscription = Subscription(
      keyId = keyId,
      relayUrl = relay,
      endpointId = confirmed.getString("id"),
      endpoint = confirmed.getString("endpoint"),
      senderKey = senderKey,
      target = target,
      p256dh = b64url(Rfc8291.rawPublicKey(pair.public as ECPublicKey)),
      wrapped = Subscriptions.wrap(pair.private.encoded, auth),
    )
    Subscriptions.put(context, subscription)
    return subscription
  }

  /** Moves every subscription whose target is stale to [target], keeping its endpoint. */
  fun rotate(context: Context, target: String) {
    for (subscription in Subscriptions.all(context).filter { it.target != target }) {
      try {
        challengeFlow(subscription.relayUrl, target, subscription.keyId, subscription.senderKey, subscription.endpointId)
        Subscriptions.put(context, subscription.copy(target = target))
      } catch (e: PushharborException) {
        // The endpoint still points at the old target; retried on the next rotation check.
        Log.w(TAG, "target rotation failed: ${e.code}")
      }
    }
  }

  fun unregister(context: Context, keyId: String) {
    val subscription = Subscriptions.find(context, keyId) ?: return
    val (status, _) = http("DELETE", "${subscription.relayUrl}/v1/push/${subscription.endpointId}", null)
    if (status != 204 && status != 404) throw PushharborException("ERR_RELAY", "unregister failed with HTTP $status")
    Subscriptions.remove(context, keyId)
  }

  private fun challengeFlow(relay: String, target: String, keyId: String, senderKey: String, replaces: String?): JSONObject {
    val request = JSONObject()
      .put("platform", "fcm").put("target", target).put("key_id", keyId).put("sender_key", senderKey)
    replaces?.let { request.put("replaces", it) }
    val rid = expect(http("POST", "$relay/v1/registrations", request), 202).getString("rid")
    val answer = CompletableFuture<String>()
    pending[rid] = answer
    try {
      var sends = 1
      while (true) {
        try {
          val nonce = answer.get(CHALLENGE_WAIT_SECS, TimeUnit.SECONDS)
          // Answer only to the configured relay, never to a URL from the push.
          return expect(http("POST", "$relay/v1/registrations/$rid/confirm", JSONObject().put("c", nonce)), 201)
        } catch (e: TimeoutException) {
          if (sends >= MAX_CHALLENGE_SENDS) {
            throw PushharborException(
              "ERR_CHALLENGE_TIMEOUT",
              "Couldn't set up notifications on this device. Make sure you're online and Google Play services is up to date, then try again.",
            )
          }
          expect(http("POST", "$relay/v1/registrations/$rid/challenge", JSONObject()), 202)
          sends++
        }
      }
    } finally {
      pending.remove(rid)
    }
  }

  private fun expect(response: Pair<Int, JSONObject?>, status: Int): JSONObject {
    val (got, body) = response
    if (got == status && body != null) return body
    val code = body?.optString("error").orEmpty().ifEmpty { "http_$got" }
    throw PushharborException("ERR_RELAY", "relay answered $got $code")
  }

  /** Small JSON-over-HTTP call; never logs URLs or bodies (endpoint IDs are capabilities). */
  private fun http(method: String, url: String, body: JSONObject?): Pair<Int, JSONObject?> = try {
    val conn = URL(url).openConnection() as HttpURLConnection
    conn.requestMethod = method
    conn.connectTimeout = 10_000
    conn.readTimeout = 15_000
    if (body != null) {
      conn.doOutput = true
      conn.setRequestProperty("Content-Type", "application/json")
      conn.outputStream.use { it.write(body.toString().toByteArray()) }
    }
    val status = conn.responseCode
    val stream = if (status >= 400) conn.errorStream else conn.inputStream
    val text = stream?.bufferedReader()?.use { it.readText() }.orEmpty()
    status to (if (text.isBlank()) JSONObject() else runCatching { JSONObject(text) }.getOrNull())
  } catch (e: IOException) {
    throw PushharborException("ERR_NETWORK", "cannot reach the relay: ${e.javaClass.simpleName}")
  }
}
