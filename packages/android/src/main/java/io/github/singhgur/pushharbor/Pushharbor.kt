package io.github.singhgur.pushharbor

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import androidx.core.content.ContextCompat
import kotlinx.coroutines.future.await
import org.json.JSONObject
import java.net.InetAddress
import java.net.URL
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CopyOnWriteArrayList

/** A failed call; [code] is one of the `ERR_*` constants (same codes as the JavaScript API). */
class PushharborException(val code: String, message: String) : Exception(message) {
  companion object {
    /** No challenge push arrived after 3 tries (~90 s). The message can be shown to the user. */
    const val ERR_CHALLENGE_TIMEOUT = "ERR_CHALLENGE_TIMEOUT"
    /** The relay refused; the message has its error code. */
    const val ERR_RELAY = "ERR_RELAY"
    /** The relay is unreachable. */
    const val ERR_NETWORK = "ERR_NETWORK"
    /** The relay is on a private network address: request [Pushharbor.LOCAL_NETWORK_PERMISSION] first. */
    const val ERR_LOCAL_NETWORK = "ERR_LOCAL_NETWORK"
    /** The subscription's keys can't be read on this device. */
    const val ERR_KEYS = "ERR_KEYS"
    /** Anything else. */
    const val ERR_PUSHHARBOR = "ERR_PUSHHARBOR"
  }
}

/**
 * A Web Push subscription as the app's server expects it, plus [id] to unregister it. Hand
 * [toJson] to your server.
 */
data class PushSubscription(val id: String, val endpoint: String, val p256dh: String, val auth: String) {
  /** `{id, endpoint, expirationTime: null, keys: {p256dh, auth}}`, the browser `PushSubscription` JSON plus `id`. */
  fun toJson(): String = JSONObject()
    .put("id", id)
    .put("endpoint", endpoint)
    .put("expirationTime", JSONObject.NULL)
    .put("keys", JSONObject().put("p256dh", p256dh).put("auth", auth))
    .toString()
}

/** Receives every decrypted message, on a background thread. */
fun interface MessageListener {
  fun onMessage(message: Message)
}

/**
 * Pushharbor client: registers this device with an app's relay, decrypts incoming pushes and
 * shows those with a title or body as notifications (also when the app is not running).
 *
 * Calls run one at a time on a background thread. Failures are [PushharborException]s.
 */
object Pushharbor {
  private const val TAG = "Pushharbor"

  /** Android 17+ runtime permission for reaching a relay on a private network address. */
  const val LOCAL_NETWORK_PERMISSION = "android.permission.ACCESS_LOCAL_NETWORK"

  /** Android 17 protects local-network access behind a runtime permission (PH-18). */
  private const val LOCAL_NETWORK_SDK = 37

  private val listeners = CopyOnWriteArrayList<MessageListener>()

  /**
   * Creates a subscription on the relay at [relayUrl] that only the server owning the VAPID key
   * [senderKey] (uncompressed P-256 public key, base64url) can send to. Proves to the relay that
   * this device receives its pushes first, which takes about a second (up to ~90 s on failure).
   */
  suspend fun register(context: Context, relayUrl: String, senderKey: String): PushSubscription =
    registerAsync(context, relayUrl, senderKey).await()

  /** Subscriptions on this device. Keep them in sync with your server. */
  suspend fun subscriptions(context: Context): List<PushSubscription> = subscriptionsAsync(context).await()

  /** Deletes the subscription on the relay and its keys on the device. Tell your server too. */
  suspend fun unregister(context: Context, id: String) {
    unregisterAsync(context, id).await()
  }

  /** [register] for Java. */
  @JvmStatic
  fun registerAsync(context: Context, relayUrl: String, senderKey: String): CompletableFuture<PushSubscription> {
    val app = context.applicationContext
    return background {
      if (needsLocalNetworkPermission(app, relayUrl)) {
        throw PushharborException(
          PushharborException.ERR_LOCAL_NETWORK,
          "The relay is on a local network: request $LOCAL_NETWORK_PERMISSION first",
        )
      }
      val subscription = Registrar.register(app, relayUrl, senderKey)
      toPublic(subscription)
        ?: throw PushharborException(PushharborException.ERR_KEYS, "subscription keys unavailable")
    }
  }

  /** [subscriptions] for Java. */
  @JvmStatic
  fun subscriptionsAsync(context: Context): CompletableFuture<List<PushSubscription>> {
    val app = context.applicationContext
    // Subscriptions whose keys can't be unwrapped (data restored elsewhere) are useless.
    return background { Subscriptions.all(app).mapNotNull(::toPublic) }
  }

  /** [unregister] for Java. */
  @JvmStatic
  fun unregisterAsync(context: Context, id: String): CompletableFuture<Void?> {
    val app = context.applicationContext
    return background {
      Registrar.unregister(app, id)
      null
    }
  }

  /**
   * Moves the relay endpoints to this device's current FCM ID if it changed while the app was not
   * running. Call once at app start (e.g. `Application.onCreate`); returns immediately.
   */
  @JvmStatic
  fun refreshTarget(context: Context) {
    val app = context.applicationContext
    Registrar.executor.execute {
      try {
        Registrar.rotate(app, Registrar.currentTarget())
      } catch (e: Exception) {
        Log.w(TAG, "target check failed: ${e.javaClass.simpleName}")
      }
    }
  }

  /** Called for every decrypted message (also data-only ones) while the app process runs. */
  @JvmStatic
  fun addMessageListener(listener: MessageListener) {
    listeners.addIfAbsent(listener)
  }

  @JvmStatic
  fun removeMessageListener(listener: MessageListener) {
    listeners.remove(listener)
  }

  /** True on Android 13+ until the app holds `POST_NOTIFICATIONS`; request it before registering. */
  @JvmStatic
  fun needsNotificationPermission(context: Context): Boolean =
    Build.VERSION.SDK_INT >= 33 &&
      ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED

  /**
   * True when [relayUrl] is a literal private or link-local address and the app lacks
   * [LOCAL_NETWORK_PERMISSION] (Android 17+); [register] fails with `ERR_LOCAL_NETWORK` then.
   */
  @JvmStatic
  fun needsLocalNetworkPermission(context: Context, relayUrl: String): Boolean {
    if (Build.VERSION.SDK_INT < LOCAL_NETWORK_SDK) return false
    if (ContextCompat.checkSelfPermission(context, LOCAL_NETWORK_PERMISSION) == PackageManager.PERMISSION_GRANTED) return false
    // Literal addresses only: resolving names here would block; private DNS names are the app's call.
    val host = runCatching { URL(relayUrl).host }.getOrNull() ?: return false
    if (!host.all { it.isDigit() || it == '.' || it == ':' }) return false
    val address = runCatching { InetAddress.getByName(host) }.getOrNull() ?: return false
    return address.isSiteLocalAddress || address.isLinkLocalAddress
  }

  /** Called by [PushService] for every decrypted message. */
  internal fun dispatch(message: Message) {
    for (listener in listeners) {
      try {
        listener.onMessage(message)
      } catch (e: Exception) {
        Log.w(TAG, "message listener failed: ${e.javaClass.simpleName}")
      }
    }
  }

  private fun toPublic(s: Subscription): PushSubscription? {
    val secrets = Subscriptions.secrets(s) ?: return null
    return PushSubscription(s.keyId, s.endpoint, s.p256dh, b64url(secrets.auth))
  }

  /** Runs [block] on the registration thread; unexpected failures become `ERR_PUSHHARBOR`. */
  private fun <T> background(block: () -> T): CompletableFuture<T> = CompletableFuture.supplyAsync({
    try {
      block()
    } catch (e: PushharborException) {
      throw e
    } catch (e: Exception) {
      throw PushharborException(PushharborException.ERR_PUSHHARBOR, e.javaClass.simpleName)
    }
  }, Registrar.executor)
}
