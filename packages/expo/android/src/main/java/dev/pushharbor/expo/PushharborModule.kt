package dev.pushharbor.expo

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import androidx.core.content.ContextCompat
import expo.modules.interfaces.permissions.Permissions
import expo.modules.kotlin.Promise
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import java.lang.ref.WeakReference
import java.net.InetAddress
import java.net.URL

class PushharborModule : Module() {
  private val context: Context get() = requireNotNull(appContext.reactContext).applicationContext

  override fun definition() = ModuleDefinition {
    Name("Pushharbor")
    Events("onMessage")

    OnCreate {
      active = WeakReference(this@PushharborModule)
      // Catch target changes that happened while the app was not running.
      val context = appContext.reactContext?.applicationContext ?: return@OnCreate
      Registrar.executor.execute {
        try {
          Registrar.rotate(context, Registrar.currentTarget())
        } catch (e: Exception) {
          Log.w("Pushharbor", "target check failed: ${e.javaClass.simpleName}")
        }
      }
    }

    OnDestroy {
      if (active?.get() === this@PushharborModule) active = null
    }

    AsyncFunction("register") { relayUrl: String, senderKey: String, promise: Promise ->
      val context = context
      if (needsLocalNetworkPermission(context, relayUrl)) {
        return@AsyncFunction promise.reject(
          "ERR_LOCAL_NETWORK",
          "The relay is on a local network: call requestLocalNetworkPermission() first",
          null,
        )
      }
      Registrar.executor.execute {
        settle(promise) { toJs(Registrar.register(context, relayUrl, senderKey)) }
      }
    }

    AsyncFunction("getSubscriptions") { promise: Promise ->
      val context = context
      Registrar.executor.execute {
        // Subscriptions whose keys can't be unwrapped (data restored elsewhere) are useless.
        settle(promise) {
          Subscriptions.all(context).filter { Subscriptions.secrets(it) != null }.map(::toJs)
        }
      }
    }

    AsyncFunction("unregister") { id: String, promise: Promise ->
      val context = context
      Registrar.executor.execute { settle(promise) { Registrar.unregister(context, id) } }
    }

    AsyncFunction("requestNotificationPermission") { promise: Promise ->
      if (Build.VERSION.SDK_INT < 33) return@AsyncFunction promise.resolve(true)
      ask(promise, Manifest.permission.POST_NOTIFICATIONS)
    }

    AsyncFunction("requestLocalNetworkPermission") { promise: Promise ->
      if (Build.VERSION.SDK_INT < LOCAL_NETWORK_SDK) return@AsyncFunction promise.resolve(true)
      ask(promise, LOCAL_NETWORK_PERMISSION)
    }
  }

  private fun ask(promise: Promise, permission: String) {
    val permissions = appContext.permissions ?: return promise.reject("ERR_PERMISSIONS", "permissions unavailable", null)
    permissions.askForPermissions({ result -> promise.resolve(result[permission]?.status?.name == "GRANTED") }, permission)
  }

  private fun settle(promise: Promise, block: () -> Any?) {
    try {
      promise.resolve(block())
    } catch (e: PushharborException) {
      promise.reject(e.code, e.message, null)
    } catch (e: Exception) {
      promise.reject("ERR_PUSHHARBOR", e.javaClass.simpleName, null)
    }
  }

  /** The Web Push subscription the app hands to its server, plus the ID to unregister it. */
  private fun toJs(s: Subscription): Map<String, Any?> {
    val auth = Subscriptions.secrets(s)?.auth ?: throw PushharborException("ERR_KEYS", "subscription keys unavailable")
    return mapOf(
      "id" to s.keyId,
      "endpoint" to s.endpoint,
      "expirationTime" to null,
      "keys" to mapOf("p256dh" to s.p256dh, "auth" to b64url(auth)),
    )
  }

  companion object {
    /** Android 17 protects local-network access behind a runtime permission (PH-18). */
    private const val LOCAL_NETWORK_SDK = 37
    private const val LOCAL_NETWORK_PERMISSION = "android.permission.ACCESS_LOCAL_NETWORK"

    @Volatile
    private var active: WeakReference<PushharborModule>? = null

    /** Delivers a decrypted message to JS if the app is running; otherwise it is only shown. */
    fun emit(envelope: Envelope) {
      val module = active?.get() ?: return
      module.sendEvent(
        "onMessage",
        mapOf("title" to envelope.title, "body" to envelope.body, "url" to envelope.url, "tag" to envelope.tag, "data" to envelope.data),
      )
    }

    private fun needsLocalNetworkPermission(context: Context, relayUrl: String): Boolean {
      if (Build.VERSION.SDK_INT < LOCAL_NETWORK_SDK) return false
      if (ContextCompat.checkSelfPermission(context, LOCAL_NETWORK_PERMISSION) == PackageManager.PERMISSION_GRANTED) return false
      // Literal addresses only: resolving names here would block; private DNS names are the app's call.
      val host = runCatching { URL(relayUrl).host }.getOrNull() ?: return false
      if (!host.all { it.isDigit() || it == '.' || it == ':' }) return false
      val address = runCatching { InetAddress.getByName(host) }.getOrNull() ?: return false
      return address.isSiteLocalAddress || address.isLinkLocalAddress
    }
  }
}
