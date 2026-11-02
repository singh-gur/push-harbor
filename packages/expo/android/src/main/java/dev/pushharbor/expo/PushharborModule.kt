package dev.pushharbor.expo

import android.Manifest
import android.content.Context
import android.os.Build
import expo.modules.kotlin.Promise
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import io.github.singhgur.pushharbor.MessageListener
import io.github.singhgur.pushharbor.PushSubscription
import io.github.singhgur.pushharbor.Pushharbor
import io.github.singhgur.pushharbor.PushharborException
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CompletionException

/** JS bridge over the pushharbor-android library (bundled as Gradle project :pushharbor-android). */
class PushharborModule : Module() {
  private val context: Context get() = requireNotNull(appContext.reactContext).applicationContext

  /** Delivers decrypted messages to JS while the app is running; otherwise they are only shown. */
  private val listener = MessageListener { m ->
    sendEvent("onMessage", mapOf("title" to m.title, "body" to m.body, "url" to m.url, "tag" to m.tag, "data" to m.data))
  }

  override fun definition() = ModuleDefinition {
    Name("Pushharbor")
    Events("onMessage")

    OnCreate {
      Pushharbor.addMessageListener(listener)
      // Catch target changes that happened while the app was not running.
      appContext.reactContext?.let { Pushharbor.refreshTarget(it) }
    }

    OnDestroy {
      Pushharbor.removeMessageListener(listener)
    }

    AsyncFunction("register") { relayUrl: String, senderKey: String, promise: Promise ->
      if (Pushharbor.needsLocalNetworkPermission(context, relayUrl)) {
        return@AsyncFunction promise.reject(
          PushharborException.ERR_LOCAL_NETWORK,
          "The relay is on a local network: call requestLocalNetworkPermission() first",
          null,
        )
      }
      settle(promise, Pushharbor.registerAsync(context, relayUrl, senderKey), ::toJs)
    }

    AsyncFunction("getSubscriptions") { promise: Promise ->
      settle(promise, Pushharbor.subscriptionsAsync(context)) { it.map(::toJs) }
    }

    AsyncFunction("unregister") { id: String, promise: Promise ->
      settle(promise, Pushharbor.unregisterAsync(context, id)) { null }
    }

    AsyncFunction("requestNotificationPermission") { promise: Promise ->
      if (Build.VERSION.SDK_INT < 33) return@AsyncFunction promise.resolve(true)
      ask(promise, Manifest.permission.POST_NOTIFICATIONS)
    }

    AsyncFunction("requestLocalNetworkPermission") { promise: Promise ->
      if (Build.VERSION.SDK_INT < LOCAL_NETWORK_SDK) return@AsyncFunction promise.resolve(true)
      ask(promise, Pushharbor.LOCAL_NETWORK_PERMISSION)
    }
  }

  private fun ask(promise: Promise, permission: String) {
    val permissions = appContext.permissions ?: return promise.reject("ERR_PERMISSIONS", "permissions unavailable", null)
    permissions.askForPermissions({ result -> promise.resolve(result[permission]?.status?.name == "GRANTED") }, permission)
  }

  private fun <T> settle(promise: Promise, future: CompletableFuture<T>, toJs: (T) -> Any?) {
    future.whenComplete { value, error ->
      if (error == null) {
        promise.resolve(toJs(value))
      } else {
        val cause = (error as? CompletionException)?.cause ?: error
        if (cause is PushharborException) {
          promise.reject(cause.code, cause.message, null)
        } else {
          promise.reject(PushharborException.ERR_PUSHHARBOR, cause.javaClass.simpleName, null)
        }
      }
    }
  }

  /** The Web Push subscription the app hands to its server, plus the ID to unregister it. */
  private fun toJs(s: PushSubscription): Map<String, Any?> = mapOf(
    "id" to s.id,
    "endpoint" to s.endpoint,
    "expirationTime" to null,
    "keys" to mapOf("p256dh" to s.p256dh, "auth" to s.auth),
  )

  companion object {
    /** Android 17 protects local-network access behind a runtime permission (PH-18). */
    private const val LOCAL_NETWORK_SDK = 37
  }
}
