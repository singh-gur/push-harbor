package dev.pushharbor.spike

import com.google.firebase.messaging.FirebaseMessaging
import expo.modules.kotlin.Promise
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import java.io.File

class PushharborSpikeModule : Module() {
  private val context get() = requireNotNull(appContext.reactContext)

  override fun definition() = ModuleDefinition {
    Name("PushharborSpike")

    /** Web Push subscription keys the server needs to encrypt for this device. */
    Function("getKeys") {
      val keys = Store.keys(context)
      mapOf("p256dh" to b64url(keys.public), "auth" to b64url(keys.auth))
    }

    /**
     * FCM registration token. Also writes the full subscription to `files/subscription.json` so a
     * debug build can be read with `adb shell run-as <pkg> cat files/subscription.json` (no logging).
     */
    AsyncFunction("getToken") { promise: Promise ->
      // shortcut: getToken() is deprecated since firebase-messaging 25.1 in favour of register()/onRegistered (FID);
      // still works, and how to send to an FID via the HTTP v1 API is open (PH-21/PH-10).
      @Suppress("DEPRECATION")
      FirebaseMessaging.getInstance().token
        .addOnSuccessListener { token ->
          val keys = Store.keys(context)
          File(context.filesDir, "subscription.json").writeText(
            """{"token":"$token","p256dh":"${b64url(keys.public)}","auth":"${b64url(keys.auth)}"}""",
          )
          promise.resolve(token)
        }
        .addOnFailureListener { e -> promise.reject("ERR_FCM_TOKEN", e.message, e) }
    }

    Function("getStats") { Store.stats(context) }
  }
}
