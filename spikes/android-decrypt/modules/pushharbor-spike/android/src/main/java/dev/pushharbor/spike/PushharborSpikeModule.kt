package dev.pushharbor.spike

import com.google.firebase.installations.FirebaseInstallations
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
     * Registers with FCM by Firebase Installation ID and returns the FID. Also writes the subscription
     * to `files/subscription.json` so a debug build can be read with
     * `adb shell run-as <pkg> cat files/subscription.json` (no logging).
     *
     * With `firebase_messaging_installation_id_enabled` the legacy getToken() is disabled; HTTP v1
     * targets the FID with the `fid` field.
     */
    AsyncFunction("getToken") { promise: Promise ->
      FirebaseMessaging.getInstance().register()
        .continueWithTask { FirebaseInstallations.getInstance().id }
        .addOnSuccessListener { fid ->
          val keys = Store.keys(context)
          File(context.filesDir, "subscription.json").writeText(
            """{"fid":"$fid","p256dh":"${b64url(keys.public)}","auth":"${b64url(keys.auth)}"}""",
          )
          promise.resolve(fid)
        }
        .addOnFailureListener { e -> promise.reject("ERR_FCM_TOKEN", e.message, e) }
    }

    Function("getStats") { Store.stats(context) }
  }
}
