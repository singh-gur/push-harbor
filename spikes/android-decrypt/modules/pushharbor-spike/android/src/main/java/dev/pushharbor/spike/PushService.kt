package dev.pushharbor.spike

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage
import org.json.JSONObject

/**
 * Receives FCM data messages `{ p: base64url(aes128gcm body) }`, decrypts them natively and posts a
 * notification. Runs without the JS runtime, so it also works when the app was killed.
 */
class PushService : FirebaseMessagingService() {
  override fun onMessageReceived(message: RemoteMessage) {
    val payload = message.data["p"] ?: return Store.record(this, "ignored")
    val keys = Store.keys(this)
    val envelope = try {
      JSONObject(String(Rfc8291.decrypt(unb64url(payload), keys.private, keys.public, keys.auth)))
    } catch (e: Exception) {
      // Never log payloads or keys; the error class is enough.
      Log.w(TAG, "dropped undecryptable push: ${e.javaClass.simpleName}")
      return Store.record(this, "dropped")
    }
    show(envelope.optString("t"), envelope.optString("b"))
  }

  override fun onRegistered(installationId: String) {
    Store.setFid(this, installationId)
    Log.i(TAG, "FCM registered by installation ID")
  }


  private fun show(title: String, body: String) {
    if (Build.VERSION.SDK_INT >= 33 &&
      ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
    ) {
      return Store.record(this, "no-permission")
    }
    val manager = getSystemService(NotificationManager::class.java)
    if (Build.VERSION.SDK_INT >= 26) {
      manager.createNotificationChannel(NotificationChannel(CHANNEL, "Push notifications", NotificationManager.IMPORTANCE_DEFAULT))
    }
    val open = packageManager.getLaunchIntentForPackage(packageName)?.let {
      PendingIntent.getActivity(this, 0, it, PendingIntent.FLAG_IMMUTABLE)
    }
    val notification = NotificationCompat.Builder(this, CHANNEL)
      .setSmallIcon(applicationInfo.icon)
      .setContentTitle(title)
      .setContentText(body)
      .setContentIntent(open)
      .setAutoCancel(true)
      .build()
    manager.notify(System.currentTimeMillis().toInt(), notification)
    Store.record(this, "shown")
  }

  companion object {
    private const val TAG = "Pushharbor"
    private const val CHANNEL = "pushharbor"
  }
}
