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
import java.net.HttpURLConnection
import java.net.URL

/**
 * Receives FCM data messages `{ p: base64url(aes128gcm body) }`, decrypts them natively and posts a
 * notification. Runs without the JS runtime, so it also works when the app was killed.
 */
class PushService : FirebaseMessagingService() {
  override fun onMessageReceived(message: RemoteMessage) {
    message.data["c"]?.let { return answerChallenge(it, message.data["e"]) }
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

  /**
   * PH-18 spike: proves the device holds this FID by POSTing the challenge nonce back.
   * shortcut: the echo URL comes from the message only for the spike; the real module (PH-7) uses
   * its configured relay URL and only answers challenges for a registration it started.
   */
  private fun answerChallenge(nonce: String, echoUrl: String?) {
    val outcome = try {
      val conn = URL(echoUrl).openConnection() as HttpURLConnection
      conn.requestMethod = "POST"
      conn.connectTimeout = 5000
      conn.readTimeout = 5000
      conn.doOutput = true
      conn.setRequestProperty("Content-Type", "application/json")
      conn.outputStream.use { it.write("""{"c":"$nonce"}""".toByteArray()) }
      if (conn.responseCode in 200..299) "challenge-answered" else "challenge-rejected"
    } catch (e: Exception) {
      Log.w(TAG, "challenge answer failed: ${e.javaClass.simpleName}")
      "challenge-failed"
    }
    Store.record(this, outcome)
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
