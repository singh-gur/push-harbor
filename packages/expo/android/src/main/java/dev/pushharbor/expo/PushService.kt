package dev.pushharbor.expo

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage

/**
 * FCM data messages (spec: envelope.md): `{c, r}` challenges and `{p, s}` payloads. Runs without
 * the JS runtime, so it also works when the app was killed. Anything that fails is dropped silently.
 */
class PushService : FirebaseMessagingService() {
  override fun onMessageReceived(message: RemoteMessage) {
    val data = message.data
    val nonce = data["c"]
    val rid = data["r"]
    if (nonce != null && rid != null) return Registrar.onChallenge(rid, nonce)
    val payload = data["p"] ?: return
    val keyId = data["s"] ?: return
    val envelope = decrypt(keyId, payload) ?: return
    if (envelope.visible) show(envelope)
    PushharborModule.emit(envelope)
  }

  private fun decrypt(keyId: String, payload: String): Envelope? {
    val subscription = Subscriptions.find(this, keyId) ?: return drop("unknown key id")
    val secrets = Subscriptions.secrets(subscription) ?: return drop("keys unavailable")
    return try {
      Envelope.parse(Rfc8291.decrypt(unb64url(payload), secrets.private, secrets.public, secrets.auth))
        ?: drop("not an envelope")
    } catch (e: Exception) {
      drop(e.javaClass.simpleName)
    }
  }

  /** Never logs payloads, keys or key IDs: the reason is enough. */
  private fun drop(reason: String): Envelope? {
    Log.i(TAG, "dropped push: $reason")
    return null
  }

  override fun onRegistered(installationId: String) {
    Registrar.executor.execute { Registrar.rotate(applicationContext, installationId) }
  }

  private fun show(envelope: Envelope) {
    if (Build.VERSION.SDK_INT >= 33 &&
      ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
    ) {
      return
    }
    val manager = getSystemService(NotificationManager::class.java)
    if (Build.VERSION.SDK_INT >= 26) {
      manager.createNotificationChannel(NotificationChannel(CHANNEL, "Notifications", NotificationManager.IMPORTANCE_HIGH))
    }
    val notification = NotificationCompat.Builder(this, CHANNEL)
      .setSmallIcon(icon())
      .setContentTitle(envelope.title)
      .setContentText(envelope.body)
      .setStyle(NotificationCompat.BigTextStyle().bigText(envelope.body))
      .setContentIntent(tapIntent(envelope.url))
      .setAutoCancel(true)
      .build()
    // Same tag replaces the shown notification (also collapses repeats); otherwise a new one.
    val tag = envelope.tag
    if (tag != null) manager.notify(tag, 0, notification) else manager.notify(System.nanoTime().toInt(), notification)
  }

  /**
   * Opens `u` only if this app itself handles it (its own deep links): any server holding a
   * subscription chooses `u`, so it must not be able to send the user elsewhere.
   */
  private fun tapIntent(url: String?): PendingIntent? {
    val deepLink = url?.let { Intent(Intent.ACTION_VIEW, Uri.parse(it)).setPackage(packageName) }
      ?.takeIf { it.resolveActivity(packageManager) != null }
    val intent = deepLink ?: packageManager.getLaunchIntentForPackage(packageName) ?: return null
    intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    return PendingIntent.getActivity(this, System.nanoTime().toInt(), intent, PendingIntent.FLAG_IMMUTABLE)
  }

  /** `dev.pushharbor.notification_icon` meta-data (a drawable) if the app sets one, else the app icon. */
  private fun icon(): Int {
    val meta = packageManager.getApplicationInfo(packageName, PackageManager.GET_META_DATA).metaData
    return meta?.getInt("dev.pushharbor.notification_icon", 0)?.takeIf { it != 0 } ?: applicationInfo.icon
  }

  companion object {
    private const val TAG = "Pushharbor"
    private const val CHANNEL = "pushharbor"
  }
}
