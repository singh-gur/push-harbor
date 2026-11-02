package dev.pushharbor.nativeapp

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import io.github.singhgur.pushharbor.MessageListener
import io.github.singhgur.pushharbor.Pushharbor
import io.github.singhgur.pushharbor.PushharborException
import kotlinx.coroutines.MainScope
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import org.json.JSONObject
import java.io.File

/**
 * Pushharbor native example. In a real app the server's VAPID key comes from your server, and the
 * subscription goes back to it. Here both are entered by hand, or via a deep link for scripts:
 *   pushharbornative://register?relay=<url>&key=<VAPID public key>
 * The newest subscription is also written to files/subscription.json (debug: `adb shell run-as
 * dev.pushharbor.nativeapp cat files/subscription.json`).
 */
class MainActivity : Activity() {
  private val scope = MainScope()
  private lateinit var relayUrl: EditText
  private lateinit var senderKey: EditText
  private lateinit var status: TextView
  private lateinit var subscriptions: LinearLayout
  private lateinit var lastMessage: TextView

  // Called on a background thread for every decrypted message while the app runs.
  private val listener = MessageListener { message -> runOnUiThread { lastMessage.text = "Last message: $message" } }

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    buildViews()
    // Real apps call this once in Application.onCreate.
    Pushharbor.refreshTarget(this)
    Pushharbor.addMessageListener(listener)
    if (Pushharbor.needsNotificationPermission(this)) {
      requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1)
    }
    scope.launch { refresh() }
    handleLink(intent)
  }

  override fun onNewIntent(intent: Intent) {
    super.onNewIntent(intent)
    handleLink(intent)
  }

  override fun onDestroy() {
    Pushharbor.removeMessageListener(listener)
    scope.cancel()
    super.onDestroy()
  }

  private fun handleLink(intent: Intent?) {
    val uri = intent?.data ?: return
    if (uri.scheme != "pushharbornative" || uri.host != "register") return
    val relay = uri.getQueryParameter("relay") ?: return
    val key = uri.getQueryParameter("key") ?: return
    register(relay, key)
  }

  private fun register(relay: String, key: String) = scope.launch {
    if (Pushharbor.needsLocalNetworkPermission(this@MainActivity, relay)) {
      requestPermissions(arrayOf(Pushharbor.LOCAL_NETWORK_PERMISSION), 2)
      status.text = "Allow local network access, then register again"
      return@launch
    }
    status.text = "Registering…"
    status.text = try {
      Pushharbor.register(this@MainActivity, relay, key)
      "Registered"
    } catch (e: PushharborException) {
      "Failed: ${e.code} ${e.message}"
    }
    refresh()
  }

  private fun unregister(id: String) = scope.launch {
    try {
      Pushharbor.unregister(this@MainActivity, id)
    } catch (e: PushharborException) {
      status.text = "Failed: ${e.code} ${e.message}"
    }
    refresh()
  }

  private suspend fun refresh() {
    val subs = Pushharbor.subscriptions(this)
    File(filesDir, "subscription.json").writeText(subs.lastOrNull()?.toJson() ?: "null")
    subscriptions.removeAllViews()
    for (s in subs) {
      subscriptions.addView(TextView(this).apply {
        text = JSONObject(s.toJson()).toString(2)
        setTextIsSelectable(true)
      })
      subscriptions.addView(Button(this).apply {
        text = "Unregister"
        setOnClickListener { unregister(s.id) }
      })
    }
  }

  private fun buildViews() {
    val dp = resources.displayMetrics.density
    val column = LinearLayout(this).apply {
      orientation = LinearLayout.VERTICAL
      setPadding((24 * dp).toInt(), (64 * dp).toInt(), (24 * dp).toInt(), (24 * dp).toInt())
    }
    relayUrl = EditText(this).apply { setText("http://127.0.0.1:8080") }
    senderKey = EditText(this).apply { hint = "Server VAPID public key" }
    status = TextView(this)
    subscriptions = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
    lastMessage = TextView(this)
    column.addView(TextView(this).apply {
      text = "Pushharbor native example"
      textSize = 20f
    })
    column.addView(relayUrl)
    column.addView(senderKey)
    column.addView(Button(this).apply {
      text = "Register"
      setOnClickListener { register(relayUrl.text.toString().trim(), senderKey.text.toString().trim()) }
    })
    column.addView(status)
    column.addView(subscriptions)
    column.addView(lastMessage)
    setContentView(ScrollView(this).apply { addView(column) })
  }
}
