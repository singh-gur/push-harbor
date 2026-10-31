package dev.pushharbor.expo

import org.json.JSONObject

/** Plaintext envelope (spec: envelope.md). All fields optional; unknown keys ignored. */
data class Envelope(
  val title: String?,
  val body: String?,
  val url: String?,
  val tag: String?,
  /** `d` as JSON text, passed to the app unchanged. */
  val data: String?,
) {
  val visible get() = title != null || body != null

  companion object {
    /** Null when the plaintext is not a JSON object: such messages are dropped like decrypt failures. */
    fun parse(plaintext: ByteArray): Envelope? {
      val json = try {
        JSONObject(String(plaintext, Charsets.UTF_8))
      } catch (e: Exception) {
        return null
      }
      fun text(key: String) = (json.opt(key) as? String)?.takeIf { it.isNotEmpty() }
      return Envelope(text("t"), text("b"), text("u"), text("g"), (json.opt("d") as? JSONObject)?.toString())
    }
  }
}
