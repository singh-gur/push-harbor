package io.github.singhgur.pushharbor

import org.json.JSONObject

/** A decrypted plaintext envelope (spec: envelope.md). All fields optional; unknown keys ignored. */
data class Message(
  val title: String?,
  val body: String?,
  val url: String?,
  val tag: String?,
  /** The envelope's `d` object as JSON text, unchanged. */
  val data: String?,
) {
  internal val visible get() = title != null || body != null

  internal companion object {
    /** Null when the plaintext is not a JSON object: such messages are dropped like decrypt failures. */
    fun parse(plaintext: ByteArray): Message? {
      val json = try {
        JSONObject(String(plaintext, Charsets.UTF_8))
      } catch (e: Exception) {
        return null
      }
      fun text(key: String) = (json.opt(key) as? String)?.takeIf { it.isNotEmpty() }
      return Message(text("t"), text("b"), text("u"), text("g"), (json.opt("d") as? JSONObject)?.toString())
    }
  }
}
