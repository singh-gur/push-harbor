package io.github.singhgur.pushharbor

import java.io.File
import java.util.Base64
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.fail
import org.junit.Test

/** docs/spec/vectors/encryption.json: what the device must decrypt and what it must drop. */
class SpecVectorsTest {
  private fun b64(s: String) = Base64.getUrlDecoder().decode(s)

  // Unit tests run with packages/android as working directory.
  private val file = JSONObject(File("../../docs/spec/vectors/encryption.json").readText())

  @Test
  fun encryptionVectors() {
    val vectors = file.getJSONArray("vectors")
    assert(vectors.length() >= 7)
    for (i in 0 until vectors.length()) {
      val v = vectors.getJSONObject(i)
      val name = v.getString("name")
      val result = runCatching {
        Rfc8291.decrypt(b64(v.getString("body")), Rfc8291.privateKey(b64(v.getString("ua_private"))), b64(v.getString("ua_public")), b64(v.getString("auth")))
      }
      when (v.getString("decrypt")) {
        "ok" -> assertEquals(name, v.getString("plaintext"), String(result.getOrElse { fail("$name: $it"); return }))
        else -> assert(result.isFailure) { "$name must not decrypt" }
      }
    }
  }

  @Test
  fun vectorEnvelopesParse() {
    val vectors = file.getJSONArray("vectors")
    val short = (0 until vectors.length()).map { vectors.getJSONObject(it) }.first { it.getString("name") == "envelope-short" }
    val envelope = Message.parse(short.getString("plaintext").toByteArray())
    assertNotNull(envelope)
    envelope!!
    assertEquals("New message", envelope.title)
    assertEquals("Alice: are we still on for 7?", envelope.body)
    assertEquals("https://chat.example/c/42", envelope.url)
    assertEquals("chat-42", envelope.tag)
    assertEquals(42, JSONObject(envelope.data!!).getInt("chat"))
  }

  @Test
  fun envelopeRules() {
    // Not a JSON object: dropped like a decrypt failure.
    for (bad in listOf("When I grow up", "[1,2]", "\"text\"", "")) assertNull(bad, Message.parse(bad.toByteArray()))
    // All keys optional, unknown keys ignored, wrong types treated as absent.
    val silent = Message.parse("""{"d":{"x":1},"future":true,"t":5}""".toByteArray())!!
    assertEquals(false, silent.visible)
    assertEquals("""{"x":1}""", silent.data)
    assertEquals(true, Message.parse("""{"b":"only a body"}""".toByteArray())!!.visible)
  }

  @Test
  fun subscriptionJsonMatchesJsShape() {
    val json = JSONObject(PushSubscription("k1", "https://relay.example/v1/push/e1", "BPub", "auth").toJson())
    assertEquals(setOf("id", "endpoint", "expirationTime", "keys"), json.keys().asSequence().toSet())
    assertEquals("k1", json.getString("id"))
    assertEquals("https://relay.example/v1/push/e1", json.getString("endpoint"))
    assert(json.isNull("expirationTime"))
    assertEquals("BPub", json.getJSONObject("keys").getString("p256dh"))
    assertEquals("auth", json.getJSONObject("keys").getString("auth"))
  }
}
