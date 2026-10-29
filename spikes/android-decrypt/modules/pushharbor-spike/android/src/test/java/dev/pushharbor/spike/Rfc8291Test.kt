package dev.pushharbor.spike

import java.util.Base64
import java.util.Properties
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class Rfc8291Test {
  private fun b64(s: String) = Base64.getUrlDecoder().decode(s.replace(" ", ""))

  private fun decrypt(body: ByteArray, uaPrivate: String, uaPublic: String, auth: String) =
    Rfc8291.decrypt(body, Rfc8291.privateKey(b64(uaPrivate)), b64(uaPublic), b64(auth))

  /** RFC 8291 Section 5 / Appendix A example. */
  private val rfcBody =
    b64("DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8") +
      b64("8pfeW0KbunFT06SuDKoJH9Ql87S1QUrdirN6GcG7sFz1y1sqLgVi1VhjVkHsUoEsbI_0LpXMuGvnzQ")
  private val rfcPrivate = "q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94"
  private val rfcPublic = "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4"
  private val rfcAuth = "BTBZMqHH6r4Tts7J_aSIgg"

  @Test
  fun rfc8291Example() {
    val plaintext = decrypt(rfcBody, rfcPrivate, rfcPublic, rfcAuth)
    assertEquals("When I grow up, I want to be a watermelon", String(plaintext))
  }

  @Test
  fun webPushLibraryVectors() {
    // Unit tests run with the module's android/ dir as working directory.
    val p = Properties().apply { java.io.File("src/test/resources/webpush-vectors.properties").inputStream().use(::load) }
    for (name in listOf("short", "near-cap")) {
      val got = decrypt(b64(p.getProperty("$name.body")), p.getProperty("$name.ua_private"), p.getProperty("$name.ua_public"), p.getProperty("$name.auth"))
      assertArrayEquals(name, b64(p.getProperty("$name.plaintext")), got)
    }
  }

  @Test
  fun rejectsTamperedOrForeignMessages() {
    val tampered = rfcBody.copyOf().also { it[it.size - 20] = (it[it.size - 20].toInt() xor 1).toByte() }
    assertThrows(Exception::class.java) { decrypt(tampered, rfcPrivate, rfcPublic, rfcAuth) }
    val wrongAuth = "AAAAAAAAAAAAAAAAAAAAAA"
    assertThrows(Exception::class.java) { decrypt(rfcBody, rfcPrivate, rfcPublic, wrongAuth) }
    assertThrows(Exception::class.java) { decrypt(rfcBody.copyOf(50), rfcPrivate, rfcPublic, rfcAuth) }
  }

  @Test
  fun generatedKeysRoundTripTheRawEncoding() {
    val pair = Rfc8291.generateKeyPair()
    val raw = Rfc8291.rawPublicKey(pair.public as java.security.interfaces.ECPublicKey)
    assertEquals(65, raw.size)
    assertEquals(pair.public, Rfc8291.publicKey(raw))
  }
}
