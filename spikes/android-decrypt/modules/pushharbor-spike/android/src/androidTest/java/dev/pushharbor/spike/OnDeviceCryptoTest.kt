package dev.pushharbor.spike

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith

/** Same crypto as the JVM tests, but on the device's own providers (Conscrypt) and storage. */
@RunWith(AndroidJUnit4::class)
class OnDeviceCryptoTest {
  @Test
  fun rfc8291ExampleDecryptsOnDevice() {
    val body = unb64url("DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8") +
      unb64url("8pfeW0KbunFT06SuDKoJH9Ql87S1QUrdirN6GcG7sFz1y1sqLgVi1VhjVkHsUoEsbI_0LpXMuGvnzQ")
    val plaintext = Rfc8291.decrypt(
      body,
      Rfc8291.privateKey(unb64url("q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94")),
      unb64url("BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4"),
      unb64url("BTBZMqHH6r4Tts7J_aSIgg"),
    )
    assertEquals("When I grow up, I want to be a watermelon", String(plaintext))
  }

  @Test
  fun storedKeysSurviveReload() {
    val context = InstrumentationRegistry.getInstrumentation().targetContext
    val first = Store.keys(context)
    val second = Store.keys(context)
    assertEquals(b64url(first.public), b64url(second.public))
    assertEquals(first.private, second.private)
    assertEquals(16, second.auth.size)
  }
}
