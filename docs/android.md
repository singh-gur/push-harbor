# Using the Android library (Kotlin / Java)

`pushharbor-android` turns a native Android app into a Pushharbor client: it creates the
device's Web Push keys, registers with your app's relay (proving it receives pushes there),
decrypts incoming notifications on the device and shows them. The Expo module
([guide](expo.md)) is a thin wrapper over this library, so both behave the same.

A complete app using it: [examples/android](../examples/android).

## Requirements

- Android 7 (API 24) or newer; the library compiles against SDK 37.
- A Firebase project with your Android app added (its package name), and the relay for that
  Firebase project ([deploy guide](deploy.md)).
- `google-services.json` from the Firebase console in your app module, and the Google services
  Gradle plugin (`com.google.gms.google-services`) applied to it.

## Install

The library is on Maven Central. In your app module:

```groovy
dependencies {
  implementation("io.github.singh-gur:pushharbor-android:0.2.0")
}
```

Releases are signed with the PGP key `0DA6688B8C505B5C477444D4B6AB8A752A2A2A92`
(on keyserver.ubuntu.com and keys.openpgp.org).

To build from source instead, include `packages/android` from a checkout of this repository
(for example a Git submodule) in `settings.gradle` and depend on `project(':pushharbor-android')`:

```groovy
include ':pushharbor-android'
project(':pushharbor-android').projectDir = file('../push-harbor/packages/android')
```

The included build file needs the Android Gradle plugin (9.x) and the Kotlin Android plugin in
your build, with `android.builtInKotlin=false` in `gradle.properties` (the same setup React
Native apps use); see [examples/android](../examples/android) for a complete build.

**No manifest changes are needed.** The library's manifest adds its FCM service, the
`INTERNET`, `POST_NOTIFICATIONS` and `ACCESS_LOCAL_NETWORK` permissions, and opts in to Firebase
Installation IDs. **It must be the app's only FCM message handler**: don't add another
`FirebaseMessagingService`, because Android delivers each FCM message to only one service.

## Register a device

Kotlin (suspend functions):

```kotlin
import io.github.singhgur.pushharbor.Pushharbor

const val RELAY_URL = "https://push.example.com" // your app's relay, not the user's server

suspend fun enablePush(context: Context, api: MyServerApi) {
  val key = api.vapidPublicKey() // your server's VAPID public key
  val subscription = Pushharbor.register(context, RELAY_URL, key)
  api.postSubscription(subscription.toJson()) // {"id", "endpoint", "expirationTime", "keys"}
}
```

Java (`CompletableFuture`):

```java
Pushharbor.registerAsync(context, RELAY_URL, key)
    .thenAccept(subscription -> api.postSubscription(subscription.toJson()));
```

`register` takes about a second: the relay sends a challenge push to the device, the library
answers it, and only then is the endpoint issued. Hand the whole subscription to your server
([sending guide](sending.md)). Each server the user connects gets its own subscription; an app
can hold several.

```kotlin
val subscriptions = Pushharbor.subscriptions(context) // keep your server in sync
Pushharbor.unregister(context, subscription.id)       // on sign-out; tell your server too
```

Java has `subscriptionsAsync` and `unregisterAsync`. Calls run one at a time on a background
thread; they are safe to start from the main thread.

Call `Pushharbor.refreshTarget(context)` once at app start (e.g. in `Application.onCreate`):
it moves the relay endpoints to the device's new FCM ID if it changed while the app was not
running. It returns immediately.

### Permissions

The library declares its permissions; the app asks for the runtime ones:

```kotlin
if (Pushharbor.needsNotificationPermission(context)) {        // Android 13+
  requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), REQUEST_CODE)
}
if (Pushharbor.needsLocalNetworkPermission(context, relayUrl)) { // Android 17+, relay on a LAN address
  requestPermissions(arrayOf(Pushharbor.LOCAL_NETWORK_PERMISSION), REQUEST_CODE)
}
```

### Errors

Failures are `PushharborException`s with a `code` (the same codes as the Expo module):

| Code | Meaning | What to do |
|---|---|---|
| `ERR_CHALLENGE_TIMEOUT` | No challenge push arrived after 3 tries (~90 s) | Show the message (it asks the user to check the connection and Google Play services), offer a retry. |
| `ERR_RELAY` | The relay refused; `message` has its error code | Usually configuration: wrong relay URL or an invalid VAPID key. |
| `ERR_NETWORK` | The relay is unreachable | Retry later. |
| `ERR_LOCAL_NETWORK` | The relay is on a private network address (Android 17+) | Request `Pushharbor.LOCAL_NETWORK_PERMISSION`, then retry. |
| `ERR_KEYS` | The subscription's keys can't be read on this device | Register again. |
| `ERR_PUSHHARBOR` | Anything else | Retry; report if it persists. |

From Java, the futures complete exceptionally with the `PushharborException` (wrapped in a
`CompletionException` or `ExecutionException`, depending on how you read them).

## Receive

Nothing to do for notifications: the library decrypts each push in its FCM service, also while
the app is in the background or killed, and shows those with a title or body (`t`/`b`). A newer
notification with the same tag (`g`) replaces the shown one. Tapping opens `u` **only if your
app handles that link** (an intent filter in your app); otherwise it just opens the app, so a
server can't send users to arbitrary sites.

While the app process runs you also get every message, including data-only ones:

```kotlin
val listener = MessageListener { message ->
  // message.title, .body, .url, .tag, .data (the envelope's `d` object as JSON text)
  // Called on a background thread.
}
Pushharbor.addMessageListener(listener)
// later: Pushharbor.removeMessageListener(listener)
```

Anything that fails to decrypt (wrong keys, tampered, not from the user's server) is dropped
silently.

## Good to know

- **Keys** live in app-private storage, encrypted with a key that never leaves the Android
  Keystore. A backup restored on another phone can't decrypt; such subscriptions disappear from
  `subscriptions()` and the app should register again.
- **FCM ID changes** (reinstall with restore, cleared data) are handled automatically: the
  library moves the relay endpoint to the new ID, so your server's subscription stays valid.
- **Force-stopped apps** (Settings → Force stop) receive nothing until opened again; that is
  Android's rule for every push.
- **Notification icon**: defaults to the app icon. To use a monochrome drawable, add
  `<meta-data android:name="dev.pushharbor.notification_icon" android:resource="@drawable/ic_notification"/>`
  to the application element (the native example does).
- **Local development**: run a relay on your machine (`just example-relay`), connect the device
  over USB, `adb reverse tcp:8080 tcp:8080`, and use `http://127.0.0.1:8080` as the relay URL.
