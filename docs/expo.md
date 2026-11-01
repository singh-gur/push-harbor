# Using the Expo module (Android)

`@pushharbor/expo` turns an Expo / React Native app into a Pushharbor client: it creates the
device's Web Push keys, registers with your app's relay (proving it receives pushes there),
decrypts incoming notifications on the device and shows them. iOS support is planned; the
JavaScript API won't change.

A complete app using it: [examples/expo](../examples/expo).

## Requirements

- Expo SDK 58 or newer with a [development build](https://docs.expo.dev/develop/development-builds/introduction/)
  (Expo Go can't load native modules). Android 7 (API 24) or newer.
- A Firebase project with your Android app added (its package name), and the relay for that
  Firebase project ([deploy guide](deploy.md)).
- `google-services.json` from the Firebase console, referenced in `app.json`:

  ```json
  { "expo": { "android": { "package": "com.example.myapp", "googleServicesFile": "./google-services.json" } } }
  ```

## Install

```sh
npx expo install @pushharbor/expo
npx expo prebuild --platform android   # or: npx expo run:android
```

**No config plugin is needed on Android.** The module's manifest adds its FCM service and opts
in to Firebase Installation IDs. **It must be the app's only FCM message handler**: don't use
`expo-notifications` remote push or `@react-native-firebase/messaging` in the same app, because
Android delivers each FCM message to only one service.

## Register a device

```ts
import * as Pushharbor from '@pushharbor/expo';

const RELAY_URL = 'https://push.example.com'; // your app's relay, not the user's server

async function enablePush(api: MyServerApi) {
  await Pushharbor.requestNotificationPermission(); // Android 13+
  const { key } = await api.get('/push/vapid-public-key'); // your server's VAPID public key
  const subscription = await Pushharbor.register({ relayUrl: RELAY_URL, senderKey: key });
  await api.post('/push/subscriptions', subscription); // { id, endpoint, expirationTime, keys }
}
```

`register` takes about a second: the relay sends a challenge push to the device, the module
answers it natively, and only then is the endpoint issued. Hand the whole subscription to your
server ([sending guide](sending.md)). Each server the user connects gets its own subscription;
an app can hold several.

```ts
const subscriptions = await Pushharbor.getSubscriptions(); // keep your server in sync
await Pushharbor.unregister(subscription.id);              // on sign-out; tell your server too
```

### Errors

`register` rejects with a `code`:

| Code | Meaning | What to do |
|---|---|---|
| `ERR_CHALLENGE_TIMEOUT` | No challenge push arrived after 3 tries (~90 s) | Show the message (it asks the user to check the connection and Google Play services), offer a retry. |
| `ERR_RELAY` | The relay refused; `message` has its error code | Usually configuration: wrong relay URL or an invalid VAPID key. |
| `ERR_NETWORK` | The relay is unreachable | Retry later. |
| `ERR_LOCAL_NETWORK` | The relay is on a private network address (Android 17+) | Call `requestLocalNetworkPermission()`, then retry. |

## Receive

Nothing to do for notifications: the module decrypts each push natively, also while the app is
in the background or killed, and shows those with a title or body (`t`/`b`). A newer
notification with the same tag (`g`) replaces the shown one. Tapping opens `u` **only if your
app handles that link** (an intent filter in your app, e.g. your `scheme` in `app.json`);
otherwise it just opens the app, so a server can't send users to arbitrary sites.

While the app is running you also get every message, including data-only ones:

```ts
useEffect(() => {
  const sub = Pushharbor.addMessageListener(({ title, body, url, tag, data }) => {
    // update UI, refetch, ...
  });
  return () => sub.remove();
}, []);
```

Anything that fails to decrypt (wrong keys, tampered, not from the user's server) is dropped
silently.

## Good to know

- **Keys** live in app-private storage, encrypted with a key that never leaves the Android
  Keystore. A backup restored on another phone can't decrypt; such subscriptions disappear from
  `getSubscriptions()` and the app should register again.
- **FCM ID changes** (reinstall with restore, cleared data) are handled automatically: the
  module moves the relay endpoint to the new ID, so your server's subscription stays valid.
- **Force-stopped apps** (Settings → Force stop) receive nothing until opened again; that is
  Android's rule for every push.
- **Notification icon**: defaults to the app icon. To use a monochrome drawable, add
  `<meta-data android:name="dev.pushharbor.notification_icon" android:resource="@drawable/ic_notification"/>`
  to the application element (with a small config plugin in Expo).
- **Local development**: run a relay on your machine (`just example-relay`), connect the device
  over USB, `adb reverse tcp:8080 tcp:8080`, and use `http://127.0.0.1:8080` as the relay URL.
  A relay on a LAN address needs `requestLocalNetworkPermission()` on Android 17+.
