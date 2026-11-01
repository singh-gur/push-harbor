# @pushharbor/expo

Expo / React Native client for [Pushharbor](https://github.com/singh-gur/push-harbor): push
notifications for self-hosted apps, end-to-end encrypted, sent by any Web Push library.

The module creates the device's Web Push keys, registers with your app's Pushharbor relay
(proving it receives pushes there), and decrypts and shows notifications natively, even when the
app is closed. Android is supported; iOS is planned with the same JavaScript API.

```sh
npx expo install @pushharbor/expo
```

```ts
import * as Pushharbor from '@pushharbor/expo';

await Pushharbor.requestNotificationPermission();
const subscription = await Pushharbor.register({
  relayUrl: 'https://push.example.com', // your app's relay
  senderKey: serverVapidPublicKey,      // from the user's server
});
await api.post('/push/subscriptions', subscription); // { id, endpoint, expirationTime, keys }
```

Requires Expo SDK 58+ with a development build and a Firebase project for your app.

- [Usage guide](https://github.com/singh-gur/push-harbor/blob/main/docs/expo.md)
- [Sending from your server](https://github.com/singh-gur/push-harbor/blob/main/docs/sending.md)
- [Deploying the relay](https://github.com/singh-gur/push-harbor/blob/main/docs/deploy.md)

MIT licensed.
