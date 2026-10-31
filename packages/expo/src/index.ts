import { type EventSubscription, NativeModule, requireNativeModule } from 'expo';

/**
 * A Web Push subscription as the app's server expects it (the browser `PushSubscription` JSON
 * shape), plus `id` to unregister it. Hand everything but `id` to your server.
 */
export type Subscription = {
  id: string;
  endpoint: string;
  expirationTime: null;
  keys: { p256dh: string; auth: string };
};

/** A decrypted plaintext envelope (spec: docs/spec/envelope.md). */
export type Message = {
  title?: string;
  body?: string;
  url?: string;
  tag?: string;
  /** The envelope's `d` object, unchanged. */
  data?: Record<string, unknown>;
};

/**
 * Rejection codes: `ERR_CHALLENGE_TIMEOUT` (no challenge push arrived after 3 tries),
 * `ERR_RELAY` (the relay refused; message has its error code), `ERR_NETWORK`,
 * `ERR_LOCAL_NETWORK` (call `requestLocalNetworkPermission()` first), `ERR_KEYS`.
 */
export type PushharborErrorCode =
  | 'ERR_CHALLENGE_TIMEOUT'
  | 'ERR_RELAY'
  | 'ERR_NETWORK'
  | 'ERR_LOCAL_NETWORK'
  | 'ERR_KEYS'
  | 'ERR_PUSHHARBOR';

type NativeMessage = {
  title: string | null;
  body: string | null;
  url: string | null;
  tag: string | null;
  data: string | null;
};

declare class PushharborNativeModule extends NativeModule<{ onMessage(message: NativeMessage): void }> {
  register(relayUrl: string, senderKey: string): Promise<Subscription>;
  getSubscriptions(): Promise<Subscription[]>;
  unregister(id: string): Promise<void>;
  requestNotificationPermission(): Promise<boolean>;
  requestLocalNetworkPermission(): Promise<boolean>;
}

const native = requireNativeModule<PushharborNativeModule>('Pushharbor');

/**
 * Creates a subscription on the relay at `relayUrl` that only the server owning the VAPID key
 * `senderKey` (uncompressed P-256 public key, base64url) can send to. Proves to the relay that
 * this device receives its pushes first, which takes about a second (up to ~90 s on failure).
 */
export function register(options: { relayUrl: string; senderKey: string }): Promise<Subscription> {
  return native.register(options.relayUrl, options.senderKey);
}

/** Subscriptions on this device. Keep them in sync with your server. */
export function getSubscriptions(): Promise<Subscription[]> {
  return native.getSubscriptions();
}

/** Deletes the subscription on the relay and its keys on the device. Tell your server too. */
export function unregister(id: string): Promise<void> {
  return native.unregister(id);
}

/** Android 13+ needs this before notifications can be shown. Resolves to whether it is granted. */
export function requestNotificationPermission(): Promise<boolean> {
  return native.requestNotificationPermission();
}

/** Android 17+ needs this to reach a relay on a private network address. */
export function requestLocalNetworkPermission(): Promise<boolean> {
  return native.requestLocalNetworkPermission();
}

/**
 * Called for every decrypted message while the app is running. Messages with a title or body
 * are also shown as notifications (the app does not need to be running for that).
 */
export function addMessageListener(listener: (message: Message) => void): EventSubscription {
  return native.addListener('onMessage', (m) =>
    listener({
      title: m.title ?? undefined,
      body: m.body ?? undefined,
      url: m.url ?? undefined,
      tag: m.tag ?? undefined,
      data: m.data ? JSON.parse(m.data) : undefined,
    }),
  );
}
