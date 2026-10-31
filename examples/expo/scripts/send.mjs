// Plays the app's server for local and device tests of the example (docs/testing/android-e2e.md).
//   node scripts/send.mjs keys                       writes $VAPID, prints the public key
//   node scripts/send.mjs send '<envelope JSON>'     encrypts for $SUB and sends; prints the status
// Env: VAPID (default vapid.json) and SUB (default subscription.json) pick the server's key pair
// and the subscription, so several "servers" can be played; WRONG_AUTH=1 encrypts with a wrong
// auth secret (the device must drop it).
// web-push only speaks HTTPS, so this uses its request builder and sends with fetch (local
// relays are plain HTTP).
import { randomBytes } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import webpush from 'web-push';

const vapidFile = process.env.VAPID ?? 'vapid.json';
const subscriptionFile = process.env.SUB ?? 'subscription.json';
const [command, envelope] = process.argv.slice(2);
if (command === 'keys') {
  const keys = webpush.generateVAPIDKeys();
  writeFileSync(vapidFile, JSON.stringify(keys));
  console.log(keys.publicKey);
} else if (command === 'send') {
  const vapid = JSON.parse(readFileSync(vapidFile));
  const subscription = JSON.parse(readFileSync(subscriptionFile));
  if (process.env.WRONG_AUTH) subscription.keys.auth = randomBytes(16).toString('base64url');
  const request = webpush.generateRequestDetails(subscription, envelope, {
    TTL: 60,
    vapidDetails: { subject: 'mailto:example@example.com', ...vapid },
  });
  const response = await fetch(request.endpoint, { method: 'POST', headers: request.headers, body: request.body });
  console.log(response.status, await response.text());
} else {
  console.error('usage: send.mjs keys | send <envelope JSON>');
  process.exit(2);
}
