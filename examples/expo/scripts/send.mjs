// Plays the app's server for local tests of the example.
//   node scripts/send.mjs keys                       writes vapid.json, prints the public key
//   node scripts/send.mjs send '<envelope JSON>'     encrypts for subscription.json and sends
// web-push only speaks HTTPS, so this uses its request builder and sends with fetch (local
// relays are plain HTTP).
import { readFileSync, writeFileSync } from 'node:fs';
import webpush from 'web-push';

const [command, envelope] = process.argv.slice(2);
if (command === 'keys') {
  const keys = webpush.generateVAPIDKeys();
  writeFileSync('vapid.json', JSON.stringify(keys));
  console.log(keys.publicKey);
} else if (command === 'send') {
  const vapid = JSON.parse(readFileSync('vapid.json'));
  const subscription = JSON.parse(readFileSync('subscription.json'));
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
