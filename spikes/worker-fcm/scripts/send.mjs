// Sends Web Push requests (RFC 8291 body + RFC 8292 VAPID) to the spike Worker, which forwards them to FCM.
//
//   npm run send -- [--url http://localhost:8787] [--sub ../android-decrypt/subscription.json]
//                   [--count N] [--corrupt] [--title T] [--body B]
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { parseArgs } from "node:util";

const require = createRequire(import.meta.url);
const webpush = require("web-push");
const { encrypt } = require("web-push/src/encryption-helper.js");

const { values } = parseArgs({
  options: {
    url: { type: "string", default: "http://localhost:8787" },
    sub: { type: "string", default: "../android-decrypt/subscription.json" },
    count: { type: "string", default: "1" },
    corrupt: { type: "boolean" },
    title: { type: "string", default: "Pushharbor" },
    body: { type: "string", default: "Hello via the Worker" },
  },
});
const sub = JSON.parse(readFileSync(values.sub, "utf8"));
const target = sub.fid ? `fid=${encodeURIComponent(sub.fid)}` : `token=${encodeURIComponent(sub.token)}`;
const vapid = webpush.generateVAPIDKeys();
const { Authorization } = webpush.getVapidHeaders(
  new URL(values.url).origin, "mailto:spike@example.com", vapid.publicKey, vapid.privateKey, "aes128gcm",
);

const results = [];
for (let i = 1; i <= Number(values.count); i++) {
  const n = Number(values.count) > 1 ? ` #${i}` : "";
  const { cipherText } = encrypt(sub.p256dh, sub.auth, JSON.stringify({ t: values.title + n, b: values.body }), "aes128gcm");
  if (values.corrupt) cipherText[cipherText.length - 1] ^= 1;
  const started = Date.now();
  const res = await fetch(`${values.url}/send?${target}`, {
    method: "POST",
    headers: { Authorization, "Content-Encoding": "aes128gcm", TTL: "60" },
    body: cipherText,
  });
  const info = await res.json().catch(() => ({}));
  results.push({ status: res.status, total_ms: Date.now() - started, ...info, fcm: info.fcm?.error?.status ?? (info.fcm ? "ok" : undefined) });
}
console.table(results);
const failed = results.filter((r) => r.status !== 201).length;
console.log(`${results.length - failed}/${results.length} accepted`);
