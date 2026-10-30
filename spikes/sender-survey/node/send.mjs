// web-push (Node) against the capture server. Prints one JSON line per case.
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";

const webpush = createRequire(import.meta.url)("web-push");
const sub = JSON.parse(readFileSync(new URL("../subscription.json", import.meta.url)));
const keys = webpush.generateVAPIDKeys();
webpush.setVapidDetails("mailto:survey@example.com", keys.publicKey, keys.privateKey);
// web-push always uses https.request, so it needs the TLS listener (self-signed: NODE_TLS_REJECT_UNAUTHORIZED=0).
const base = "https://127.0.0.1:8898/ep";
const lib = "web-push";

for (const status of [201, 404, 410, 413, 429]) {
  const payload = "x".repeat(status === 201 ? 2797 : 10);
  const target = { endpoint: `${base}/${status}?lib=${lib}`, keys: { p256dh: sub.p256dh, auth: sub.auth } };
  try {
    const r = await webpush.sendNotification(target, payload, { TTL: 60, headers: { "Idempotency-Key": "idem-node" } });
    console.log(JSON.stringify({ lib, status, outcome: "returned", statusCode: r.statusCode }));
  } catch (e) {
    console.log(JSON.stringify({ lib, status, outcome: `throws ${e.name}`, statusCode: e.statusCode, retryAfter: e.headers?.["retry-after"] }));
  }
}
