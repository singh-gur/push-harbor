// PH-22 interop sender: web-push (Node), configured only as docs/spec/send.md says.
// Usage: node send.mjs <fixture.json>; prints one JSON line per case.
import { readFileSync } from "node:fs";
import webpush from "web-push";

const f = JSON.parse(readFileSync(process.argv[2]));
const subscription = (endpoint) => ({ endpoint, keys: f.keys });
const details = (k) => ({ subject: f.subject, publicKey: k.public, privateKey: k.private });

async function send(name, endpoint, payload, { vapid = f.vapid, headers, vapidDetails } = {}) {
  let status, retryAfter = null;
  try {
    const r = await webpush.sendNotification(subscription(endpoint), payload, {
      TTL: 3600,
      vapidDetails: vapidDetails === undefined ? details(vapid) : vapidDetails,
      headers,
    });
    status = r.statusCode;
  } catch (e) {
    if (e.statusCode === undefined) throw e;
    status = e.statusCode;
    retryAfter = e.headers?.["retry-after"] ?? null;
  }
  console.log(JSON.stringify({ case: name, status, retry_after: retryAfter }));
  return { status, retryAfter };
}

await send("at_cap", f.endpoints.ok, f.at_cap);
await send("over_cap", f.endpoints.ok, f.over_cap);
await send("no_key", f.endpoints.ok, f.short);
await send("idempotent_first", f.endpoints.ok, f.short, { headers: { "Idempotency-Key": f.idempotency_key } });
await send("idempotent_repeat", f.endpoints.ok, f.short, { headers: { "Idempotency-Key": f.idempotency_key } });
await send("unbound_key", f.endpoints.ok, f.short, { vapid: f.unbound });
// web-push has no expiry option on send; getVapidHeaders (public API) builds an expired token.
const audience = new URL(f.endpoints.ok).origin;
const expired = webpush.getVapidHeaders(audience, f.subject, f.vapid.public, f.vapid.private, "aes128gcm", f.expired_exp);
await send("expired", f.endpoints.ok, f.short, { vapidDetails: null, headers: { Authorization: expired.Authorization } });
await send("gone_first", f.endpoints.gone, f.short);
await send("gone_second", f.endpoints.gone, f.short);
await send("deleted", f.endpoints.deleted, f.short);
for (let i = 0; i < 10; i++) {
  const r = await send(`limited_${i}`, f.endpoints.limited, f.short, { vapid: f.limited_vapid });
  if (r.status !== 201) {
    console.log(JSON.stringify({ case: "limited", status: r.status, retry_after: r.retryAfter }));
    break;
  }
}
