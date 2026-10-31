// Sending a Pushharbor notification from Node.js with web-push (docs/sending.md).
// Usage: VAPID_PUBLIC_KEY=... VAPID_PRIVATE_KEY=... VAPID_SUBJECT=mailto:you@example.com \
//          node send.mjs subscription.json '{"t":"Title","b":"Body"}'
// Exit codes: 0 delivered, 2 subscription gone (delete it), 1 failed.
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import webpush from "web-push";

webpush.setVapidDetails(process.env.VAPID_SUBJECT, process.env.VAPID_PUBLIC_KEY, process.env.VAPID_PRIVATE_KEY);

/** Returns "delivered" or "gone"; throws when the relay or provider keeps failing. */
export async function send(subscription, envelope, attempts = 3) {
  const payload = JSON.stringify(envelope); // at most 2,797 bytes
  const idempotencyKey = randomUUID(); // the same key on every retry: never delivered twice
  for (let attempt = 1; ; attempt++) {
    try {
      await webpush.sendNotification(subscription, payload, {
        TTL: 86400, // seconds the provider keeps it for an offline device
        urgency: "high",
        headers: { "Idempotency-Key": idempotencyKey },
      });
      return "delivered";
    } catch (e) {
      if (e.statusCode === 404 || e.statusCode === 410) return "gone";
      const retryable = e.statusCode === undefined || e.statusCode === 429 || e.statusCode === 503;
      if (!retryable || attempt === attempts) throw e;
      await sleep(retryDelay(e.headers?.["retry-after"], attempt));
    }
  }
}

/** Retry-After when the relay sends it (capped), otherwise 1 s, 2 s, 4 s, ... */
function retryDelay(retryAfter, attempt) {
  const seconds = Number(retryAfter);
  return (Number.isFinite(seconds) && seconds > 0 ? Math.min(seconds, 60) : 2 ** (attempt - 1)) * 1000;
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

if (import.meta.url === `file://${process.argv[1]}`) {
  const [file, envelope] = process.argv.slice(2);
  try {
    const result = await send(JSON.parse(readFileSync(file)), JSON.parse(envelope));
    console.log(result);
    process.exit(result === "gone" ? 2 : 0);
  } catch (e) {
    console.error(`failed: ${e.statusCode ?? e.message}`);
    process.exit(1);
  }
}
