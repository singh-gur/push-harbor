// Shared helpers: RFC 8291 encryption (web-push) and FCM HTTP v1 sends with a service account.
import { createSign } from "node:crypto";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";

const { encrypt } = createRequire(import.meta.url)("web-push/src/encryption-helper.js");

export const b64 = (x) => Buffer.from(x).toString("base64url");

/** aes128gcm body for a subscription `{ p256dh, auth }` (rs 4096, no padding: body = plaintext + 103). */
export const encryptFor = (sub, plaintext) => encrypt(sub.p256dh, sub.auth, plaintext, "aes128gcm").cipherText;

/** FID-registered apps are targeted with `fid`; older subscriptions carry a registration `token`. */
export const targetOf = (sub) => (sub.fid ? { fid: sub.fid } : { token: sub.token });

export async function fcmClient(saPath = process.env.GOOGLE_APPLICATION_CREDENTIALS) {
  const sa = JSON.parse(readFileSync(saPath, "utf8"));
  const now = Math.floor(Date.now() / 1000);
  const unsigned = [
    { alg: "RS256", typ: "JWT" },
    { iss: sa.client_email, scope: "https://www.googleapis.com/auth/firebase.messaging", aud: sa.token_uri, iat: now, exp: now + 3600 },
  ].map((part) => b64(JSON.stringify(part))).join(".");
  const assertion = `${unsigned}.${createSign("RSA-SHA256").update(unsigned).sign(sa.private_key, "base64url")}`;
  const grant = await fetch(sa.token_uri, {
    method: "POST",
    body: new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion }),
  }).then(async (r) => (r.ok ? r.json() : Promise.reject(new Error(`oauth ${r.status} ${await r.text()}`))));

  /** Resolves to `{ status, body }`; never throws on FCM errors so callers can inspect them. */
  return async function send(message, { validateOnly = false } = {}) {
    const r = await fetch(`https://fcm.googleapis.com/v1/projects/${sa.project_id}/messages:send`, {
      method: "POST",
      headers: { authorization: `Bearer ${grant.access_token}`, "content-type": "application/json" },
      body: JSON.stringify({ message, validate_only: validateOnly }),
    });
    return { status: r.status, body: await r.json() };
  };
}
