// Sends one RFC 8291-encrypted test push straight through FCM HTTP v1 (no relay involved).
//
//   npm run subscription                      # pull files/subscription.json from the debug app via adb
//   GOOGLE_APPLICATION_CREDENTIALS=service-account.json npm run send -- [--corrupt] [--title T] [--body B] [--size N]
//
// --corrupt flips one ciphertext bit: the app must drop it silently.
import { createSign } from "node:crypto";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { parseArgs } from "node:util";

const { encrypt } = createRequire(import.meta.url)("web-push/src/encryption-helper.js");
const { values, positionals } = parseArgs({
  allowPositionals: true,
  options: {
    corrupt: { type: "boolean" },
    title: { type: "string", default: "Pushharbor" },
    body: { type: "string", default: "Hello from the PH-20 spike" },
    size: { type: "string" },
  },
});
const sub = JSON.parse(readFileSync(positionals[0] ?? "subscription.json", "utf8"));
const sa = JSON.parse(readFileSync(process.env.GOOGLE_APPLICATION_CREDENTIALS, "utf8"));
const b64 = (x) => Buffer.from(x).toString("base64url");

const text = values.size ? "x".repeat(Number(values.size)) : values.body;
const { cipherText } = encrypt(sub.p256dh, sub.auth, JSON.stringify({ t: values.title, b: text }), "aes128gcm");
if (values.corrupt) cipherText[cipherText.length - 1] ^= 1;

const now = Math.floor(Date.now() / 1000);
const unsigned = [
  { alg: "RS256", typ: "JWT" },
  { iss: sa.client_email, scope: "https://www.googleapis.com/auth/firebase.messaging", aud: sa.token_uri, iat: now, exp: now + 3600 },
].map((part) => b64(JSON.stringify(part))).join(".");
const assertion = `${unsigned}.${createSign("RSA-SHA256").update(unsigned).sign(sa.private_key, "base64url")}`;
const { access_token } = await post(
  sa.token_uri,
  new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion }),
);

// FID-registered apps are targeted with `fid`; older subscriptions carry a registration `token`.
const target = sub.fid ? { fid: sub.fid } : { token: sub.token };
const message = { ...target, data: { p: b64(cipherText) }, android: { priority: "HIGH" } };
const res = await post(
  `https://fcm.googleapis.com/v1/projects/${sa.project_id}/messages:send`,
  JSON.stringify({ message }),
  { authorization: `Bearer ${access_token}`, "content-type": "application/json" },
);
console.log(`sent ${cipherText.length}-byte body${values.corrupt ? " (corrupted)" : ""} -> ${res.name}`);

async function post(url, body, headers) {
  const r = await fetch(url, { method: "POST", body, headers });
  const json = await r.json();
  if (!r.ok) throw new Error(`${url} ${r.status} ${JSON.stringify(json)}`);
  return json;
}
