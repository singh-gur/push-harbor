// PH-19: largest Web Push body (aes128gcm) that fits one FCM data message and one APNs payload.
//
//   GOOGLE_APPLICATION_CREDENTIALS=service-account.json npm run measure-cap -- [--sid-len 32] [--confirm]
//
// FCM: binary search with `validate_only` (nothing delivered), then with --confirm sends the max for
// real (device must show it) and max+1 (FCM must reject it). APNs: computed from its 4096-byte limit.
import { readFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { b64, encryptFor, fcmClient, targetOf } from "./fcm.mjs";

const { values } = parseArgs({
  options: {
    "sid-len": { type: "string", default: "32" },
    "alert-len": { type: "string", default: "64" },
    confirm: { type: "boolean" },
  },
});
const sidLen = Number(values["sid-len"]);
const RFC8291_OVERHEAD = 103; // 86-byte header (salt, rs, idlen, keyid) + 1 delimiter + 16-byte tag
const sub = JSON.parse(readFileSync("subscription.json", "utf8"));
const send = await fcmClient();

/** Envelope the relay would send: ciphertext `p` plus a subscription id `s` (reserved, PH-9). */
const fcmData = (body) => ({ p: b64(body), ...(sidLen ? { s: "s".repeat(sidLen) } : {}) });
const bodyOfSize = (size) => {
  const prefix = '{"t":"Cap","b":"';
  const plaintext = prefix + "x".repeat(size - RFC8291_OVERHEAD - prefix.length - 2) + '"}';
  const body = encryptFor(sub, plaintext);
  if (body.length !== size) throw new Error(`expected ${size}-byte body, got ${body.length}`);
  return body;
};
const fits = async (size, validateOnly = true) =>
  send({ ...targetOf(sub), data: fcmData(bodyOfSize(size)), android: { priority: "HIGH" } }, { validateOnly });

let [lo, hi] = [1000, 4096]; // lo fits, hi doesn't
if ((await fits(lo)).status !== 200) throw new Error("even 1000 bytes rejected");
while (hi - lo > 1) {
  const mid = (lo + hi) >> 1;
  ((await fits(mid)).status === 200 ? (lo = mid) : (hi = mid));
}
const tooBig = await fits(lo + 1);
console.log(`FCM (s=${sidLen} chars): max body ${lo} B = base64 ${b64(Buffer.alloc(lo)).length} chars, plaintext ${lo - RFC8291_OVERHEAD} B`);
console.log(`  max+1 -> ${tooBig.status} ${tooBig.body.error?.status}: ${tooBig.body.error?.message}`);

if (values.confirm) {
  const ok = await fits(lo, false);
  const over = await fits(lo + 1, false);
  console.log(`  real send of max -> ${ok.status} ${ok.body.name ? "accepted" : JSON.stringify(ok.body)}; max+1 -> ${over.status}`);
}

// APNs: payload JSON must be <= 4096 bytes. The NSE only runs for an alert with mutable-content,
// and the alert text is what iOS shows if the NSE fails, so it carries the generic notice (budget --alert-len).
const apnsEnvelope = (p) =>
  JSON.stringify({ aps: { alert: { body: "n".repeat(Number(values["alert-len"])) }, "mutable-content": 1 }, ...(sidLen ? { s: "s".repeat(sidLen) } : {}), p });
const apnsOverhead = Buffer.byteLength(apnsEnvelope(""));
let apnsMax = 0;
while (Buffer.byteLength(apnsEnvelope(b64(Buffer.alloc(apnsMax + 1)))) <= 4096) apnsMax++;
console.log(`APNs (s=${sidLen}, alert=${values["alert-len"]} B): envelope overhead ${apnsOverhead} B -> max body ${apnsMax} B, plaintext ${apnsMax - RFC8291_OVERHEAD} B`);
