// Writes docs/spec/vectors/encryption.json: RFC 8291 aes128gcm vectors made with http_ece (the
// encrypter inside web-push), deterministic from fixed keys and salts. Run: node encryption-vectors.mjs
import { createECDH, createHash } from "node:crypto";
import { writeFileSync } from "node:fs";
import ece from "http_ece";

const MAX_BODY = 2900;
const OVERHEAD = 103;
const b64 = (buf) => Buffer.from(buf).toString("base64url");
const seed = (label, len = 32) => createHash("sha256").update(`pushharbor vector ${label}`).digest().subarray(0, len);
const keypair = (label) => {
  const ecdh = createECDH("prime256v1");
  ecdh.setPrivateKey(seed(label));
  return ecdh;
};

const ua = keypair("user agent");
const auth = seed("auth", 16);
const otherAuth = seed("other auth", 16);

function encrypt(name, plaintext, { rs = 4096, pad = 0 } = {}) {
  const as = keypair(`application server ${name}`);
  const salt = seed(`salt ${name}`, 16);
  const body = ece.encrypt(Buffer.from(plaintext), {
    version: "aes128gcm", dh: b64(ua.getPublicKey()), privateKey: as, salt: b64(salt),
    authSecret: b64(auth), rs, pad,
  });
  return { as_private: b64(as.getPrivateKey()), salt: b64(salt), rs, pad, body };
}

// A plaintext envelope (spec: envelope.md) whose JSON is exactly `len` bytes.
function envelopeOfLength(len) {
  const base = { t: "Weekly report", b: "", u: "https://app.example/reports/42", g: "report-42", d: { id: 42 } };
  const empty = JSON.stringify(base).length;
  return JSON.stringify({ ...base, b: "x".repeat(len - empty) });
}

const short = JSON.stringify({ t: "New message", b: "Alice: are we still on for 7?", u: "https://chat.example/c/42", g: "chat-42", d: { chat: 42 } });
const atCap = envelopeOfLength(MAX_BODY - OVERHEAD);
const overCap = envelopeOfLength(MAX_BODY - OVERHEAD + 1);

const vectors = [];
const add = (name, description, plaintext, opts, extra = {}) => {
  const { body, ...params } = encrypt(name, plaintext, opts);
  const vector = {
    name, description, ...params, body: b64(body), body_bytes: body.length,
    auth: b64(auth), plaintext, decrypt: "ok", relay_status: body.length > MAX_BODY ? 413 : 201, ...extra,
  };
  vectors.push(vector);
  return { vector, body };
};

// RFC 8291 section 5 / appendix A (independent ground truth; keys differ from the rest). The RFC
// prints the body in two lines; re-encrypting with its keys and salt must reproduce it.
const rfcBody = Buffer.concat([
  Buffer.from("DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8", "base64url"),
  Buffer.from("8pfeW0KbunFT06SuDKoJH9Ql87S1QUrdirN6GcG7sFz1y1sqLgVi1VhjVkHsUoEsbI_0LpXMuGvnzQ", "base64url"),
]);
const rfcAs = createECDH("prime256v1");
rfcAs.setPrivateKey(Buffer.from("yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw", "base64url"));
const rfcAgain = ece.encrypt(Buffer.from("When I grow up, I want to be a watermelon"), {
  version: "aes128gcm", dh: "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4",
  privateKey: rfcAs, salt: "DGv6ra1nlYgDCS1FRnbzlw", authSecret: "BTBZMqHH6r4Tts7J_aSIgg", rs: 4096,
});
if (!rfcAgain.equals(rfcBody)) throw new Error("RFC 8291 example does not reproduce");
vectors.push({
  name: "rfc8291-example",
  description: "The worked example from RFC 8291 section 5 and appendix A.",
  ua_private: "q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94",
  ua_public: "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4",
  as_private: "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw",
  salt: "DGv6ra1nlYgDCS1FRnbzlw",
  rs: 4096,
  pad: 0,
  body: b64(rfcBody),
  body_bytes: rfcBody.length,
  auth: "BTBZMqHH6r4Tts7J_aSIgg",
  plaintext: "When I grow up, I want to be a watermelon",
  decrypt: "ok",
  relay_status: 201,
});
add("envelope-short", "A typical plaintext envelope, library defaults (rs 4096, no padding).", short, {});
const { body: capBody } = add("at-cap", "Largest accepted body: 2,797 B plaintext gives exactly 2,900 B.", atCap, {});
add("over-cap", "One plaintext byte more: 2,901 B body, rejected with 413 before delivery.", overCap, {});
add("padded-to-record-size", "webpush-go with RecordSize 2900: padded so the body is exactly rs; decrypters must strip padding.", short, { rs: 2900, pad: MAX_BODY - OVERHEAD - Buffer.byteLength(short) });

const tampered = Buffer.from(capBody);
tampered[tampered.length - 20] ^= 1;
vectors.push({
  ...vectors.find((v) => v.name === "at-cap"),
  name: "tampered",
  description: "at-cap with one ciphertext bit flipped: the relay cannot tell, the device must drop it.",
  body: b64(tampered), plaintext: null, decrypt: "fail",
});
vectors.push({
  ...vectors.find((v) => v.name === "envelope-short"),
  name: "wrong-auth-secret",
  description: "envelope-short decrypted with another auth secret (e.g. sent by a server holding a stale subscription): drop.",
  auth: b64(otherAuth), plaintext: null, decrypt: "fail",
});

for (const v of vectors) {
  if (v.ua_private) continue;
  v.ua_private = b64(ua.getPrivateKey());
  v.ua_public = b64(ua.getPublicKey());
}
// Stable key order for readable diffs.
const order = ["name", "description", "ua_private", "ua_public", "auth", "as_private", "salt", "rs", "pad", "plaintext", "body", "body_bytes", "decrypt", "relay_status"];
const file = {
  source: "http_ece 1.2 (as used by web-push 3.6.7); rfc8291-example from RFC 8291. Generator: spikes/sender-survey/encryption-vectors.mjs",
  max_body_bytes: MAX_BODY,
  vectors: vectors.map((v) => Object.fromEntries(order.map((k) => [k, v[k]]))),
};
const out = new URL("../../docs/spec/vectors/encryption.json", import.meta.url);
writeFileSync(out, JSON.stringify(file, null, 2) + "\n");
console.log(`wrote ${vectors.length} vectors to ${out.pathname}`);
