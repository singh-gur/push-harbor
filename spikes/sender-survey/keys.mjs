// Writes subscription.json: a test browser-style subscription (endpoint, p256dh, auth) plus the private
// key the capture server needs to decrypt. Test-only keys, safe to regenerate.
import { createECDH, randomBytes } from "node:crypto";
import { writeFileSync } from "node:fs";

const ecdh = createECDH("prime256v1");
ecdh.generateKeys();
writeFileSync(
  new URL("subscription.json", import.meta.url),
  JSON.stringify({
    endpoint: "http://127.0.0.1:8899/ep/201",
    p256dh: ecdh.getPublicKey("base64url"),
    auth: randomBytes(16).toString("base64url"),
    private: ecdh.getPrivateKey("base64url"),
  }, null, 2) + "\n",
);
console.log("wrote subscription.json");
