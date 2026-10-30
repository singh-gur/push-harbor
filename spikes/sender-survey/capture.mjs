// PH-25 capture server: records what a Web Push library actually sends and answers with a chosen status.
//   POST /ep/<status>?lib=<name>   -> responds <status> (429 adds Retry-After: 30)
// Appends one JSON line per request to captures.jsonl. Decrypts the body with subscription.json's
// private key to prove the library's RFC 8291 encryption is correct.
import { appendFileSync, readFileSync } from "node:fs";
import { createServer } from "node:http";
import { createServer as createTlsServer } from "node:https";
import { createRequire } from "node:module";

const ece = createRequire(import.meta.url)("http_ece");
const ecdh = (await import("node:crypto")).createECDH("prime256v1");
const sub = JSON.parse(readFileSync(new URL("subscription.json", import.meta.url)));
ecdh.setPrivateKey(Buffer.from(sub.private, "base64url"));

const decodeJwt = (t) => t.split(".").slice(0, 2).map((p) => JSON.parse(Buffer.from(p, "base64url")));

function handle(req, res) {
  const chunks = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", () => {
    const url = new URL(req.url, "http://x");
    const status = Number(url.pathname.split("/")[2] ?? 201);
    const body = Buffer.concat(chunks);
    const auth = req.headers.authorization ?? "";
    const rec = {
      lib: url.searchParams.get("lib"),
      status,
      at: Math.floor(Date.now() / 1000),
      authorization: auth, // test keys only; used to build interop vectors for the core VAPID verifier
      scheme: auth.split(" ")[0],
      crypto_key: req.headers["crypto-key"],
      content_encoding: req.headers["content-encoding"],
      ttl: req.headers.ttl,
      urgency: req.headers.urgency,
      topic: req.headers.topic,
      idempotency_key: req.headers["idempotency-key"],
      body_bytes: body.length,
    };
    const t = /t=([^,\s]+)/.exec(auth)?.[1] ?? (rec.scheme === "WebPush" ? auth.split(" ")[1] : undefined);
    if (t) {
      const [header, claims] = decodeJwt(t);
      Object.assign(rec, { alg: header.alg, aud: claims.aud, sub: claims.sub, exp_in_s: claims.exp - Math.floor(Date.now() / 1000), has_k: /k=/.test(auth) });
    }
    if (rec.content_encoding === "aes128gcm" && body.length > 21) {
      Object.assign(rec, { rs: body.readUInt32BE(16), idlen: body[20] });
      try {
        const plain = ece.decrypt(body, { version: "aes128gcm", privateKey: ecdh, authSecret: sub.auth });
        Object.assign(rec, { decrypt: "ok", plaintext_bytes: plain.length, overhead: body.length - plain.length });
      } catch (e) {
        rec.decrypt = `failed: ${e.message}`;
      }
    }
    appendFileSync(new URL("captures.jsonl", import.meta.url), JSON.stringify(rec) + "\n");
    const headers = status === 429 ? { "Retry-After": "30" } : {};
    res.writeHead(status, headers).end(status >= 400 ? `status ${status} from capture server` : "");
  });
}

createServer(handle).listen(8899, "127.0.0.1", () => console.log("capture server on http://127.0.0.1:8899"));
// web-push (Node) only speaks HTTPS, so also listen with a self-signed cert when one is given.
if (process.env.TLS_KEY) {
  const tls = { key: readFileSync(process.env.TLS_KEY), cert: readFileSync(process.env.TLS_CERT) };
  createTlsServer(tls, handle).listen(8898, "127.0.0.1", () => console.log("capture server on https://127.0.0.1:8898"));
}
