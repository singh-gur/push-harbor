// Sends one RFC 8291-encrypted test push straight through FCM HTTP v1 (no relay involved).
//
//   npm run subscription                      # pull files/subscription.json from the debug app via adb
//   GOOGLE_APPLICATION_CREDENTIALS=service-account.json npm run send -- [--corrupt] [--title T] [--body B] [--size N]
//
// --corrupt flips one ciphertext bit: the app must drop it silently.
import { readFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { b64, encryptFor, fcmClient, targetOf } from "./fcm.mjs";

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
const text = values.size ? "x".repeat(Number(values.size)) : values.body;
const body = encryptFor(sub, JSON.stringify({ t: values.title, b: text }));
if (values.corrupt) body[body.length - 1] ^= 1;

const send = await fcmClient();
const res = await send({ ...targetOf(sub), data: { p: b64(body) }, android: { priority: "HIGH" } });
if (res.status !== 200) throw new Error(`FCM ${res.status} ${JSON.stringify(res.body)}`);
console.log(`sent ${body.length}-byte body${values.corrupt ? " (corrupted)" : ""} -> ${res.body.name}`);
