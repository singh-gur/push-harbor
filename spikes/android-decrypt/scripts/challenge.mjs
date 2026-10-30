// PH-18: does a challenge (high-priority FCM data message with a nonce) reach the app and get
// answered over the network, in every app state? Timed on the host clock only:
// send -> FCM -> device -> POST back to this script's echo server.
//
//   GOOGLE_APPLICATION_CREDENTIALS=service-account.json npm run challenge -- [--rounds 10]
import { execSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { parseArgs } from "node:util";
import { fcmClient } from "./fcm.mjs";

const { values } = parseArgs({ options: { rounds: { type: "string", default: "10" }, timeout: { type: "string", default: "30" } } });
const ROUNDS = Number(values.rounds);
const TIMEOUT_MS = Number(values.timeout) * 1000;
const PKG = "dev.pushharbor.testapp";
const sub = JSON.parse(readFileSync("subscription.json", "utf8"));
const send = await fcmClient();
const adb = (cmd) => execSync(`adb shell ${cmd}`, { stdio: ["ignore", "pipe", "ignore"] }).toString().trim();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Echo server, reached from the device through `adb reverse tcp:8788 tcp:8788` (loopback, so
// Android 17 local-network protection does not apply; a real relay is on the public internet).
const waiting = new Map();
createServer((req, res) => {
  let body = "";
  req.on("data", (c) => (body += c));
  req.on("end", () => {
    const { c } = JSON.parse(body || "{}");
    waiting.get(c)?.(Date.now());
    res.writeHead(204).end();
  });
}).listen(8788, "127.0.0.1");

async function challenge() {
  const nonce = randomBytes(16).toString("base64url");
  const answered = new Promise((resolve) => {
    waiting.set(nonce, resolve);
    setTimeout(() => resolve(null), TIMEOUT_MS);
  });
  const sentAt = Date.now();
  const r = await send({ fid: sub.fid, data: { c: nonce, e: "http://127.0.0.1:8788/confirm" }, android: { priority: "HIGH", ttl: "60s" } });
  if (r.status !== 200) throw new Error(`FCM ${r.status} ${JSON.stringify(r.body)}`);
  const at = await answered;
  waiting.delete(nonce);
  return at === null ? null : at - sentAt;
}

const launch = () => adb(`am start -W -n ${PKG}/.MainActivity`);
const scenarios = {
  foreground: { setup: async () => { launch(); await sleep(2000); } },
  background: { setup: async () => { launch(); await sleep(1500); adb("input keyevent KEYCODE_HOME"); await sleep(1000); } },
  killed: { setup: async () => { adb("input keyevent KEYCODE_HOME"); adb(`am kill ${PKG}`); await sleep(1000); } },
  doze: {
    setup: async () => {
      adb("input keyevent KEYCODE_HOME");
      adb(`am kill ${PKG}`);
      adb("dumpsys battery unplug");
      adb("input keyevent KEYCODE_SLEEP");
      adb("dumpsys deviceidle force-idle");
      await sleep(1000);
    },
    teardown: async () => { adb("dumpsys deviceidle unforce"); adb("dumpsys battery reset"); adb("input keyevent KEYCODE_WAKEUP"); },
  },
  "force-stopped": { setup: async () => { adb(`am force-stop ${PKG}`); await sleep(1000); }, rounds: 2 },
};

const summary = [];
for (const [name, s] of Object.entries(scenarios)) {
  const latencies = [];
  let failed = 0;
  for (let i = 0; i < (s.rounds ?? ROUNDS); i++) {
    await s.setup();
    const ms = await challenge();
    ms === null ? failed++ : latencies.push(ms);
    if (name === "doze") console.log(`  doze round ${i + 1}: idle=${adb("dumpsys deviceidle get deep")} -> ${ms ?? "timeout"}`);
  }
  await s.teardown?.();
  latencies.sort((a, b) => a - b);
  const p = (q) => latencies[Math.min(latencies.length - 1, Math.floor(q * latencies.length))] ?? "-";
  summary.push({ scenario: name, sent: latencies.length + failed, answered: latencies.length, failed, p50_ms: p(0.5), p90_ms: p(0.9), max_ms: latencies.at(-1) ?? "-" });
  console.log(`${name}: ${latencies.length}/${latencies.length + failed} answered`);
}
launch(); // leave the app in a normal state
console.table(summary);
process.exit(0);
