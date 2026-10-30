// Writes .dev.vars (gitignored) for `wrangler dev` from a local service-account file, without printing it.
//   npm run dev-vars -- ../android-decrypt/service-account.json
import { readFileSync, writeFileSync } from "node:fs";

const path = process.argv[2] ?? "../android-decrypt/service-account.json";
const json = JSON.stringify(JSON.parse(readFileSync(path, "utf8")));
if (json.includes("'")) throw new Error("unexpected quote in service account JSON");
writeFileSync(".dev.vars", `FCM_SERVICE_ACCOUNT='${json}'\n`, { mode: 0o600 });
console.log("wrote .dev.vars");
