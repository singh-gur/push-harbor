#!/usr/bin/env bash
# Starts the Workers adapter in `wrangler dev` (local workerd + Durable Objects) with the
# conformance contract config (crates/conformance docs), runs a command, then stops it.
# Usage: scripts/with-worker.sh <origin> <log file> <command...>
# Needs node and worker-build (`cargo install worker-build@0.8.7`). Listens on 127.0.0.1:8787.
set -euo pipefail
origin=$1 log=$2
shift 2
root=$(pwd)
cd crates/worker
npm ci --silent
# Single quotes: dotenv must not unescape the key's \n sequences.
{ echo "PUSHHARBOR_ORIGIN=$origin"
  echo "PUSHHARBOR_FCM_SERVICE_ACCOUNT='$(tr -d '\n' < ../conformance/fixtures/service-account.json)'"
  echo "PUSHHARBOR_FCM_API_BASE=http://127.0.0.1:9790"
  echo "PUSHHARBOR_PROVIDER_TIMEOUT_SECS=5"
  echo "PUSHHARBOR_LIMIT_GLOBAL=1000000/60"
  echo "PUSHHARBOR_LIMIT_PER_IP=1000000/60"
  echo "PUSHHARBOR_LIMIT_PER_SENDER=10/60"
  echo "PUSHHARBOR_LIMIT_PER_ENDPOINT=5/60"
  echo "PUSHHARBOR_LIMIT_REGISTRATIONS_PER_IP=1000000/3600"
  echo "PUSHHARBOR_LIMIT_CHALLENGES_PER_TARGET=5/3600"; } > .dev.vars
rm -rf .wrangler/state
npx wrangler dev --ip 127.0.0.1 --port 8787 --log-level warn > "$log" 2>&1 &
dev=$!
trap 'kill $dev 2>/dev/null || true; rm -f "$root/crates/worker/.dev.vars"' EXIT
for _ in $(seq 600); do curl -sf http://127.0.0.1:8787/v1/health >/dev/null && break; sleep 0.5; done
curl -sf http://127.0.0.1:8787/v1/health >/dev/null || { echo "wrangler dev failed to start:"; cat "$log"; exit 1; }
cd "$root"
"$@"
