#!/usr/bin/env bash
# Starts the native relay with the conformance contract config (crates/conformance docs), runs a
# command against it, then stops the relay.
# Usage: scripts/with-native.sh <origin> <database url> <log file> <command...>
# Extra relay settings can be passed as environment variables (e.g. PUSHHARBOR_LISTEN).
# Metrics listen on the listen port + 1000.
set -euo pipefail
origin=$1 db=$2 log=$3
shift 3
listen=${PUSHHARBOR_LISTEN:-127.0.0.1:8080}
metrics=127.0.0.1:$(( ${listen##*:} + 1000 ))  # e.g. 8080 -> 9080
cargo build -q -p pushharbor-native
PUSHHARBOR_ORIGIN=$origin PUSHHARBOR_LISTEN=$listen PUSHHARBOR_DATABASE_URL=$db \
PUSHHARBOR_METRICS_LISTEN=$metrics \
PUSHHARBOR_FCM_SERVICE_ACCOUNT_FILE=crates/conformance/fixtures/service-account.json \
PUSHHARBOR_FCM_API_BASE=http://127.0.0.1:9790 PUSHHARBOR_PROVIDER_TIMEOUT_SECS=5 \
PUSHHARBOR_REQUEST_TIMEOUT_SECS=8 \
PUSHHARBOR_ADMIN_TOKEN=conformance-admin-token-not-a-secret-0123456789 \
PUSHHARBOR_LIMIT_GLOBAL=1000000/60 PUSHHARBOR_LIMIT_PER_IP=1000000/60 \
PUSHHARBOR_LIMIT_PER_SENDER=10/60 PUSHHARBOR_LIMIT_PER_ENDPOINT=5/60 \
PUSHHARBOR_LIMIT_REGISTRATIONS_PER_IP=1000000/3600 PUSHHARBOR_LIMIT_CHALLENGES_PER_TARGET=5/3600 \
RUST_LOG=${RUST_LOG:-debug} target/debug/pushharbor-native > "$log" 2>&1 &
relay=$!
trap 'kill $relay 2>/dev/null || true' EXIT
for _ in $(seq 50); do curl -sf "http://$listen/v1/health" >/dev/null && break; sleep 0.2; done
kill -0 $relay 2>/dev/null || { echo "relay failed to start:"; cat "$log"; exit 1; }
"$@"
