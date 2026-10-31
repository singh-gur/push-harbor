#!/usr/bin/env bash
# Local emulation of deploy/cloudrun/service.yaml's container contract (no GCP project in CI):
# the image built from this tree, no persistent disk, port 8080, the service account as a mounted
# secret file, and PostgreSQL reached through a Unix socket under /cloudsql/PROJECT:REGION:INSTANCE
# exactly as Cloud SQL provides it. Then the conformance suite and the log check.
set -euo pipefail
secrets=$PWD/target/conformance-secrets.txt
instance=/cloudsql/demo-project:us-central1:pushharbor
docker build -q -t pushharbor-native:dev . >/dev/null
docker rm -f ph-cr-postgres ph-cr-relay >/dev/null 2>&1 || true
docker volume rm -f ph-cr-socket >/dev/null 2>&1 || true
cleanup() { docker rm -f ph-cr-postgres ph-cr-relay >/dev/null 2>&1; docker volume rm -f ph-cr-socket >/dev/null 2>&1; }
trap cleanup EXIT
docker run -d --name ph-cr-postgres --mount type=volume,src=ph-cr-socket,dst=/var/run/postgresql \
  -e POSTGRES_PASSWORD=pushharbor -e POSTGRES_DB=pushharbor postgres:17-alpine >/dev/null
for _ in $(seq 60); do docker exec ph-cr-postgres pg_isready -q -U postgres -d pushharbor && break; sleep 0.5; done
sleep 1
docker run -d --name ph-cr-relay --network host \
  --mount type=volume,src=ph-cr-socket,dst=$instance \
  -v "$PWD/crates/conformance/fixtures/service-account.json:/secrets/fcm/service-account.json:ro,z" \
  -e PUSHHARBOR_ORIGIN=http://127.0.0.1:8080 -e PUSHHARBOR_LISTEN=127.0.0.1:8080 \
  -e PUSHHARBOR_TRUST_PROXY=1 -e PUSHHARBOR_FCM_SERVICE_ACCOUNT_FILE=/secrets/fcm/service-account.json \
  -e "PUSHHARBOR_DATABASE_URL=postgres://postgres:pushharbor@localhost/pushharbor?host=$instance" \
  -e PUSHHARBOR_FCM_API_BASE=http://127.0.0.1:9790 -e PUSHHARBOR_PROVIDER_TIMEOUT_SECS=5 \
  -e PUSHHARBOR_REQUEST_TIMEOUT_SECS=8 -e PUSHHARBOR_ADMIN_TOKEN=conformance-admin-token-not-a-secret-0123456789 \
  -e PUSHHARBOR_LIMIT_GLOBAL=1000000/60 -e PUSHHARBOR_LIMIT_PER_IP=1000000/60 \
  -e PUSHHARBOR_LIMIT_PER_SENDER=10/60 -e PUSHHARBOR_LIMIT_PER_ENDPOINT=5/60 \
  -e PUSHHARBOR_LIMIT_REGISTRATIONS_PER_IP=1000000/3600 -e PUSHHARBOR_LIMIT_CHALLENGES_PER_TARGET=5/3600 \
  pushharbor-native:dev >/dev/null
for _ in $(seq 60); do curl -sf http://127.0.0.1:8080/v1/health >/dev/null && break; sleep 0.5; done
curl -sf http://127.0.0.1:8080/v1/health >/dev/null || { docker logs ph-cr-relay; exit 1; }
rm -f "$secrets"
export CONFORMANCE_SECRETS=$secrets
RELAY_URL=http://127.0.0.1:8080 RELAY_REQUEST_TIMEOUT_SECS=8 cargo test -q -p pushharbor-conformance --test conformance
log=$(mktemp); docker logs ph-cr-relay > "$log" 2>&1
RELAY_LOG=$log cargo test -q -p pushharbor-conformance --test logs
