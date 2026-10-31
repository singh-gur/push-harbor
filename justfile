# Pushharbor development tasks. Run `just` to list them.

wasm_target := "wasm32-unknown-unknown"
secrets := justfile_directory() + "/target/conformance-secrets.txt"

# Runs wasm32-wasip1 test/example binaries under Node (V8, same engine as Workers)
export CARGO_TARGET_WASM32_WASIP1_RUNNER := "node --no-warnings " + justfile_directory() + "/scripts/wasi-run.mjs"

# List available tasks
default:
    @just --list

# Format all code
fmt:
    cargo fmt --all

# Check formatting and run clippy with warnings as errors
lint:
    cargo fmt --all --check
    cargo clippy --workspace --all-targets -- -D warnings
    cargo clippy -p pushharbor-worker --target {{wasm_target}} -- -D warnings

# Run all tests
test:
    cargo test --workspace

# Build core + worker for wasm32 (installs the target if missing)
build-wasm:
    rustup target add {{wasm_target}}
    cargo build -p pushharbor-core -p pushharbor-worker --target {{wasm_target}}

# Run core tests compiled to wasm under Node (needs node >= 20)
test-wasm:
    rustup target add wasm32-wasip1
    cargo test -p pushharbor-core --target wasm32-wasip1

# Time vapid::verify natively and as wasm under Node
bench-vapid:
    cargo run -q --release -p pushharbor-core --example vapid_bench
    rustup target add wasm32-wasip1
    cargo run -q --release -p pushharbor-core --example vapid_bench --target wasm32-wasip1

# Conformance suite against a running relay configured per crates/conformance docs; optional log check
conformance relay_url log="":
    rm -f {{secrets}}
    CONFORMANCE_SECRETS={{secrets}} RELAY_URL={{relay_url}} cargo test -p pushharbor-conformance --test conformance
    CONFORMANCE_SECRETS={{secrets}} RELAY_LOG={{log}} cargo test -p pushharbor-conformance --test logs

# Conformance suite against the native server (SQLite) started with the suite's contract config
conformance-native:
    #!/usr/bin/env bash
    set -euo pipefail
    log=$(mktemp)
    scripts/with-native.sh http://127.0.0.1:8080 "sqlite://$(mktemp -d)/pushharbor.db" "$log" \
      just conformance http://127.0.0.1:8080 "$log"

# Conformance suite against two native instances sharing a PostgreSQL database (Docker), plus
# the multi-instance test (shared limits, idempotency and pending registrations)
conformance-postgres:
    #!/usr/bin/env bash
    set -euo pipefail
    docker rm -f ph-postgres >/dev/null 2>&1 || true
    docker run -d --rm --name ph-postgres -p 127.0.0.1:55432:5432 --tmpfs /var/lib/postgresql \
      -e POSTGRES_PASSWORD=pushharbor -e POSTGRES_DB=pushharbor postgres:17-alpine >/dev/null
    trap 'docker rm -f ph-postgres >/dev/null 2>&1 || true' EXIT
    for _ in $(seq 60); do docker exec ph-postgres pg_isready -q -U postgres -d pushharbor && break; sleep 0.5; done
    db=postgres://postgres:pushharbor@127.0.0.1:55432/pushharbor
    log=$(mktemp)
    scripts/with-native.sh http://127.0.0.1:8080 $db "$log" \
      env PUSHHARBOR_LISTEN=127.0.0.1:8081 scripts/with-native.sh http://127.0.0.1:8080 $db "$log.b" \
      bash -c "just conformance http://127.0.0.1:8080 $log && \
        RELAY_URL=http://127.0.0.1:8080 RELAY_URL_2=http://127.0.0.1:8081 CONFORMANCE_SECRETS={{secrets}} \
        cargo test -p pushharbor-conformance --test multi_instance && \
        CONFORMANCE_SECRETS={{secrets}} RELAY_LOG=$log.b cargo test -p pushharbor-conformance --test logs"

# Conformance suite against the Workers adapter in `wrangler dev` (local workerd + Durable
# Objects). Needs node and worker-build (`cargo install worker-build@0.8.7`).
conformance-worker:
    #!/usr/bin/env bash
    set -euo pipefail
    log=$(mktemp)
    scripts/with-worker.sh http://127.0.0.1:8787 "$log" just conformance http://127.0.0.1:8787 "$log"

# Install the interop senders' dependencies (needs node, go, docker; python runs via uv)
interop-setup:
    cd interop/node && npm ci --silent
    cd interop/go && go build -o ../../target/interop/go-send .
    docker run --rm -v "$PWD/interop/php":/app:Z -w /app composer:2 install -q --no-progress

# Sender interop (PH-22): Web Push libraries send to a relay (`native` or `worker`) behind a
# local TLS proxy on port 443, in a container so no root is needed (web-push-php drops the port
# from the VAPID aud; Node's web-push only speaks HTTPS)
interop relay="native" libs="node,python,go,php": interop-setup
    #!/usr/bin/env bash
    set -euo pipefail
    dir=target/interop; mkdir -p $dir
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj /CN=127.0.0.1 \
      -addext subjectAltName=IP:127.0.0.1 -keyout $dir/tls-key.pem -out $dir/tls-cert.pem 2>/dev/null
    port=$([ {{relay}} = worker ] && echo 8787 || echo 8080)
    docker run -d --rm --name ph-tls-proxy --network host -v "$PWD":/repo:Z -w /repo node:24-alpine \
      node interop/tls-proxy.mjs 443 $port $dir/tls-cert.pem $dir/tls-key.pem >/dev/null
    trap 'docker rm -f ph-tls-proxy >/dev/null 2>&1 || true' EXIT
    export RELAY_URL=http://127.0.0.1:$port INTEROP_LIBS={{libs}} INTEROP_CA=$PWD/$dir/tls-cert.pem \
      CONFORMANCE_SECRETS={{secrets}}
    test="cargo test -p pushharbor-conformance --test interop -- --nocapture"
    if [ {{relay}} = worker ]; then
      scripts/with-worker.sh https://127.0.0.1 "$(mktemp)" $test
    else
      scripts/with-native.sh https://127.0.0.1 "sqlite://$(mktemp -d)/pushharbor.db" "$(mktemp)" $test
    fi

# Run the native server
run-native *args:
    cargo run -p pushharbor-native -- {{args}}

# Everything CI runs
ci: lint test test-wasm build-wasm

# Build the Expo module and run its Kotlin unit tests (spec vectors) through the example app.
# Without examples/expo/google-services.json a placeholder is used (enough to build, not to receive pushes).
test-expo:
    cd packages/expo && npm ci --silent && npx tsc
    cd examples/expo && npm ci --silent && { [ -f google-services.json ] || cp google-services.placeholder.json google-services.json; } \
      && npx tsc --noEmit && npx expo prebuild --platform android --clean > /dev/null
    cd examples/expo/android && ./gradlew -q :pushharbor-expo:testDebugUnitTest

# Native relay with real FCM for the example app on an emulator or USB device: run it, then
# `adb reverse tcp:8080 tcp:8080` and register with relay URL http://127.0.0.1:8080.
# Needs examples/expo/service-account.json (Firebase service account; gitignored).
example-relay:
    PUSHHARBOR_ORIGIN=http://127.0.0.1:8080 PUSHHARBOR_LISTEN=127.0.0.1:8080 \
    PUSHHARBOR_DATABASE_URL="sqlite://$(mktemp -d)/pushharbor.db" \
    PUSHHARBOR_FCM_SERVICE_ACCOUNT_FILE=examples/expo/service-account.json \
    cargo run -q -p pushharbor-native
