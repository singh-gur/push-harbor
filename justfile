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

# Install the interop senders' dependencies (needs node, go, docker; python runs via uv)
interop-setup:
    cd interop/node && npm ci --silent
    cd interop/go && go build -o ../../target/interop/go-send .
    docker run --rm -v "$PWD/interop/php":/app:Z -w /app composer:2 install -q --no-progress

# Sender interop (PH-22): Web Push libraries send to the native relay behind a local TLS proxy
interop-native libs="node,python,go,php": interop-setup
    #!/usr/bin/env bash
    set -euo pipefail
    dir=target/interop; mkdir -p $dir
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj /CN=127.0.0.1 \
      -addext subjectAltName=IP:127.0.0.1 -keyout $dir/tls-key.pem -out $dir/tls-cert.pem 2>/dev/null
    # Port 443 (in a container, so no root is needed): web-push-php drops the port from the VAPID aud.
    docker run -d --rm --name ph-tls-proxy --network host -v "$PWD":/repo:Z -w /repo node:24-alpine \
      node interop/tls-proxy.mjs 443 8080 $dir/tls-cert.pem $dir/tls-key.pem >/dev/null
    trap 'docker rm -f ph-tls-proxy >/dev/null 2>&1 || true' EXIT
    RELAY_URL=http://127.0.0.1:8080 INTEROP_LIBS={{libs}} INTEROP_CA=$PWD/$dir/tls-cert.pem \
    CONFORMANCE_SECRETS={{secrets}} scripts/with-native.sh https://127.0.0.1 \
      "sqlite://$(mktemp -d)/pushharbor.db" "$(mktemp)" \
      cargo test -p pushharbor-conformance --test interop -- --nocapture

# Run the native server
run-native *args:
    cargo run -p pushharbor-native -- {{args}}

# Everything CI runs
ci: lint test test-wasm build-wasm
