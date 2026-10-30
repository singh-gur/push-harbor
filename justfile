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
    cargo build -q -p pushharbor-native
    db=$(mktemp -d)/pushharbor.db; log=$(mktemp)
    PUSHHARBOR_ORIGIN=http://127.0.0.1:8080 PUSHHARBOR_LISTEN=127.0.0.1:8080 \
    PUSHHARBOR_DATABASE_URL=sqlite://$db \
    PUSHHARBOR_FCM_SERVICE_ACCOUNT_FILE=crates/conformance/fixtures/service-account.json \
    PUSHHARBOR_FCM_API_BASE=http://127.0.0.1:9790 PUSHHARBOR_PROVIDER_TIMEOUT_SECS=5 \
    PUSHHARBOR_LIMIT_GLOBAL=1000000/60 PUSHHARBOR_LIMIT_PER_IP=1000000/60 \
    PUSHHARBOR_LIMIT_PER_SENDER=10/60 PUSHHARBOR_LIMIT_PER_ENDPOINT=5/60 \
    PUSHHARBOR_LIMIT_REGISTRATIONS_PER_IP=1000000/3600 PUSHHARBOR_LIMIT_CHALLENGES_PER_TARGET=5/3600 \
    RUST_LOG=debug target/debug/pushharbor-native > "$log" 2>&1 &
    relay=$!
    trap 'kill $relay 2>/dev/null || true' EXIT
    for _ in $(seq 50); do curl -sf http://127.0.0.1:8080/v1/health >/dev/null && break; sleep 0.2; done
    just conformance http://127.0.0.1:8080 "$log"

# Run the native server
run-native *args:
    cargo run -p pushharbor-native -- {{args}}

# Everything CI runs
ci: lint test test-wasm build-wasm
