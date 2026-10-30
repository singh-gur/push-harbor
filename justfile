# Pushharbor development tasks. Run `just` to list them.

wasm_target := "wasm32-unknown-unknown"

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
    rm -f target/conformance-secrets.txt
    RELAY_URL={{relay_url}} cargo test -p pushharbor-conformance --test conformance
    RELAY_LOG={{log}} cargo test -p pushharbor-conformance --test logs

# Run the native server
run-native *args:
    cargo run -p pushharbor-native -- {{args}}

# Everything CI runs
ci: lint test test-wasm build-wasm
