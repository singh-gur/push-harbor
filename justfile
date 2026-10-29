# Pushharbor development tasks. Run `just` to list them.

wasm_target := "wasm32-unknown-unknown"

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

# Run the native server
run-native *args:
    cargo run -p pushharbor-native -- {{args}}

# Everything CI runs
ci: lint test build-wasm
