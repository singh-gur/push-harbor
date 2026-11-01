#!/usr/bin/env bash
# Fails unless the release tag (v0.1.0) matches the crates' and the npm package's version.
set -euo pipefail
tag=${1:?usage: check-release-version.sh v<version>}
want=${tag#v}
cargo_version=$(sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\(.*\)"/\1/p' Cargo.toml)
npm_version=$(node -p 'require("./packages/expo/package.json").version')
echo "tag $want, crates $cargo_version, npm $npm_version"
[ "$cargo_version" = "$want" ] && [ "$npm_version" = "$want" ]
