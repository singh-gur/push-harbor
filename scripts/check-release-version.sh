#!/usr/bin/env bash
# Fails unless the release tag (v0.1.0) matches the crates', the npm package's and the Android
# library's version.
set -euo pipefail
tag=${1:?usage: check-release-version.sh v<version>}
want=${tag#v}
cargo_version=$(sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\(.*\)"/\1/p' Cargo.toml)
npm_version=$(node -p 'require("./packages/expo/package.json").version')
android_version=$(sed -n 's/^VERSION_NAME=//p' packages/android/gradle.properties)
echo "tag $want, crates $cargo_version, npm $npm_version, android $android_version"
[ "$cargo_version" = "$want" ] && [ "$npm_version" = "$want" ] && [ "$android_version" = "$want" ]
