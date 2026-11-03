#!/usr/bin/env bash
# Release notes for a tag (v0.2.0): install lines for that version and the commit subjects since
# the previous release tag (suffixed tags like v0.1.0-dryrun.1 are skipped). Used by the
# github-release job in .github/workflows/release.yml; needs the full history and tags.
set -euo pipefail
tag=${1:?usage: release-notes.sh v<version>}
version=${tag#v}
prev=$(git describe --tags --abbrev=0 --match 'v[0-9]*' --exclude '*-*' "$tag^" 2>/dev/null || true)

cat <<EOF
## Install

- Android library: \`implementation("io.github.singh-gur:pushharbor-android:$version")\`
  (signed with PGP key \`0DA6688B8C505B5C477444D4B6AB8A752A2A2A92\`)
- Expo / React Native module: \`npx expo install @pushharbor/expo\`
- Relay container: \`docker pull ghcr.io/singh-gur/pushharbor-native:$version\`
- Relay binary: \`cargo install pushharbor-native\`
- Protocol library (Rust): \`cargo add pushharbor-core\`

## Changes

EOF
git log --no-merges --format='- %s' "${prev:+$prev..}$tag"
if [ -n "$prev" ]; then
  printf '\n**Full Changelog**: https://github.com/singh-gur/push-harbor/compare/%s...%s\n' "$prev" "$tag"
fi
