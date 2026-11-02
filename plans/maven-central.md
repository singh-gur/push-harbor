# Implementation Plan: Publish `pushharbor-android` to Maven Central (PH-35)

## Overview

Publish the Android library as `io.github.singh-gur:pushharbor-android` from the existing tag
release workflow, keeping the rule that jobs able to publish run no third-party build code. A
manual dry run proves token, signature and bundle format against the real Central before the
first (permanent) publish with v0.2.0.

## Planning Profile

- Executor: Workhorse
- Detail: Standard

## Global Context

- Library: `packages/android` (standalone Gradle build; `build.gradle` is also bundled into the
  npm package by `packages/expo/scripts/sync-android.mjs`, which copies only `build.gradle` and
  `src/main`).
- Release workflow: `.github/workflows/release.yml`. Unprivileged jobs build/verify; publish jobs
  (`environment: release`) only upload. Actions pinned to SHAs, no Actions cache.
- Owner setup done: namespace `io.github.singh-gur` verified; `release` environment secrets
  `MAVEN_CENTRAL_USERNAME`, `MAVEN_CENTRAL_PASSWORD`, `GPG_PRIVATE_KEY`, `GPG_PASSPHRASE`; signing
  key `0DA6688B8C505B5C477444D4B6AB8A752A2A2A92` (RSA 4096, primary only, expires 2028-11) on
  keyserver.ubuntu.com and keys.openpgp.org.
- Central has no OIDC trusted publishing: user token + PGP signatures required. Bundle = zip in
  Maven repository layout, every file with `.md5`/`.sha1` and an `.asc` signature (checksums and
  `.asc` files need neither). Portal API: `POST /api/v1/publisher/upload?publishingType=...`
  (multipart `bundle`), `POST /api/v1/publisher/status?id=`, `DELETE
  /api/v1/publisher/deployment/<id>`; header `Authorization: Bearer base64(user:pass)`.
- Prototype (scratch copy) confirmed: AGP `singleVariant('release') { withSourcesJar();
  withJavadocJar() }` + `maven-publish` to a local repo yields AAR, POM, `.module`, javadoc jar
  (AGP-generated), sources jar, each with md5/sha1/sha256/sha512, plus `maven-metadata.xml*` at
  artifact level; `gpg --batch --pinentry-mode loopback --passphrase-fd 0 --armor --detach-sign`
  signatures verify.

## Architecture Decisions

1. Publishing config lives in `packages/android/publish.gradle`, applied from `build.gradle` only
   when the library is the root project: `if (project == rootProject) apply from: 'publish.gradle'`.
2. Version: `VERSION_NAME` in `packages/android/gradle.properties`, checked against the tag by
   `scripts/check-release-version.sh`.
3. `maven-pack` (unprivileged) builds the unsigned bundle with Gradle and uploads artifact
   `maven-bundle`. `maven-publish` (`environment: release`) downloads it, signs with `gpg`, zips,
   uploads with `curl`, polls with `jq`; no checkout, no Gradle.
4. Go-live: `publishingType=AUTOMATIC` (approval of the release run is the gate).
5. Dry run: `workflow_dispatch` boolean input `maven_dry_run`; version
   `<VERSION_NAME>-dryrun.<run_number>`; `USER_MANAGED`; wait for `VALIDATED`, then DELETE.
6. Existing-version skip: POM present at
   `https://repo1.maven.org/maven2/io/github/singh-gur/pushharbor-android/<v>/pushharbor-android-<v>.pom`.

## Assumptions

- The owner creates the GitHub release page for v0.2.0 as for v0.1.0.
- `jq`, `zip`, `gpg`, `curl` are preinstalled on `ubuntu-latest`.

## Phases

### Phase 1: Gradle publishing

- Status: Complete
- Prerequisites: none

| Path | Action | Purpose |
|---|---|---|
| `packages/android/publish.gradle` | create | `maven-publish`, group/version, AGP single variant with sources+javadoc, publication `release` (artifactId `pushharbor-android`, POM name/description/url/MIT licence/developer `singh-gur`/SCM), repository `bundle` at `build/central-bundle` |
| `packages/android/build.gradle` | modify | Append the guarded `apply from` line with a one-line comment |
| `packages/android/gradle.properties` | modify | `VERSION_NAME=0.1.0` |
| `scripts/check-release-version.sh` | modify | Also read `VERSION_NAME`, print and compare it |
| `justfile` | modify | `android-bundle`: build the bundle, list its files |

- [x] Implement the files above.
- [x] Verify: `just android-bundle` lists aar/pom/module/sources/javadoc each with 4 checksums;
  `just test-android`, `just test-expo` pass; `npm pack --dry-run` in `packages/expo` does not list
  `publish.gradle`; `scripts/check-release-version.sh v0.1.0` exits 0.

### Phase 2: Release jobs and dry run

- Status: Complete
- Prerequisites: Phase 1

| Path | Action | Purpose |
|---|---|---|
| `.github/workflows/release.yml` | modify | `maven_dry_run` input; `maven-pack` and `maven-publish` jobs; header comment |

- `maven-pack`: `if: startsWith(github.ref, 'refs/tags/v') || inputs.maven_dry_run`; checkout
  (no credentials), setup-java 17 (CI's SHA), version check on tags, build with
  `-PVERSION_NAME=<v>-dryrun.$GITHUB_RUN_NUMBER` for dry runs, upload
  `packages/android/build/central-bundle` as `maven-bundle` (`if-no-files-found: error`).
- `maven-publish`: `needs: maven-pack`, same `if`, `environment: release`, `contents: read`;
  inputs via `env:` only (no `${{ }}` inside `run`). Script: version from the bundle folder; skip
  real runs if on repo1; temp `GNUPGHOME`; import key; delete `maven-metadata.xml*`; sign all
  non-checksum files; zip; `::add-mask::` the bearer token; upload; poll 15 s up to 30 min.
  Real: PUBLISHED → ok, PUBLISHING at timeout → ok with note, FAILED → print `errors`, exit 1.
  Dry run: VALIDATED → DELETE (expect 204) → ok; FAILED → print errors, keep, exit 1.
- [x] Implement; push; owner starts "Release" manually with `maven_dry_run` and approves.
- [x] Verify: run log shows `VALIDATED` and DELETE 204.

### Phase 3: v0.2.0 release

- Status: In Progress
- Prerequisites: Phase 2 dry run passed

- [ ] Bump to 0.2.0: `Cargo.toml` workspace version, `crates/native/Cargo.toml` and
  `crates/worker/Cargo.toml` `pushharbor-core` versions, `Cargo.lock` (via cargo),
  `packages/expo` (`npm version 0.2.0 --no-git-tag-version`), `packages/expo/android/build.gradle`
  (`version`, `versionName`), `VERSION_NAME`, `deploy/helm/pushharbor/Chart.yaml`
  (`version`, `appVersion`), `deploy/cloudrun/service.yaml` image tag, `docs/deploy.md` pin
  example, README image tag and Releases row.
- [ ] Docs: `docs/android.md` Install uses `implementation("io.github.singh-gur:pushharbor-android:0.2.0")`
  (keep source include as an alternative) and lists the signing key fingerprint; README install row.
- [ ] Verify locally: `scripts/check-release-version.sh v0.2.0`, `just ci`, `just test-android`,
  `just test-expo`; push; CI green.
- [ ] Owner tags `v0.2.0` and approves; verify repo1 serves the POM and a fresh Gradle project
  resolves the dependency; npm, crates, image released.

## Phase Dependencies

1 → 2 → 3.

## Risks

- Central versions are permanent: Phase 3 only after a passing dry run.
- A re-run right after publishing (before repo1 sync) uploads again and fails validation loudly;
  nothing is published twice.

## Questions for User

- None.
