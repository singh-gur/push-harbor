# Real-device end-to-end checklist (Android)

Manual checks on a physical phone, through both hosting options. Run them before a release and
when the Expo module, the relay or the protocol changes. iOS-5 reuses this list with its own
device steps. Last run: Pixel 8 Pro, Android 17, 2026-10-31 (PH-11): all checks passed on native
and Workers.

## Setup

- A phone with Google Play services, USB debugging on, connected and authorized (`adb devices`).
  With several devices attached, `export ANDROID_SERIAL=<serial>`.
- `examples/expo/google-services.json` and `examples/expo/service-account.json` for the test
  Firebase project (not in git).
- Install the example app: `cd examples/expo && npx expo prebuild --platform android --clean &&
  (cd android && ./gradlew :app:installDebug)`. Open it once and answer the prompts (allow
  notifications; the "nearby devices" prompt of debug builds can be denied).
- **Native relay**: `just example-relay` (port 8080), then `adb reverse tcp:8080 tcp:8080`; relay
  URL `http://127.0.0.1:8080`.
- **Workers relay** (from `crates/worker`): `npx wrangler deploy --name pushharbor-test --var
  PUSHHARBOR_ORIGIN:https://pushharbor-test.<subdomain>.workers.dev`, then `npx wrangler secret
  put PUSHHARBOR_FCM_SERVICE_ACCOUNT --name pushharbor-test < ../../examples/expo/service-account.json`.
  Delete it afterwards: `npx wrangler delete --name pushharbor-test`.

Play two servers with their own VAPID keys (from `examples/expo`):

```sh
mkdir -p .e2e
keyA=$(VAPID=.e2e/serverA.json node scripts/send.mjs keys)
keyB=$(VAPID=.e2e/serverB.json node scripts/send.mjs keys)
```

Register the phone for a server (open the app first; the example can miss a link sent while it
is still starting), then save the subscription it wrote:

```sh
adb shell am start -a android.intent.action.VIEW \
  -d "'pushharborexample://register?relay=<url-encoded relay URL>&key=$keyA'" dev.pushharbor.testapp
adb exec-out run-as dev.pushharbor.testapp cat files/subscription.json > .e2e/A.json
```

Send as a server: `VAPID=.e2e/serverA.json SUB=.e2e/A.json node scripts/send.mjs send '<envelope>'`
(prints the relay's status). Check what the phone shows without opening the shade:
`adb shell dumpsys notification --noredact`, looking only at records with
`pkg=dev.pushharbor.testapp`.

## Checks (repeat for each relay)

| # | Check | How | Expected |
|---|---|---|---|
| 1 | Registration through the real challenge | Register for server A and B | Both registered within a few seconds; relay log: register 202, confirm 201 |
| 2 | Encrypted push shown | Send `{"t":..,"b":..,"g":"t1"}` as A | 201; notification with that title, tag `t1` |
| 3 | Payload cap | Envelope of exactly 2,797 bytes; then 2,798 | 201 and shown; then 413 |
| 4 | Undecryptable payload | `WRONG_AUTH=1` send | 201 at the relay; nothing shown; device log `dropped push: AEADBadTagException` |
| 5 | Sender isolation | Server A's key on B's endpoint; a random endpoint ID; a native endpoint at the Worker | 403; 404; 404 |
| 6 | No endpoint without the challenge | `POST /v1/registrations` from the host with the phone's FID (`run-as … cat shared_prefs/pushharbor.xml`, `target`) and another key; wait 20 s; confirm with a guessed nonce; confirm again | The phone does **not** confirm (relay log / `wrangler tail`); 403; 404 |
| 7 | Unregister | Unregister B in the app | Relay DELETE 204; sends to B 404; A still 201 |
| 8 | Endpoint rotation | Register A again, unregister the old A | Old endpoint 404; new one 201 and shown |
| 9 | Killed app | `adb shell input keyevent KEYCODE_HOME; adb shell am kill dev.pushharbor.testapp`, send | Shown |
| 10 | Doze | `adb shell dumpsys battery unplug; adb shell input keyevent KEYCODE_SLEEP; adb shell dumpsys deviceidle force-idle`, send; then `deviceidle unforce; battery reset` | Shown |
| 11 | Device gone | `adb uninstall dev.pushharbor.testapp`, send to both relays | 410 within ~10 s, then 404 |

Not on this list because the emulator run covers it: FCM ID rotation keeping the endpoint
(PH-7: a stale stored target is moved with `replaces` on app start).

## Results 2026-10-31 (Pixel 8 Pro, Android 17)

| # | Native (SQLite) | Workers |
|---|---|---|
| 1 | 2 s / 3 s | 3 s |
| 2–5 | pass | pass |
| 6 | pass: no confirm from the phone, 403, 404 | pass: tail shows only the attacker's (curl) confirms |
| 7–9 | pass | pass (7 via the module's DELETE call) |
| 10 | pass (forced deep idle, screen off, app killed) | not repeated |
| 11 | 410 at +10 s, then 404 | 410 at +10 s, then 404 |
