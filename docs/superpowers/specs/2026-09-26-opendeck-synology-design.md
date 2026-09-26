# OpenDeck Synology - Design

Date: 2026-09-26
Status: Approved in brainstorming, pending spec review

## 1. Goal

An [OpenDeck](https://github.com/nekename/OpenDeck) plugin that turns Stream Deck keys and
dials into a live, read-only status panel for **one Synology NAS running DSM 7.x**. It is
modelled on Elgato Marketplace's *DeckPulse Synology DSM 7*, and differs from it by
supporting dials and DSM accounts with 2FA enabled.

### Success criteria

- All 10 actions (section 5) work on both keys and dials against the author's own DSM 7 NAS,
  which has 2FA enabled.
- After a one-time OTP entry, the plugin reconnects across OpenDeck and NAS restarts
  without asking for a code again.
- Ten visible keys that read the same DSM endpoint cost one request per refresh, not ten.
- A wrong password never leads to repeated login attempts, so DSM auto-block never fires
  because of the plugin.
- Only the configured NAS is ever contacted: no telemetry and no third-party hosts.

### Non-goals (v1)

- Multiple NAS profiles. There is one global connection, stored so that adding profiles
  later does not need a rewrite.
- Any action that changes the NAS: reboot, shutdown, Docker, backup triggers.
- An "Overview" dial that cycles through all metrics.
- Translations. The UI is English only.
- Platforms other than Linux x86_64.

## 2. Stack and conventions

Same as the author's existing plugins (`weather-opendeck`, `opendeck-power-profile`,
`opendeck-claude-usage`):

- Rust (edition 2024) with `openaction` 2.x, `tokio`, `reqwest` (rustls, no default
  features), `serde`, `thiserror`, `dashmap`, `log` + `simplelog`.
- New crates: `keyring` (Secret Service backend), `sha2` (certificate fingerprints),
  `rustls` (custom certificate verifier). Dev-only: `rcgen` (test certificates).
- `build.mjs` packages a `.streamDeckPlugin`; GitHub Actions `ci.yml` (fmt, clippy
  `-D warnings`, test) and `release.yml` (build and attach on tag).
- Repo: `~/git/opendeck-synology`, crate `opendeck-synology`, default branch `master`.
- Action UUIDs: `com.jfms7s.synology.<metric>`. All actions are listed under a
  **Synology** category in OpenDeck.

## 3. Architecture

```
src/
  main.rs            register 10 actions, spawn pollers, wire shared Services
  dsm/
    client.rs        HTTP + TLS (pinned cert fingerprint), SYNO.API.Info discovery
    auth.rs          login (password + OTP -> device token), session reuse, re-login
    api.rs           typed calls: utilization(), storage(), system_info(), update_status()
    model.rs         serde structs for the four DSM responses -> plain domain types
  poller.rs          generic Poller<T>: subscribers, effective interval, last value/error,
                     broadcast via tokio::sync::watch
  services.rs        owns DsmClient + the 4 pollers; subscribe(instance, endpoint, interval)
  tracker.rs         live instances: settings + dial view state
  metrics.rs         pure fns: (snapshot, settings, view) -> Reading {label, value, level}
  render/
    key.rs           SVG key image
    dial.rs          touch-strip layout
  actions/           one thin file per action: settings, endpoint, metric fn
assets/
  manifest.json, icons/, layouts/, propertyInspector/
tests/
  fixtures/          recorded DSM JSON responses
```

### Data flow

1. When a key or dial appears, its action subscribes to one endpoint through
   `Services::subscribe(instance_id, endpoint, interval)`.
2. Each endpoint's poller runs only while it has at least one subscriber. It polls at the
   **minimum** interval of its current subscribers, and stops when the last one
   unsubscribes (the key disappears).
3. Each new snapshot (or error) is broadcast on a `watch` channel. Each subscribed instance
   runs `metrics::read(snapshot, settings, view)` to get a `Reading`, then `render`, then
   `set_image` (key) or `set_feedback` (dial).
4. `metrics` and `render` do no I/O and are fully unit-testable.

### Endpoints and polling

| Endpoint | DSM API / method | Feeds | Default interval |
|---|---|---|---|
| Utilization | `SYNO.Core.System.Utilization` `get` | CPU, RAM, Network | 5 s |
| System info | `SYNO.Core.System` `info` | System temp, Uptime | 30 s |
| Storage | `SYNO.Storage.CGI.Storage` `load_info` | Disk temp, Disk health, Volume, Storage pool | 60 s |
| Update | `SYNO.Core.Upgrade.Server` `check` | DSM update | 6 h |

The interval can be overridden per action instance. The minimum is 2 s; anything lower is
clamped.

## 4. Authentication, 2FA and TLS

### Settings

- **Global settings file (plain JSON):** host, port (default 5001), `https` (default true),
  account, temperature unit (°C/°F), pinned certificate fingerprint.
- **System keyring (Secret Service via `keyring`):** password and the 2FA device token
  (`did`). If no keyring is available, the plugin stores both in the global settings and
  logs a warning once.
- A shared **Connection** block at the top of every action's settings panel edits these
  and shows a live status line: `Connected as <user> - DSM <version>`, `Needs 2FA code`,
  `Wrong password`, `IP blocked by DSM`, `Certificate not trusted`, `Certificate changed`,
  `Unreachable`.

### Login flow

1. Call `SYNO.API.Info` `query` once per connection to learn the paths and maximum
   versions for the APIs above. Auth uses v6 or higher.
2. Call `SYNO.API.Auth` `login` with `account`, `passwd`, `session=OpenDeck`, `format=sid`,
   and `device_id=<did>` / `device_name` if a `did` is stored.
3. **Error 403** (2FA code required): the status becomes `Needs 2FA code`. The panel shows
   an OTP field, and keys and dials show a lock glyph with the text `2FA`. Pollers pause.
4. When an OTP is submitted, the plugin calls `login` again with `otp_code`,
   `enable_device_token=yes` and `device_name=OpenDeck-<hostname>`. It stores the `did`
   from the response in the keyring and resumes the pollers.
5. **Session expired** (errors 106/107/119 on a data call): log in again once, silently,
   then retry the call once. **Error 105** (no permission) is ambiguous right after a
   session loss, so it gets the same single re-login and retry; if the retry returns 105
   again, the error is `Permission` and no further re-login happens for that endpoint
   until the next poll. Concurrent pollers share a single in-flight login (a mutex
   around the session plus a generation counter), so they never set off parallel logins.
6. **No automatic retry** on 400 (bad credentials), 404 (bad OTP), 406 (2FA enforced but
   not set up), 407 (IP blocked) or 410 (password expired). The plugin pauses the pollers,
   shows the status, and waits for a settings change.
7. When the plugin shuts down it makes a best-effort `SYNO.API.Auth` `logout` call, with a
   1 s timeout.

If the stored `did` is rejected (a 403 again after sending `device_id`), the plugin drops
the `did` and goes back to step 3.

### TLS

- A custom rustls `ServerCertVerifier` accepts the server certificate if **either**:
  - it validates against the system roots (webpki) for the configured host, **or**
  - the SHA-256 fingerprint of its leaf certificate equals the pinned fingerprint. Hostname
    mismatches are ignored in this case, because the pin is the trust anchor.
- If neither holds and no pin is stored, the connection fails with
  `CertificateNotTrusted {fingerprint, subject}`. The panel shows both, plus a **Trust this
  certificate** button that stores the fingerprint.
- If a pin is stored and doesn't match, the connection fails with `CertificateChanged`,
  which the panel shows the same way and which must be re-trusted explicitly.
- Plain HTTP (port 5000) is allowed when `https=false`. The panel labels it "unencrypted".

## 5. Actions

Every action works on both keys and dials, and has these settings: refresh interval
(optional override), warn threshold and crit threshold (numeric metrics only), plus the
action-specific settings below.

| Action (UUID suffix) | Source fields | Key shows | Dial views (rotate) | Default warn / crit |
|---|---|---|---|---|
| CPU (`cpu`) | `cpu.user_load + system_load + other_load`; `1min_load`, `5min_load`, `15min_load` | `37%` | total -> 1m -> 5m -> 15m | 70 / 90 % |
| RAM (`ram`) | `memory.real_usage`, `total_real`, `avail_real` | `62%` | % -> `9.8 / 16 GB` | 80 / 95 % |
| Network (`network`) | `network[]` entry `total` or a chosen interface; `rx`, `tx` (B/s) | `↓12.4 MB/s` | in -> out -> combined | none (optional, MB/s) |
| System temp (`systemp`) | `sys_temp` | `48°C` | (none) | 60 / 70 °C |
| Uptime (`uptime`) | `up_time` | `12d 4h` | (none) | none |
| Disk temp (`disktemp`) | `disks[].temp`, `id`, `name` | `41°C` + disk name | each disk -> hottest | 50 / 60 °C |
| Disk health (`diskhealth`) | `disks[].smart_status`, `status` | `OK` / `Warning` / `Failing` | each disk -> worst | state-based |
| Volume (`volume`) | `volumes[].size.total`, `size.used`, `status` | `71%` or `5.1/7.2 TB` | each volume | 80 / 90 % |
| Storage pool (`pool`) | `storagePools[].status`, `raidType`, repair/expand progress | `Normal` / `Degraded` / `Rebuild 43%` | each pool | state-based |
| DSM update (`update`) | `available`, `version` | `Up to date` / `<version>` | (none) | update pending = warn |

The field names are what DSM 7 is expected to return. **The first implementation task
records real responses from the author's NAS as fixtures**, and the field mappings are
adjusted to match them.

Action-specific settings:

- **Network:** direction (in / out / combined); interface (`total` or a name from the
  latest snapshot).
- **Disk temp:** disk (a disk ID such as `sata1`, or "hottest").
- **Disk health:** disk (a disk ID, or "worst").
- **Volume:** volume ID; display (percent / used-of-total).
- **Storage pool:** pool ID.
- **CPU:** default view (total / 1m / 5m / 15m).

Dropdowns for disks, volumes, pools and interfaces are filled from the latest snapshot. The
plugin sends it to the panel when the panel opens.

### State-to-level mapping

- Disk health: `normal` -> normal; `warning` or `abnormal` -> warn; `failing`, `crashed`
  or any status other than normal -> crit. Unknown strings -> warn and are logged once.
- Storage pool: `normal` -> normal; `repairing`, `expanding` or `verifying` (with
  progress) -> warn; `degraded` or `crashed` -> crit. Unknown -> warn and are logged once.
- DSM update: none available -> normal; available -> warn.

## 6. Rendering

- **Levels:** `Normal`, `Warn`, `Crit`, `Stale`, `Error`. The key background tint is
  neutral, amber, red, grey and red respectively. `Stale` and `Error` add a small `!`
  glyph.
- **Key:** an icon at the top, the value large in the middle, the label/subject small at
  the bottom (e.g. `Drive 3`, `volume_1`).
- **Dial touch strip:** the action name on top, the value, then a horizontal bar for
  numeric metrics (filled to value / max, with threshold ticks) or a state pill for
  state-based metrics. A `‹ n/m ›` hint shows when rotation has more views.
- **Dial input:** rotating changes that instance's in-memory view only; it does not
  persist. Pressing forces an immediate poll of that endpoint. For keys, pressing does the
  same.
- **Units:** temperature follows the global °C/°F setting. Sizes use binary multiples but
  are labelled GB/TB, like DSM. Throughput scales automatically between B/s, KB/s and MB/s.

### Missing, stale and unsupported data

- **Stale:** if a poll fails, the last reading stays on screen; after 3 consecutive failed
  intervals the level becomes `Stale`. A zero is never shown in place of missing data.
- **Chosen disk, volume or pool missing** from the snapshot: the key shows `Missing` at
  level `Crit`.
- **Field absent on this model** (e.g. no `sys_temp`): the key shows `N/A` at level
  `Normal`.
- **Permission denied** on Storage (error 105 persisting after one re-login, see section 4): the four storage actions show `No permission`, and the other actions are
  unaffected.
- **Before the first snapshot:** `…` at level `Normal`.

## 7. Error handling

- `DsmError` (`thiserror`) variants: `Transport` (timeout, DNS, connection refused),
  `CertificateNotTrusted`, `CertificateChanged`, `Auth(AuthError)` (NeedOtp,
  BadCredentials, BadOtp, Blocked, PasswordExpired, OtpEnforced), `Permission`, and
  `Api {api, code}`.
- **Transport and API errors:** the affected poller backs off (interval × 2, up to 5 min)
  and resets after the first success.
- **Auth and TLS errors:** **all** pollers pause until the connection settings change or
  an OTP or trust action is taken. The status line and keys show why.
- Every request has a 10 s timeout. The only host ever contacted is the configured one.
- Logging goes through `simplelog` to OpenDeck's plugin log. Passwords, OTP codes, `sid`
  and `did` are never logged; the request logger redacts those query parameters.

## 8. Testing

- **Unit tests, fixture-driven (no network):** the `metrics` mappings for all 10 actions
  against recorded NAS responses, plus hand-edited fixtures (degraded pool, rebuilding
  pool, failing disk, missing `sys_temp`, missing selected disk); threshold/level logic;
  unit formatting; dial view cycling.
- **Poller tests (`tokio` test-util, paused time):** the effective interval is the minimum
  across subscribers and is recalculated on unsubscribe; polling stops at zero
  subscribers; backoff and reset; pausing on auth/TLS errors; a forced refresh on press.
- **Auth tests** against a fake transport behind a `DsmTransport` trait: 403 -> OTP -> `did`
  stored; `did` accepted on the next login; a rejected `did` is dropped; session expiry
  leads to exactly one re-login even with 4 concurrent callers; no retry on 400/404/407.
- **TLS verifier tests** with certificates generated by `rcgen`: pinned match accepted;
  unknown certificate rejected with its fingerprint; pin mismatch reported as
  `CertificateChanged`.
- **Manual smoke-test checklist** in the README, run against the real NAS before each
  release: 2FA first run; OpenDeck restart without OTP; NAS reboot; network cable pulled
  (goes stale, then recovers); certificate renewed (`Certificate changed`, re-trust); each
  action on a key and a dial.
