# OpenDeck Synology Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build an OpenDeck plugin that shows live, read-only status of one Synology DSM 7 NAS (10 metrics) on Stream Deck keys and dials, with 2FA login and certificate pinning.

**Architecture:** One DSM `Session` (login, 2FA device token, single-flight re-login) is shared by four endpoint `Poller`s. Each poller runs only while a key or dial subscribes to it, at the shortest requested interval, and broadcasts results on a `tokio::sync::watch` channel. Each visible key or dial has a render task that turns the latest poll into a `Reading` with pure functions (`metrics`), then draws it with `render::key` (SVG image) or `render::dial` (touch-strip feedback).

**Tech Stack:** Rust 2024, `openaction` 2.7, `tokio`, `reqwest` 0.13 (rustls + form), `rustls` 0.23 with a custom certificate verifier, `rustls-native-certs`, `sha2`, `keyring` 3 (Secret Service), `serde_json`, `thiserror`, `dashmap`, `futures`, `gethostname`; dev: `rcgen`, tokio `test-util`. Plugin packaging with `build.mjs` (Node), icons rendered with ImageMagick (`magick`).

**Spec:** `docs/superpowers/specs/2026-09-26-opendeck-synology-design.md`. Read it before starting any task.

## Global Constraints

- Crate name `opendeck-synology`, version `0.1.0`, edition `2024`, license MIT, default branch `master`.
- Plugin UUID `com.jfms7s.synology`. Action UUIDs `com.jfms7s.synology.<suffix>`, with suffixes `cpu`, `ram`, `network`, `systemp`, `uptime`, `disktemp`, `diskhealth`, `volume`, `pool`, `update`. Manifest `"Category": "Synology"`.
- Linux `x86_64-unknown-linux-gnu` only.
- Every action supports both `Keypad` and `Encoder` controllers.
- Default poll intervals: Utilization 5 s, System info 30 s, Storage 60 s, Update 6 h. Per-instance override, minimum 2 s (clamped).
- Default thresholds (warn / crit): CPU 70 / 90 %, RAM 80 / 95 %, system temperature 60 / 70 °C, disk temperature 50 / 60 °C, volume 80 / 90 %. Network has none unless the user sets them (MB/s). Temperature thresholds are always in °C.
- A value goes `Stale` after 3 consecutive failed polls. The backoff after n consecutive failures is interval × 2ⁿ, capped at 5 min.
- Every HTTP request has a 10 s timeout. All DSM parameters go in a form-encoded POST body, never in the URL.
- Never log the password, OTP code, `sid` or `did`, and never log raw settings-panel payloads.
- Auth errors 400, 401, 402, 403, 404, 406, 407, 408, 409 and 410 are never retried automatically. Session-lost codes 106, 107 and 119, plus 105, get exactly one re-login and one retry.
- The password and `did` go to the system keyring (service `com.jfms7s.synology`). They fall back to `GlobalSettings.fallback_secrets` only when the keyring fails.
- `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` and `cargo test` must pass at the end of every task.
- Commit messages follow Conventional Commits and end with the line `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

These are inputs the spec implies but doesn't spell out, most likely first. Each one has a pinning test in the task named.

1. **Host typed as a URL** (`https://nas.lan:5001/`, `nas.lan:5001`, `[fe80::1]`): the plugin must still build `https://nas.lan:5001`, not `https://https://nas.lan:5001/:5001`. Pinned in Task 4 (`Connection::base_url` tests).
2. **Password with URL-special or non-ASCII characters** (`p&ss=w+rd%ü`): it must reach DSM byte-for-byte. Pinned in Task 10 (session passes it through unchanged) and Task 9 (form encoding round-trip).
3. **2FA code pasted with spaces or a newline** (`"123 456\n"`): it must be sent as `123456`. Pinned in Task 15 (`otp_code_is_normalised`).
4. **DSM returning numbers as strings or strings as numbers** (sizes `"7680000000000"` vs `7680000000000`, percent `"43"` vs `43`): parsing must not fail. Pinned in Task 3 (`tolerates_numbers_and_strings`).
5. **A threshold cleared in the settings panel**: the panel must send `null` (not `""`). An empty string would make `openaction` fall back to *default* settings for the whole action, silently dropping the chosen disk. Pinned in Task 4 (`null_thresholds_deserialize`) and in the Task 15 panel code (`numberOrNull`).

## File Map

| File | Responsibility | Task |
|---|---|---|
| `Cargo.toml`, `rustfmt.toml`, `.gitignore`, `LICENSE`, `build.mjs`, `.github/workflows/{ci,release}.yml` | Scaffolding, packaging, CI | 1 |
| `scripts/capture-fixtures.sh`, `tests/fixtures/real/*.json` | Record real DSM responses (redacted) | 2 |
| `src/dsm/mod.rs`, `src/dsm/error.rs`, `src/dsm/model.rs`, `tests/fixtures/*.json` | Error taxonomy; DSM JSON → domain types | 3 |
| `src/settings.rs`, `src/metric.rs`, `src/status.rs` | Persisted settings; metric and endpoint catalogue; connection status | 4 |
| `src/poller.rs` | Subscription-driven poller with backoff and pause | 5 |
| `src/format.rs` | Unit formatting (%, °C/°F, bytes, rates, uptime) | 6 |
| `src/metrics.rs` | Pure `read` / `rotate` / `target_options` for all 10 metrics | 7 |
| `src/dsm/tls.rs` | Pinning certificate verifier | 8 |
| `src/dsm/transport.rs`, `src/dsm/api.rs` | HTTP POST + envelope; API discovery | 9 |
| `src/dsm/session.rs`, `src/dsm/fake.rs` | Login, 2FA, device token, re-login; test fake | 10 |
| `src/secrets.rs` | Keyring store + in-memory test store | 11 |
| `src/services.rs` | Wires connection, secrets, session and pollers; status | 12 |
| `src/render/{mod,glyphs,key,dial}.rs`, `assets/layouts/metric.json` | Key SVG and dial feedback | 13 |
| `src/actions.rs`, `src/instances.rs`, `assets/manifest.json`, `assets/icons/*`, `scripts/render-icons.sh` | 10 actions, live instance render loops, manifest, icons | 14 |
| `src/inspector.rs`, `assets/propertyInspector/index.html` | Settings panel protocol + UI | 15 |
| `src/main.rs`, `README.md` | Wiring, global settings, logout; docs + smoke checklist | 16 |
| (none) | Manual smoke test on the real NAS, then release | 17 |

---
### Task 1: Project scaffolding

**Files:**
- Create: `Cargo.toml`, `rustfmt.toml`, `.gitignore`, `LICENSE`, `src/main.rs`, `build.mjs`, `.github/workflows/ci.yml`, `.github/workflows/release.yml`

**Interfaces:**
- Consumes: nothing
- Produces: a crate that builds, with every dependency later tasks use already declared. `src/main.rs` carries `#![allow(dead_code)]` until Task 16.

- [ ] **Step 1: Write `Cargo.toml`**

```toml
[package]
name = "opendeck-synology"
version = "0.1.0"
edition = "2024"
license = "MIT"
description = "OpenDeck plugin: live Synology DSM 7 status - CPU, RAM, temperatures, disks, volumes, storage pools, network, uptime and updates - on Stream Deck keys and dials"
repository = "https://github.com/jfms7s/opendeck-synology"

[dependencies]
openaction = "2.7"
tokio = { version = "1.48", features = ["rt-multi-thread", "macros", "time", "sync"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
async-trait = "0.1"
thiserror = "2"
dashmap = "6"
futures = "0.3"
log = "0.4"
simplelog = "0.12"
base64 = "0.22"
reqwest = { version = "0.13.5", default-features = false, features = ["rustls", "form"] }
rustls = { version = "0.23", default-features = false, features = ["aws_lc_rs", "std", "tls12"] }
rustls-native-certs = "0.8"
sha2 = "0.10"
keyring = { version = "3.6", default-features = false, features = ["async-secret-service", "tokio", "crypto-rust"] }
gethostname = "1"

[dev-dependencies]
tokio = { version = "1.48", features = ["test-util", "macros", "rt", "rt-multi-thread"] }
rcgen = "0.14"
```

- [ ] **Step 2: Write `rustfmt.toml`, `.gitignore`, `LICENSE`**

`rustfmt.toml`:
```toml
edition = "2024"
```

`.gitignore`:
```
/target
/dist
*.sdPlugin.zip
*.streamDeckPlugin
```

`LICENSE`: copy it from the author's other plugin.
```bash
cp /home/jfms7s/git/weather-opendeck/LICENSE LICENSE
```

- [ ] **Step 3: Write `src/main.rs`**

```rust
// Modules arrive task by task; this allow goes away once main wires
// everything together (Task 16).
#![allow(dead_code)]

fn main() {}
```

- [ ] **Step 4: Write `build.mjs`**

```js
#!/usr/bin/env node
// Assembles dist/<uuid>.sdPlugin/ from assets/ + a release binary for one target.
// Usage: node build.mjs <target-triple>
// Requires: cargo build --release --target <target-triple> already run for that triple.
import { cpSync, copyFileSync, mkdirSync, rmSync, existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

const UUID = "com.jfms7s.synology";
const BIN_NAME = "opendeck-synology";

const target = process.argv[2];
if (!target) {
	console.error("usage: node build.mjs <target-triple>");
	process.exit(1);
}

// Cargo.toml's version and manifest.json's "Version" have nothing keeping
// them in sync - catch drift here rather than ship a mismatched plugin.
const cargoToml = readFileSync("Cargo.toml", "utf8");
const cargoVersionMatch = cargoToml.match(/^version\s*=\s*"([^"]+)"/m);
if (!cargoVersionMatch) {
	console.error('could not find `version = "..."` in Cargo.toml');
	process.exit(1);
}
const cargoVersion = cargoVersionMatch[1];
const manifestVersion = JSON.parse(readFileSync("assets/manifest.json", "utf8")).Version;
if (cargoVersion !== manifestVersion) {
	console.error(
		`version mismatch: Cargo.toml is ${cargoVersion} but assets/manifest.json is ${manifestVersion} - bump them together`,
	);
	process.exit(1);
}

const binPath = join("target", target, "release", BIN_NAME);
if (!existsSync(binPath)) {
	console.error(`missing release binary: ${binPath} (run: cargo build --release --target ${target})`);
	process.exit(1);
}

const outDir = join("dist", `${UUID}.sdPlugin`);
rmSync(outDir, { recursive: true, force: true });
mkdirSync(outDir, { recursive: true });

cpSync("assets/manifest.json", join(outDir, "manifest.json"));
cpSync("assets/icons", join(outDir, "icons"), {
	recursive: true,
	// SVG sources are only inputs to scripts/render-icons.sh.
	filter: (src) => !src.includes(`${join("icons", "source")}`),
});
cpSync("assets/layouts", join(outDir, "layouts"), { recursive: true });
cpSync("assets/propertyInspector", join(outDir, "propertyInspector"), { recursive: true });
copyFileSync(binPath, join(outDir, `${BIN_NAME}-${target}`));

console.log(`built ${outDir} for ${target}`);
```

- [ ] **Step 5: Write the workflows**

`.github/workflows/ci.yml`:
```yaml
name: CI
on:
  push:
    branches: [master]
  pull_request:

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: rustfmt, clippy
      - run: cargo fmt --check
      - run: cargo clippy --all-targets -- -D warnings
      - run: cargo test
```

`.github/workflows/release.yml`:
```yaml
name: Release
on:
  release:
    types: [published]

jobs:
  build:
    permissions:
      contents: write
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo build --release --target x86_64-unknown-linux-gnu
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - run: node build.mjs x86_64-unknown-linux-gnu
      - name: Zip the plugin bundle
        run: |
          cd dist
          zip -r ../opendeck-synology.streamDeckPlugin com.jfms7s.synology.sdPlugin
      - uses: softprops/action-gh-release@v2
        with:
          files: opendeck-synology.streamDeckPlugin
```

- [ ] **Step 6: Verify that it builds and lints clean**

Run: `cargo build && cargo clippy --all-targets -- -D warnings && cargo test`
Expected: all three succeed (0 tests). If cargo reports an unknown `keyring` feature, run `cargo info keyring@3` and use the features it lists for the pure-Rust Secret Service backend on tokio: the async Secret Service backend, its tokio runtime flavour, and pure-Rust crypto. Don't use the `sync-secret-service` feature: it links libdbus through C.

- [ ] **Step 7: Commit**

```bash
git add Cargo.toml Cargo.lock rustfmt.toml .gitignore LICENSE src/main.rs build.mjs .github
git commit -m "chore: scaffold the opendeck-synology crate, packaging and CI

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: Capture real DSM responses as fixtures

This task needs the human: they run the script against their NAS and enter their password and 2FA code. The implementer writes the script, then **asks the user to run it**. If the user can't run it now, commit the script only; Task 3's recorded-fixture test skips missing files.

**Files:**
- Create: `scripts/capture-fixtures.sh`
- Create (by running it): `tests/fixtures/real/{api_info,utilization,system,storage,update}.json`

**Interfaces:**
- Consumes: nothing
- Produces: redacted `data` payloads of the five DSM calls, which Task 3 (`recorded_fixtures_parse`) and Task 9 (`recorded_api_info_parses`) read

- [ ] **Step 1: Write `scripts/capture-fixtures.sh`**

```bash
#!/usr/bin/env bash
# Records real DSM 7 responses as test fixtures in tests/fixtures/real/.
#
# Usage:   scripts/capture-fixtures.sh <host[:port]> <account>
# Env:     INSECURE=1 accepts a self-signed certificate for this one run.
#
# The password is read from the terminal and handed to curl on stdin, so
# it never appears in the process list. Serial numbers, MAC/IP addresses,
# UUIDs and hostnames are replaced with "REDACTED" before anything is written.
set -euo pipefail

host=${1:?usage: $0 <host[:port]> <account>}
account=${2:?usage: $0 <host[:port]> <account>}
[[ $host == *:* ]] || host="$host:5001"
base="https://$host/webapi"

curl_opts=(--silent --show-error --fail --max-time 15)
[[ ${INSECURE:-0} == 1 ]] && curl_opts+=(--insecure)

out="$(cd "$(dirname "$0")/.." && pwd)/tests/fixtures/real"
mkdir -p "$out"

read -rsp "DSM password for $account: " password
echo
read -rp "2FA code (leave empty if the account has no 2FA): " otp
otp=${otp//[[:space:]]/}

post() {
	local path=$1
	shift
	curl "${curl_opts[@]}" "$base/$path" "$@"
}

redact='walk(if type == "object" then with_entries(
  if (.key | test("serial|uuid|wwn|(^|_)(mac|ip|ipv6|hostname|server_name)(_|$)"; "i"))
  then .value = "REDACTED" else . end) else . end)'

apis="SYNO.API.Auth,SYNO.Core.System.Utilization,SYNO.Core.System,SYNO.Storage.CGI.Storage,SYNO.Core.Upgrade.Server"
post query.cgi --data-urlencode "api=SYNO.API.Info" --data-urlencode "version=1" \
	--data-urlencode "method=query" --data-urlencode "query=$apis" | jq '.data' >"$out/api_info.json"
echo "wrote $out/api_info.json"

login_args=(--data-urlencode "api=SYNO.API.Auth" --data-urlencode "version=6"
	--data-urlencode "method=login" --data-urlencode "account=$account"
	--data-urlencode "passwd@-" --data-urlencode "session=OpenDeckCapture"
	--data-urlencode "format=sid")
[[ -n $otp ]] && login_args+=(--data-urlencode "otp_code=$otp")

login=$(printf %s "$password" | post entry.cgi "${login_args[@]}")
unset password
if ! sid=$(jq -er '.data.sid' <<<"$login"); then
	echo "login failed: $(jq -c '.error' <<<"$login")" >&2
	exit 1
fi

logout() {
	post entry.cgi --data-urlencode "api=SYNO.API.Auth" --data-urlencode "version=6" \
		--data-urlencode "method=logout" --data-urlencode "session=OpenDeckCapture" \
		--data-urlencode "_sid=$sid" >/dev/null || true
}
trap logout EXIT

capture() {
	local name=$1 api=$2 version=$3 method=$4 resp
	resp=$(post entry.cgi --data-urlencode "api=$api" --data-urlencode "version=$version" \
		--data-urlencode "method=$method" --data-urlencode "_sid=$sid")
	if jq -e '.success' <<<"$resp" >/dev/null; then
		jq "$redact | .data" <<<"$resp" >"$out/$name.json"
		echo "wrote $out/$name.json"
	else
		echo "$api $method failed: $(jq -c '.error' <<<"$resp")" >&2
	fi
}

capture utilization SYNO.Core.System.Utilization 1 get
capture system SYNO.Core.System 1 info
capture storage SYNO.Storage.CGI.Storage 1 load_info
capture update SYNO.Core.Upgrade.Server 1 check
```

```bash
chmod +x scripts/capture-fixtures.sh
bash -n scripts/capture-fixtures.sh
```
Expected: `bash -n` prints nothing (syntax OK).

- [ ] **Step 2: Ask the user to run it**

Tell the user exactly this, then wait:

> Please run this against your NAS. It asks for your password and a 2FA code, doesn't create a trusted device, and logs out when it's done:
> ```bash
> INSECURE=1 scripts/capture-fixtures.sh <your-nas-host> <your-dsm-account>
> ```
> Drop `INSECURE=1` if your NAS has a publicly trusted certificate. While you're there, please also note the "Load average" shown in DSM → Resource Monitor → CPU, or the output of `cat /proc/loadavg` over SSH. Task 3 checks the load-average scale against it.

- [ ] **Step 3: Review the captured files**

Run: `ls tests/fixtures/real && grep -rIl -iE '"(serial|mac|uuid)"\s*:\s*"[^R]' tests/fixtures/real || echo "redaction ok"`
Expected: the five files are listed, followed by `redaction ok`. Open each file and look for anything personal that the regex missed (volume descriptions, share names, user names). Replace any with `"REDACTED"` by hand before committing.

Record in the task report which of these DSM field names are present in the real files, since Task 3 depends on them:
- `utilization.json`: `cpu.user_load`, `cpu.system_load`, `cpu.other_load`, `cpu.1min_load`, `memory.real_usage`, `memory.total_real`, `memory.avail_real`, `network[].device|rx|tx`
- `system.json`: `sys_temp`, `up_time` (and its format), `firmware_ver`
- `storage.json`: `disks[].id|longName|temp|smart_status|status`, `volumes[].id|vol_path|status|size.total|size.used`, `storagePools[].id|status|device_type|progress.percent`
- `update.json`: `update.available` or top-level `available`, and `version`

- [ ] **Step 4: Commit**

```bash
git add scripts/capture-fixtures.sh tests/fixtures/real
git commit -m "test: add a script to capture redacted DSM responses as fixtures

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---
### Task 3: DSM error taxonomy and response parsing

**Files:**
- Create: `src/dsm/mod.rs`, `src/dsm/error.rs`, `src/dsm/model.rs`
- Create: `tests/fixtures/utilization.json`, `tests/fixtures/system.json`, `tests/fixtures/storage.json`, `tests/fixtures/storage_degraded.json`, `tests/fixtures/update.json`
- Modify: `src/main.rs` (add `mod dsm;`)

**Interfaces:**
- Consumes: the recorded fixtures from Task 2 (optional; the test skips missing files)
- Produces:
  - `dsm::error::AuthError` (`Copy`): `NeedOtp`, `BadCredentials`, `BadOtp`, `Blocked`, `PasswordExpired`, `OtpEnforced`, `Disabled`; `AuthError::from_login_code(i64) -> Option<AuthError>`
  - `dsm::error::DsmError` (`Clone + PartialEq`): `NotConfigured`, `Transport(String)`, `CertificateNotTrusted { fingerprint: String }`, `CertificateChanged { fingerprint: String }`, `Auth(AuthError)`, `Permission { api: String }`, `Api { api: String, code: i64 }`, `Parse { api: String, detail: String }`; `DsmError::needs_user(&self) -> bool`
  - `dsm::model::{Cpu, Memory, NetIf, Utilization, SystemInfo, Disk, Volume, Pool, Storage, UpdateStatus, Payload}` (fields below)
  - `dsm::model::{parse_utilization, parse_system_info, parse_storage, parse_update}`, each `fn(&serde_json::Value) -> Result<T, String>`

- [ ] **Step 1: Write the hand-made fixtures**

These mirror DSM 7's response shapes. `storage_degraded.json` covers the failure states a healthy NAS can't produce.

`tests/fixtures/utilization.json`:
```json
{
  "cpu": { "15min_load": 35, "1min_load": 42, "5min_load": 38, "device": "System", "other_load": 1, "system_load": 7, "user_load": 29 },
  "memory": { "avail_real": 10485760, "total_real": 16777216, "real_usage": 37, "memory_size": 16777216 },
  "network": [
    { "device": "total", "rx": 13002342, "tx": 524288 },
    { "device": "eth0", "rx": 13000000, "tx": 520000 },
    { "device": "eth1", "rx": 2342, "tx": 4288 }
  ],
  "time": 1790000000
}
```

`tests/fixtures/system.json`:
```json
{ "model": "DS920+", "firmware_ver": "DSM 7.2.2-72806 Update 3", "sys_temp": 48, "sys_tempwarn": false, "up_time": "293:05:11", "serial": "REDACTED" }
```

`tests/fixtures/storage.json`:
```json
{
  "disks": [
    { "id": "sata1", "name": "Drive 1", "longName": "Drive 1", "temp": 38, "smart_status": "normal", "status": "normal" },
    { "id": "sata2", "name": "Drive 2", "longName": "Drive 2", "temp": 44, "smart_status": "normal", "status": "normal" },
    { "id": "nvme0n1", "name": "M.2 Drive 1", "longName": "M.2 Drive 1", "temp": 0, "smart_status": "normal", "status": "normal" }
  ],
  "volumes": [
    { "id": "volume_1", "vol_path": "/volume1", "status": "normal", "size": { "total": "7680000000000", "used": "5452800000000" } }
  ],
  "storagePools": [
    { "id": "reuse_1", "device_type": "shr_with_1_disk_protect", "status": "normal", "progress": { "percent": "-1", "step": "none" } }
  ]
}
```

`tests/fixtures/storage_degraded.json`:
```json
{
  "disks": [
    { "id": "sata1", "longName": "Drive 1", "temp": 38, "smart_status": "normal", "status": "normal" },
    { "id": "sata2", "longName": "Drive 2", "temp": 61, "smart_status": "failing", "status": "crashed" }
  ],
  "volumes": [
    { "id": "volume_1", "vol_path": "/volume1", "status": "degraded", "size": { "total": "1000", "used": "950" } }
  ],
  "storagePools": [
    { "id": "reuse_1", "device_type": "raid_1", "status": "degraded", "progress": { "percent": "-1" } },
    { "id": "reuse_2", "device_type": "raid_5", "status": "repairing", "progress": { "percent": "43", "step": "resync" } }
  ]
}
```

`tests/fixtures/update.json`:
```json
{ "update": { "available": true, "version": "7.2.2-72806 Update 4", "type": "nano" } }
```

- [ ] **Step 2: Write `src/dsm/mod.rs` and `src/dsm/error.rs` with their tests**

`src/dsm/mod.rs`:
```rust
//! Everything that speaks DSM: the wire, the login session, and the typed
//! responses.

pub mod error;
pub mod model;
```

`src/dsm/error.rs`:
```rust
//! What can go wrong talking to DSM, sorted by what the plugin should do
//! about it: retry later (transport, API), or stop and wait for the user
//! (credentials, certificate, missing settings).

use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum AuthError {
    #[error("2FA code required")]
    NeedOtp,
    #[error("wrong account or password")]
    BadCredentials,
    #[error("wrong 2FA code")]
    BadOtp,
    #[error("IP blocked by DSM")]
    Blocked,
    #[error("password expired")]
    PasswordExpired,
    #[error("2FA is enforced but not set up for this account")]
    OtpEnforced,
    #[error("account disabled or not allowed to sign in")]
    Disabled,
}

impl AuthError {
    /// Maps a `SYNO.API.Auth` login error code; `None` for codes that are not
    /// about the credentials (those surface as `DsmError::Api`).
    pub fn from_login_code(code: i64) -> Option<Self> {
        Some(match code {
            400 => Self::BadCredentials,
            401 | 402 => Self::Disabled,
            403 => Self::NeedOtp,
            404 => Self::BadOtp,
            406 => Self::OtpEnforced,
            407 => Self::Blocked,
            408..=410 => Self::PasswordExpired,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Error)]
pub enum DsmError {
    #[error("connection settings are incomplete")]
    NotConfigured,
    #[error("unreachable: {0}")]
    Transport(String),
    #[error("certificate not trusted (SHA-256 {fingerprint})")]
    CertificateNotTrusted { fingerprint: String },
    #[error("certificate changed (SHA-256 {fingerprint})")]
    CertificateChanged { fingerprint: String },
    #[error("{0}")]
    Auth(#[from] AuthError),
    #[error("no permission for {api}")]
    Permission { api: String },
    #[error("{api} failed with DSM error {code}")]
    Api { api: String, code: i64 },
    #[error("unexpected response from {api}: {detail}")]
    Parse { api: String, detail: String },
}

impl DsmError {
    /// Errors only the user can fix. Pollers stop retrying on these:
    /// retrying a wrong password is exactly what trips DSM's auto-block.
    pub fn needs_user(&self) -> bool {
        matches!(
            self,
            Self::NotConfigured
                | Self::Auth(_)
                | Self::CertificateNotTrusted { .. }
                | Self::CertificateChanged { .. }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_login_codes() {
        assert_eq!(AuthError::from_login_code(400), Some(AuthError::BadCredentials));
        assert_eq!(AuthError::from_login_code(402), Some(AuthError::Disabled));
        assert_eq!(AuthError::from_login_code(403), Some(AuthError::NeedOtp));
        assert_eq!(AuthError::from_login_code(404), Some(AuthError::BadOtp));
        assert_eq!(AuthError::from_login_code(406), Some(AuthError::OtpEnforced));
        assert_eq!(AuthError::from_login_code(407), Some(AuthError::Blocked));
        assert_eq!(AuthError::from_login_code(409), Some(AuthError::PasswordExpired));
        assert_eq!(AuthError::from_login_code(119), None);
    }

    #[test]
    fn only_user_fixable_errors_pause_polling() {
        assert!(DsmError::Auth(AuthError::BadCredentials).needs_user());
        assert!(DsmError::NotConfigured.needs_user());
        assert!(DsmError::CertificateChanged { fingerprint: "ab".into() }.needs_user());
        assert!(!DsmError::Transport("timeout".into()).needs_user());
        assert!(!DsmError::Permission { api: "x".into() }.needs_user());
        assert!(!DsmError::Api { api: "x".into(), code: 117 }.needs_user());
    }
}
```

Add `mod dsm;` to `src/main.rs` below the `#![allow(dead_code)]` line.

- [ ] **Step 3: Write the failing model tests**

Create `src/dsm/model.rs` containing only the test module for now:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn fixture(name: &str) -> Value {
        let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap()
    }

    #[test]
    fn parses_utilization() {
        let u = parse_utilization(&fixture("utilization.json")).unwrap();
        assert_eq!(u.cpu.total_pct, 37.0);
        assert_eq!(u.cpu.load1, 0.42);
        assert_eq!(u.cpu.load15, 0.35);
        assert_eq!(u.memory.used_pct, 37.0);
        assert_eq!(u.memory.total_bytes, 17_179_869_184);
        assert_eq!(u.memory.used_bytes, 6_442_450_944);
        assert_eq!(u.network.len(), 3);
        assert_eq!(u.network[0], NetIf { device: "total".into(), rx: 13_002_342, tx: 524_288 });
    }

    #[test]
    fn utilization_without_cpu_is_an_error() {
        assert!(parse_utilization(&json!({ "memory": {} })).is_err());
    }

    #[test]
    fn parses_system_info() {
        let s = parse_system_info(&fixture("system.json")).unwrap();
        assert_eq!(s.sys_temp_c, Some(48.0));
        assert_eq!(s.uptime_secs, Some(293 * 3600 + 5 * 60 + 11));
        assert_eq!(s.firmware.as_deref(), Some("DSM 7.2.2-72806 Update 3"));
    }

    #[test]
    fn missing_or_zero_system_temperature_is_none() {
        assert_eq!(parse_system_info(&json!({ "up_time": "1:00:00" })).unwrap().sys_temp_c, None);
        assert_eq!(parse_system_info(&json!({ "sys_temp": 0 })).unwrap().sys_temp_c, None);
    }

    #[test]
    fn uptime_accepts_plain_seconds() {
        let s = parse_system_info(&json!({ "up_time": 90061 })).unwrap();
        assert_eq!(s.uptime_secs, Some(90061));
    }

    #[test]
    fn parses_healthy_storage() {
        let s = parse_storage(&fixture("storage.json")).unwrap();
        assert_eq!(s.disks.len(), 3);
        assert_eq!(s.disks[0].id, "sata1");
        assert_eq!(s.disks[0].name, "Drive 1");
        assert_eq!(s.disks[1].temp_c, Some(44.0));
        assert_eq!(s.disks[2].temp_c, None, "NVMe without a sensor reports 0");
        assert_eq!(s.volumes[0].name, "Volume 1");
        assert_eq!(s.volumes[0].total_bytes, 7_680_000_000_000);
        assert_eq!(s.volumes[0].used_bytes, 5_452_800_000_000);
        assert_eq!(s.pools[0].name, "Pool 1");
        assert_eq!(s.pools[0].status, "normal");
        assert_eq!(s.pools[0].raid, "shr_with_1_disk_protect");
        assert_eq!(s.pools[0].progress_pct, None, "-1 means no operation running");
    }

    #[test]
    fn parses_degraded_storage() {
        let s = parse_storage(&fixture("storage_degraded.json")).unwrap();
        assert_eq!(s.disks[1].smart_status, "failing");
        assert_eq!(s.disks[1].status, "crashed");
        assert_eq!(s.pools[0].status, "degraded");
        assert_eq!(s.pools[1].status, "repairing");
        assert_eq!(s.pools[1].progress_pct, Some(43.0));
    }

    #[test]
    fn tolerates_numbers_and_strings() {
        let s = parse_storage(&json!({
            "disks": [{ "id": "sata1", "temp": "41", "smart_status": "Normal", "status": "normal" }],
            "volumes": [{ "id": "volume_2", "status": "normal", "size": { "total": 2000, "used": "500" } }],
            "storagePools": [{ "id": "reuse_3", "status": "expanding", "progress": { "percent": 12 } }]
        }))
        .unwrap();
        assert_eq!(s.disks[0].temp_c, Some(41.0));
        assert_eq!(s.disks[0].smart_status, "normal", "statuses are lower-cased");
        assert_eq!(s.disks[0].name, "sata1", "falls back to the id");
        assert_eq!(s.volumes[0].total_bytes, 2000);
        assert_eq!(s.volumes[0].used_bytes, 500);
        assert_eq!(s.pools[0].progress_pct, Some(12.0));
    }

    #[test]
    fn entries_without_an_id_are_skipped() {
        let s = parse_storage(&json!({ "disks": [{ "temp": 30 }], "volumes": [], "storagePools": [] })).unwrap();
        assert!(s.disks.is_empty());
    }

    #[test]
    fn parses_update_in_both_shapes() {
        let u = parse_update(&fixture("update.json")).unwrap();
        assert_eq!(u, UpdateStatus { available: true, version: Some("7.2.2-72806 Update 4".into()) });
        let none = parse_update(&json!({ "available": false, "version": "7.2.2" })).unwrap();
        assert_eq!(none, UpdateStatus { available: false, version: None });
        assert!(parse_update(&json!({})).is_err());
    }

    /// Real responses from the author's NAS (Task 2). Skips files that
    /// were not captured, so CI and fresh clones still pass.
    #[test]
    fn recorded_fixtures_parse() {
        type Check = fn(&Value) -> Result<(), String>;
        let checks: [(&str, Check); 4] = [
            ("utilization.json", |v| parse_utilization(v).map(drop)),
            ("system.json", |v| parse_system_info(v).map(drop)),
            ("storage.json", |v| parse_storage(v).map(drop)),
            ("update.json", |v| parse_update(v).map(drop)),
        ];
        for (name, check) in checks {
            let path = format!("{}/tests/fixtures/real/{name}", env!("CARGO_MANIFEST_DIR"));
            let Ok(raw) = std::fs::read_to_string(&path) else {
                eprintln!("skipping {name}: not recorded");
                continue;
            };
            let value: Value = serde_json::from_str(&raw).unwrap();
            check(&value).unwrap_or_else(|e| panic!("{name}: {e}"));
        }
    }
}
```

Add `pub mod model;` to `src/dsm/mod.rs` if it isn't already there.

- [ ] **Step 4: Run the tests to verify they fail**

Run: `cargo test dsm::model`
Expected: compile errors, e.g. "cannot find function `parse_utilization`".

- [ ] **Step 5: Implement the model above the test module**

Put this at the top of `src/dsm/model.rs`:

```rust
//! DSM responses turned into plain domain types. DSM is loose with types
//! (sizes arrive as strings, percentages as strings or numbers), so parsing
//! walks `serde_json::Value` with small tolerant helpers rather than strict
//! serde structs: a firmware update that turns a number into a string must
//! not blank every key.

use serde_json::Value;

#[derive(Debug, Clone, PartialEq)]
pub struct Cpu {
    /// user + system + other load, 0-100.
    pub total_pct: f64,
    pub load1: f64,
    pub load5: f64,
    pub load15: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Memory {
    pub used_pct: f64,
    pub total_bytes: u64,
    pub used_bytes: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct NetIf {
    /// `total` for the sum over all interfaces, else e.g. `eth0`.
    pub device: String,
    /// Bytes per second.
    pub rx: u64,
    pub tx: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Utilization {
    pub cpu: Cpu,
    pub memory: Memory,
    pub network: Vec<NetIf>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SystemInfo {
    pub sys_temp_c: Option<f64>,
    pub uptime_secs: Option<u64>,
    pub firmware: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Disk {
    /// Stable id such as `sata1` - survives drives being reordered.
    pub id: String,
    pub name: String,
    pub temp_c: Option<f64>,
    pub smart_status: String,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Volume {
    pub id: String,
    pub name: String,
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Pool {
    pub id: String,
    pub name: String,
    pub status: String,
    pub raid: String,
    /// Progress of a running repair/expansion/check, 0-100.
    pub progress_pct: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Storage {
    pub disks: Vec<Disk>,
    pub volumes: Vec<Volume>,
    pub pools: Vec<Pool>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct UpdateStatus {
    pub available: bool,
    pub version: Option<String>,
}

/// One poll result of any of the four endpoints.
#[derive(Debug, Clone, PartialEq)]
pub enum Payload {
    Utilization(Utilization),
    SystemInfo(SystemInfo),
    Storage(Storage),
    Update(UpdateStatus),
}

fn num(v: &Value) -> Option<f64> {
    match v {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

fn text(v: &Value) -> Option<String> {
    v.as_str().map(str::to_string).filter(|s| !s.is_empty())
}

fn lower(v: &Value) -> String {
    text(v).unwrap_or_else(|| "unknown".into()).to_lowercase()
}

fn req_num(v: &Value, field: &str) -> Result<f64, String> {
    num(&v[field]).ok_or_else(|| format!("missing number `{field}`"))
}

/// "volume_1" -> "Volume 1"; an id without a trailing number stays as is.
fn numbered(prefix: &str, id: &str) -> String {
    match id.rsplit('_').next() {
        Some(n) if !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()) => {
            format!("{prefix} {n}")
        }
        _ => id.to_string(),
    }
}

pub fn parse_utilization(data: &Value) -> Result<Utilization, String> {
    let c = &data["cpu"];
    // DSM reports load averages multiplied by 100 (a load of 0.42 arrives as 42).
    let cpu = Cpu {
        total_pct: req_num(c, "user_load")?
            + req_num(c, "system_load")?
            + num(&c["other_load"]).unwrap_or(0.0),
        load1: req_num(c, "1min_load")? / 100.0,
        load5: req_num(c, "5min_load")? / 100.0,
        load15: req_num(c, "15min_load")? / 100.0,
    };
    let m = &data["memory"];
    // Memory sizes are in KiB.
    let total_kib = req_num(m, "total_real")?;
    let avail_kib = req_num(m, "avail_real")?;
    let memory = Memory {
        used_pct: req_num(m, "real_usage")?,
        total_bytes: (total_kib * 1024.0) as u64,
        used_bytes: ((total_kib - avail_kib).max(0.0) * 1024.0) as u64,
    };
    let network = data["network"]
        .as_array()
        .map(|list| {
            list.iter()
                .filter_map(|n| {
                    Some(NetIf {
                        device: text(&n["device"])?,
                        rx: num(&n["rx"]).unwrap_or(0.0) as u64,
                        tx: num(&n["tx"]).unwrap_or(0.0) as u64,
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(Utilization { cpu, memory, network })
}

/// `up_time` is "hours:minutes:seconds" with unbounded hours (e.g.
/// "293:05:11"); some firmware sends plain seconds instead.
fn parse_uptime(v: &Value) -> Option<u64> {
    if let Some(n) = v.as_u64() {
        return Some(n);
    }
    let parts: Vec<u64> = v
        .as_str()?
        .split(':')
        .map(|p| p.trim().parse().ok())
        .collect::<Option<_>>()?;
    match parts.as_slice() {
        [h, m, s] => Some(h * 3600 + m * 60 + s),
        [s] => Some(*s),
        _ => None,
    }
}

pub fn parse_system_info(data: &Value) -> Result<SystemInfo, String> {
    if !data.is_object() {
        return Err("expected an object".into());
    }
    Ok(SystemInfo {
        // Models without a system sensor report 0 or omit the field.
        sys_temp_c: num(&data["sys_temp"]).filter(|t| *t > 0.0),
        uptime_secs: parse_uptime(&data["up_time"]),
        firmware: text(&data["firmware_ver"]),
    })
}

pub fn parse_storage(data: &Value) -> Result<Storage, String> {
    if !data.is_object() {
        return Err("expected an object".into());
    }
    let list = |key: &str| data[key].as_array().cloned().unwrap_or_default();
    let disks = list("disks")
        .iter()
        .filter_map(|d| {
            let id = text(&d["id"])?;
            Some(Disk {
                name: text(&d["longName"])
                    .or_else(|| text(&d["name"]))
                    .unwrap_or_else(|| id.clone()),
                // Drives without a sensor (some NVMe) report 0.
                temp_c: num(&d["temp"]).filter(|t| *t > 0.0),
                smart_status: lower(&d["smart_status"]),
                status: lower(&d["status"]),
                id,
            })
        })
        .collect();
    let volumes = list("volumes")
        .iter()
        .filter_map(|v| {
            let id = text(&v["id"])?;
            Some(Volume {
                name: numbered("Volume", &id),
                total_bytes: num(&v["size"]["total"])? as u64,
                used_bytes: num(&v["size"]["used"])? as u64,
                status: lower(&v["status"]),
                id,
            })
        })
        .collect();
    let pools = list("storagePools")
        .iter()
        .filter_map(|p| {
            let id = text(&p["id"])?;
            Some(Pool {
                name: numbered("Pool", &id),
                status: lower(&p["status"]),
                raid: text(&p["device_type"])
                    .or_else(|| text(&p["raidType"]))
                    .unwrap_or_default(),
                // -1 means "no operation running".
                progress_pct: num(&p["progress"]["percent"]).filter(|x| (0.0..=100.0).contains(x)),
                id,
            })
        })
        .collect();
    Ok(Storage { disks, volumes, pools })
}

/// Most firmware nests the answer under `update`; accept both shapes.
pub fn parse_update(data: &Value) -> Result<UpdateStatus, String> {
    let u = if data["update"].is_object() { &data["update"] } else { data };
    let available = u["available"].as_bool().ok_or("missing `available`")?;
    Ok(UpdateStatus {
        available,
        version: if available { text(&u["version"]) } else { None },
    })
}
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cargo test dsm::`
Expected: all tests in `dsm::error` and `dsm::model` PASS.

- [ ] **Step 7: Reconcile with the recorded fixtures**

If `tests/fixtures/real/` exists and `recorded_fixtures_parse` fails, or the real files use different field names than listed in the Task 2 report, change the parsers (not the hand-made fixtures) until the test passes. Then check the scale against the load average the user noted in Task 2. If DSM's `1min_load` already equals the real load (e.g. `0.42`, not `42`), remove the `/ 100.0` divisions and change the fixture expectation to match. Record any change in the commit message.

Run: `cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected: PASS, no warnings.

- [ ] **Step 8: Commit**

```bash
git add src/dsm src/main.rs tests/fixtures
git commit -m "feat: parse DSM utilization, system, storage and update responses

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---
### Task 4: Settings, metric catalogue and connection status

**Files:**
- Create: `src/settings.rs`, `src/metric.rs`, `src/status.rs`
- Modify: `src/main.rs` (add `mod metric; mod settings; mod status;`)

**Interfaces:**
- Consumes: `dsm::error::{AuthError, DsmError}` (Task 3)
- Produces:
  - `settings::Connection { host: String, port: u16, https: bool, account: String, pinned_sha256: Option<String> }`, with `host() -> String`, `base_url() -> String`, `is_complete() -> bool` and `secret_scope() -> String`. Default: port 5001, https true.
  - `settings::TempUnit { Celsius (default), Fahrenheit }`, serialized in lowercase
  - `settings::FallbackSecrets { password: Option<String>, did: Option<String> }`
  - `settings::GlobalSettings { connection: Connection, temp_unit: TempUnit, fallback_secrets: Option<FallbackSecrets> }`
  - `settings::{CpuView { Total, Load1, Load5, Load15 }, Direction { In, Out, Combined }, Amount { Percent, Used }}`, all serialized in lowercase, each defaulting to its first variant
  - `settings::ActionSettings { interval_secs: Option<u64>, warn: Option<f64>, crit: Option<f64>, target: Option<String>, cpu_view: CpuView, direction: Direction, amount: Amount }`
  - `metric::Endpoint { Utilization, SystemInfo, Storage, Update }`, with `ALL` and `default_interval() -> Duration`
  - `metric::Metric { Cpu, Ram, Network, SysTemp, Uptime, DiskTemp, DiskHealth, Volume, Pool, Update }`, with `ALL`, `endpoint()`, `const fn uuid() -> &'static str`, `title() -> &'static str` and `default_thresholds() -> Option<(f64, f64)>`
  - `status::ConnStatus { NotConfigured, Connecting (default), Connected { account: String }, Auth(AuthError), Certificate { fingerprint: String, changed: bool }, Unreachable(String) }`, with `from_error(&DsmError) -> Option<ConnStatus>`, `describe() -> String` and `kind() -> &'static str`

- [ ] **Step 1: Write the failing tests**

`src/settings.rs` (tests only for now):
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn conn(host: &str, port: u16, https: bool) -> Connection {
        Connection { host: host.into(), port, https, account: "jf".into(), pinned_sha256: None }
    }

    #[test]
    fn base_url_accepts_whatever_the_user_typed() {
        assert_eq!(conn("nas.lan", 5001, true).base_url(), "https://nas.lan:5001");
        assert_eq!(conn("https://nas.lan:5001/", 5001, true).base_url(), "https://nas.lan:5001");
        assert_eq!(conn("  NAS.lan  ", 5000, false).base_url(), "http://NAS.lan:5000");
        assert_eq!(conn("http://192.168.1.10/webman", 5001, true).base_url(), "https://192.168.1.10:5001");
        assert_eq!(conn("[fe80::1]:5001", 5001, true).base_url(), "https://[fe80::1]:5001");
        assert_eq!(conn("fe80::1", 5001, true).base_url(), "https://[fe80::1]:5001");
    }

    #[test]
    fn completeness_needs_host_account_and_port() {
        assert!(conn("nas.lan", 5001, true).is_complete());
        assert!(!conn("  ", 5001, true).is_complete());
        assert!(!conn("nas.lan", 0, true).is_complete());
        let mut c = conn("nas.lan", 5001, true);
        c.account = " ".into();
        assert!(!c.is_complete());
    }

    #[test]
    fn secret_scope_uses_normalised_host_and_account() {
        let mut c = conn("https://nas.lan:5001/", 5001, true);
        c.account = " jf ".into();
        assert_eq!(c.secret_scope(), "jf@nas.lan");
    }

    #[test]
    fn global_settings_default_from_empty_object() {
        let g: GlobalSettings = serde_json::from_value(json!({})).unwrap();
        assert_eq!(g.connection.port, 5001);
        assert!(g.connection.https);
        assert_eq!(g.temp_unit, TempUnit::Celsius);
        let out = serde_json::to_value(&g).unwrap();
        assert!(out.get("fallback_secrets").is_none(), "no secrets key unless needed");
    }

    #[test]
    fn null_thresholds_deserialize() {
        let s: ActionSettings =
            serde_json::from_value(json!({ "warn": null, "crit": 90, "target": "sata2" })).unwrap();
        assert_eq!(s.warn, None);
        assert_eq!(s.crit, Some(90.0));
        assert_eq!(s.target.as_deref(), Some("sata2"));
    }

    #[test]
    fn view_enums_use_lowercase_names() {
        let s: ActionSettings = serde_json::from_value(
            json!({ "cpu_view": "load5", "direction": "combined", "amount": "used" }),
        )
        .unwrap();
        assert_eq!((s.cpu_view, s.direction, s.amount), (CpuView::Load5, Direction::Combined, Amount::Used));
        assert_eq!(ActionSettings::default().cpu_view, CpuView::Total);
    }
}
```

`src/metric.rs` (tests only for now):
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn uuids_are_unique_and_namespaced() {
        let uuids: HashSet<_> = Metric::ALL.iter().map(|m| m.uuid()).collect();
        assert_eq!(uuids.len(), 10);
        assert!(uuids.iter().all(|u| u.starts_with("com.jfms7s.synology.")));
    }

    #[test]
    fn storage_metrics_share_one_endpoint() {
        for m in [Metric::DiskTemp, Metric::DiskHealth, Metric::Volume, Metric::Pool] {
            assert_eq!(m.endpoint(), Endpoint::Storage);
        }
        assert_eq!(Metric::Cpu.endpoint(), Endpoint::Utilization);
        assert_eq!(Metric::Uptime.endpoint(), Endpoint::SystemInfo);
        assert_eq!(Metric::Update.endpoint(), Endpoint::Update);
    }

    #[test]
    fn default_intervals_match_the_spec() {
        assert_eq!(Endpoint::Utilization.default_interval().as_secs(), 5);
        assert_eq!(Endpoint::SystemInfo.default_interval().as_secs(), 30);
        assert_eq!(Endpoint::Storage.default_interval().as_secs(), 60);
        assert_eq!(Endpoint::Update.default_interval().as_secs(), 6 * 3600);
    }

    #[test]
    fn only_numeric_metrics_have_default_thresholds() {
        assert_eq!(Metric::Cpu.default_thresholds(), Some((70.0, 90.0)));
        assert_eq!(Metric::DiskTemp.default_thresholds(), Some((50.0, 60.0)));
        assert_eq!(Metric::Network.default_thresholds(), None);
        assert_eq!(Metric::Pool.default_thresholds(), None);
    }
}
```

`src/status.rs` (tests only for now):
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_connection_level_errors() {
        assert_eq!(
            ConnStatus::from_error(&DsmError::Auth(AuthError::NeedOtp)),
            Some(ConnStatus::Auth(AuthError::NeedOtp))
        );
        assert_eq!(
            ConnStatus::from_error(&DsmError::CertificateChanged { fingerprint: "ab".into() }),
            Some(ConnStatus::Certificate { fingerprint: "ab".into(), changed: true })
        );
        assert_eq!(
            ConnStatus::from_error(&DsmError::Transport("timed out".into())),
            Some(ConnStatus::Unreachable("timed out".into()))
        );
    }

    #[test]
    fn endpoint_level_errors_leave_the_connection_alone() {
        assert_eq!(ConnStatus::from_error(&DsmError::Permission { api: "x".into() }), None);
        assert_eq!(ConnStatus::from_error(&DsmError::Api { api: "x".into(), code: 117 }), None);
    }

    #[test]
    fn describes_states_for_the_settings_panel() {
        assert_eq!(ConnStatus::Connected { account: "jf".into() }.describe(), "Connected as jf");
        assert_eq!(ConnStatus::Auth(AuthError::NeedOtp).describe(), "Needs 2FA code");
        assert_eq!(ConnStatus::Auth(AuthError::NeedOtp).kind(), "needOtp");
        assert!(ConnStatus::Auth(AuthError::Blocked).describe().contains("blocked"));
    }
}
```

Add the modules to `src/main.rs`:
```rust
mod dsm;
mod metric;
mod settings;
mod status;
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test settings:: metric:: status::`
Expected: compile errors for the missing types.

- [ ] **Step 3: Implement `src/settings.rs` above its tests**

```rust
//! Persisted configuration. `GlobalSettings` is OpenDeck's plugin-wide
//! settings file - plain JSON on disk, so it carries no secrets unless the
//! system keyring is unavailable. `ActionSettings` belongs to one key or dial.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Connection {
    /// As typed by the user; see `host()` for the normalised form.
    pub host: String,
    pub port: u16,
    pub https: bool,
    pub account: String,
    /// SHA-256 of the NAS's leaf certificate (lowercase hex) once trusted.
    pub pinned_sha256: Option<String>,
}

impl Default for Connection {
    fn default() -> Self {
        Self { host: String::new(), port: 5001, https: true, account: String::new(), pinned_sha256: None }
    }
}

impl Connection {
    /// The bare host from whatever was typed: drops a scheme, a path and a
    /// `:port` suffix ("https://nas.lan:5001/" -> "nas.lan"). The port always
    /// comes from the separate port field.
    pub fn host(&self) -> String {
        let s = self.host.trim();
        let s = s.split_once("://").map_or(s, |(_, rest)| rest);
        let s = s.split('/').next().unwrap_or("");
        if s.starts_with('[') {
            return s.split_once(']').map_or_else(|| s.to_string(), |(h, _)| format!("{h}]"));
        }
        match s.rsplit_once(':') {
            Some((h, port)) if !h.contains(':') && port.chars().all(|c| c.is_ascii_digit()) => {
                h.to_string()
            }
            _ => s.to_string(),
        }
    }

    pub fn base_url(&self) -> String {
        let scheme = if self.https { "https" } else { "http" };
        let host = self.host();
        // A bare IPv6 literal needs brackets in a URL.
        let host = if host.contains(':') && !host.starts_with('[') { format!("[{host}]") } else { host };
        format!("{scheme}://{host}:{}", self.port)
    }

    pub fn is_complete(&self) -> bool {
        !self.host().is_empty() && !self.account.trim().is_empty() && self.port != 0
    }

    /// Namespaces keyring entries, so another NAS or account never reuses a
    /// password or device token.
    pub fn secret_scope(&self) -> String {
        format!("{}@{}", self.account.trim(), self.host())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TempUnit {
    #[default]
    Celsius,
    Fahrenheit,
}

/// Secrets kept in the settings file only when no system keyring works.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct FallbackSecrets {
    pub password: Option<String>,
    pub did: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct GlobalSettings {
    pub connection: Connection,
    pub temp_unit: TempUnit,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fallback_secrets: Option<FallbackSecrets>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CpuView {
    #[default]
    Total,
    Load1,
    Load5,
    Load15,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    #[default]
    In,
    Out,
    Combined,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Amount {
    #[default]
    Percent,
    Used,
}

/// One key's or dial's settings. A single struct serves all ten actions;
/// each reads only the fields that apply to it.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ActionSettings {
    /// Refresh interval override in seconds (clamped to at least 2).
    pub interval_secs: Option<u64>,
    pub warn: Option<f64>,
    pub crit: Option<f64>,
    /// Disk, volume or pool id, or a network interface. `None` selects the
    /// aggregate: hottest disk, worst disk, all interfaces, first volume/pool.
    pub target: Option<String>,
    pub cpu_view: CpuView,
    pub direction: Direction,
    pub amount: Amount,
}
```

- [ ] **Step 4: Implement `src/metric.rs` above its tests**

```rust
//! The catalogue: which metrics exist, which DSM endpoint feeds each, and
//! their defaults.

use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Endpoint {
    Utilization,
    SystemInfo,
    Storage,
    Update,
}

impl Endpoint {
    pub const ALL: [Endpoint; 4] = [Self::Utilization, Self::SystemInfo, Self::Storage, Self::Update];

    pub fn default_interval(self) -> Duration {
        Duration::from_secs(match self {
            Self::Utilization => 5,
            Self::SystemInfo => 30,
            Self::Storage => 60,
            Self::Update => 6 * 3600,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Metric {
    Cpu,
    Ram,
    Network,
    SysTemp,
    Uptime,
    DiskTemp,
    DiskHealth,
    Volume,
    Pool,
    Update,
}

impl Metric {
    pub const ALL: [Metric; 10] = [
        Self::Cpu,
        Self::Ram,
        Self::Network,
        Self::SysTemp,
        Self::Uptime,
        Self::DiskTemp,
        Self::DiskHealth,
        Self::Volume,
        Self::Pool,
        Self::Update,
    ];

    pub fn endpoint(self) -> Endpoint {
        match self {
            Self::Cpu | Self::Ram | Self::Network => Endpoint::Utilization,
            Self::SysTemp | Self::Uptime => Endpoint::SystemInfo,
            Self::DiskTemp | Self::DiskHealth | Self::Volume | Self::Pool => Endpoint::Storage,
            Self::Update => Endpoint::Update,
        }
    }

    /// `const` so each action type can use it as its `Action::UUID`.
    pub const fn uuid(self) -> &'static str {
        match self {
            Self::Cpu => "com.jfms7s.synology.cpu",
            Self::Ram => "com.jfms7s.synology.ram",
            Self::Network => "com.jfms7s.synology.network",
            Self::SysTemp => "com.jfms7s.synology.systemp",
            Self::Uptime => "com.jfms7s.synology.uptime",
            Self::DiskTemp => "com.jfms7s.synology.disktemp",
            Self::DiskHealth => "com.jfms7s.synology.diskhealth",
            Self::Volume => "com.jfms7s.synology.volume",
            Self::Pool => "com.jfms7s.synology.pool",
            Self::Update => "com.jfms7s.synology.update",
        }
    }

    /// Short heading drawn on keys and dials.
    pub fn title(self) -> &'static str {
        match self {
            Self::Cpu => "CPU",
            Self::Ram => "RAM",
            Self::Network => "Network",
            Self::SysTemp => "System",
            Self::Uptime => "Uptime",
            Self::DiskTemp => "Disk",
            Self::DiskHealth => "Health",
            Self::Volume => "Volume",
            Self::Pool => "Pool",
            Self::Update => "DSM",
        }
    }

    /// (warn, crit) for numeric metrics. Temperatures are in °C. `None` =
    /// state-based, or no thresholds unless the user sets some (network).
    pub fn default_thresholds(self) -> Option<(f64, f64)> {
        match self {
            Self::Cpu => Some((70.0, 90.0)),
            Self::Ram => Some((80.0, 95.0)),
            Self::SysTemp => Some((60.0, 70.0)),
            Self::DiskTemp => Some((50.0, 60.0)),
            Self::Volume => Some((80.0, 90.0)),
            _ => None,
        }
    }
}
```

- [ ] **Step 5: Implement `src/status.rs` above its tests**

```rust
//! The connection's state as the user should see it - in the settings
//! panel's status line, and on keys when nothing can be shown.

use crate::dsm::error::{AuthError, DsmError};

#[derive(Debug, Clone, PartialEq, Default)]
pub enum ConnStatus {
    NotConfigured,
    #[default]
    Connecting,
    Connected { account: String },
    Auth(AuthError),
    Certificate { fingerprint: String, changed: bool },
    Unreachable(String),
}

impl ConnStatus {
    /// The status an error implies, or `None` when the error is about one
    /// endpoint (permission, API error) rather than the connection.
    pub fn from_error(e: &DsmError) -> Option<Self> {
        Some(match e {
            DsmError::NotConfigured => Self::NotConfigured,
            DsmError::Transport(msg) => Self::Unreachable(msg.clone()),
            DsmError::Auth(a) => Self::Auth(*a),
            DsmError::CertificateNotTrusted { fingerprint } => {
                Self::Certificate { fingerprint: fingerprint.clone(), changed: false }
            }
            DsmError::CertificateChanged { fingerprint } => {
                Self::Certificate { fingerprint: fingerprint.clone(), changed: true }
            }
            DsmError::Permission { .. } | DsmError::Api { .. } | DsmError::Parse { .. } => return None,
        })
    }

    pub fn describe(&self) -> String {
        match self {
            Self::NotConfigured => "Not configured".into(),
            Self::Connecting => "Connecting…".into(),
            Self::Connected { account } => format!("Connected as {account}"),
            Self::Auth(AuthError::NeedOtp) => "Needs 2FA code".into(),
            Self::Auth(AuthError::BadCredentials) => "Wrong account or password".into(),
            Self::Auth(AuthError::BadOtp) => "Wrong 2FA code - try again".into(),
            Self::Auth(AuthError::Blocked) => {
                "IP blocked by DSM - unblock it in Control Panel › Security › Protection".into()
            }
            Self::Auth(other) => format!("Sign-in failed: {other}"),
            Self::Certificate { changed: false, .. } => "Certificate not trusted".into(),
            Self::Certificate { changed: true, .. } => "Certificate changed".into(),
            Self::Unreachable(msg) => format!("Unreachable: {msg}"),
        }
    }

    /// Machine-readable tag the settings panel switches on.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::NotConfigured => "notConfigured",
            Self::Connecting => "connecting",
            Self::Connected { .. } => "connected",
            Self::Auth(AuthError::NeedOtp | AuthError::BadOtp) => "needOtp",
            Self::Auth(_) => "auth",
            Self::Certificate { .. } => "certificate",
            Self::Unreachable(_) => "unreachable",
        }
    }
}
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cargo test settings:: metric:: status::`
Expected: PASS.

Run: `cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected: clean.

- [ ] **Step 7: Commit**

```bash
git add src/settings.rs src/metric.rs src/status.rs src/main.rs
git commit -m "feat: add settings, metric catalogue and connection status types

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---
### Task 5: Subscription-driven poller

**Files:**
- Create: `src/poller.rs`
- Modify: `src/main.rs` (add `mod poller;`)

**Interfaces:**
- Consumes: `dsm::error::DsmError` (Task 3)
- Produces:
  - `poller::PollState<T> { value: Option<Arc<T>>, error: Option<DsmError>, failures: u32 }`, with manual `Clone` and `Default` (neither needs `T: Clone`)
  - `poller::Fetch<T> = Arc<dyn Fn() -> BoxFuture<'static, Result<T, DsmError>> + Send + Sync>`
  - `poller::Poller<T>`:
    - `new(default_interval: Duration) -> Self`
    - `subscribe(&self, id: &str, interval: Option<Duration>) -> watch::Receiver<PollState<T>>`
    - `unsubscribe(&self, id: &str)`
    - `set_fetch(&self, fetch: Option<Fetch<T>>)`
    - `refresh_now(&self)`
    - `effective_interval(&self) -> Option<Duration>`
    - `latest(&self) -> PollState<T>`
  - `poller::{MIN_INTERVAL, MAX_BACKOFF}` and `poller::backoff(interval: Duration, failures: u32) -> Duration`

- [ ] **Step 1: Write the failing tests**

Create `src/poller.rs` with only the tests:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::dsm::error::AuthError;
    use std::sync::atomic::{AtomicU32, Ordering::SeqCst};

    fn counting(n: Arc<AtomicU32>) -> Fetch<u32> {
        Arc::new(move || {
            let n = n.clone();
            Box::pin(async move { Ok(n.fetch_add(1, SeqCst) + 1) })
        })
    }

    fn failing(n: Arc<AtomicU32>, err: DsmError) -> Fetch<u32> {
        Arc::new(move || {
            let (n, err) = (n.clone(), err.clone());
            Box::pin(async move {
                n.fetch_add(1, SeqCst);
                Err(err)
            })
        })
    }

    const S: fn(u64) -> Duration = Duration::from_secs;

    #[test]
    fn backoff_doubles_per_failure_up_to_five_minutes() {
        assert_eq!(backoff(S(5), 0), S(5));
        assert_eq!(backoff(S(5), 1), S(10));
        assert_eq!(backoff(S(5), 2), S(20));
        assert_eq!(backoff(S(5), 10), S(300));
        assert_eq!(backoff(S(6 * 3600), 3), S(6 * 3600), "never below the interval");
    }

    #[tokio::test(start_paused = true)]
    async fn polls_at_the_shortest_subscriber_interval() {
        let p = Poller::new(S(60));
        let n = Arc::new(AtomicU32::new(0));
        p.set_fetch(Some(counting(n.clone())));
        let _a = p.subscribe("a", Some(S(10)));
        tokio::time::sleep(Duration::from_millis(1)).await;
        assert_eq!(n.load(SeqCst), 1, "polls as soon as someone subscribes");
        let _b = p.subscribe("b", Some(S(5)));
        assert_eq!(p.effective_interval(), Some(S(5)));
        tokio::time::sleep(Duration::from_millis(20_500)).await;
        // One immediate poll for the new subscriber, then every 5 s.
        assert_eq!(n.load(SeqCst), 6);
    }

    #[tokio::test(start_paused = true)]
    async fn stops_when_the_last_subscriber_leaves() {
        let p = Poller::new(S(5));
        let n = Arc::new(AtomicU32::new(0));
        p.set_fetch(Some(counting(n.clone())));
        let _a = p.subscribe("a", None);
        tokio::time::sleep(Duration::from_millis(1)).await;
        p.unsubscribe("a");
        tokio::time::sleep(S(60)).await;
        assert_eq!(n.load(SeqCst), 1);
        assert_eq!(p.effective_interval(), None);
        // ...and starts again for a new subscriber.
        let _b = p.subscribe("b", None);
        tokio::time::sleep(Duration::from_millis(1)).await;
        assert_eq!(n.load(SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn clamps_intervals_to_the_minimum() {
        let p: Poller<u32> = Poller::new(S(5));
        let _a = p.subscribe("a", Some(Duration::from_millis(100)));
        assert_eq!(p.effective_interval(), Some(MIN_INTERVAL));
    }

    #[tokio::test(start_paused = true)]
    async fn broadcasts_values_and_keeps_them_through_failures() {
        let p = Poller::new(S(5));
        let n = Arc::new(AtomicU32::new(0));
        p.set_fetch(Some(counting(n.clone())));
        let mut rx = p.subscribe("a", None);
        rx.changed().await.unwrap();
        assert_eq!(rx.borrow().value.as_deref(), Some(&1));

        p.set_fetch(Some(failing(n.clone(), DsmError::Transport("down".into()))));
        // set_fetch clears the old connection's value...
        assert!(p.latest().value.is_none());
        p.set_fetch(Some(counting(Arc::new(AtomicU32::new(41)))));
        tokio::time::sleep(Duration::from_millis(1)).await;
        assert_eq!(p.latest().value.as_deref(), Some(&42));
        // ...but a failure on the same connection keeps it.
        let fail = failing(n.clone(), DsmError::Transport("down".into()));
        p.inner.registry.lock().unwrap().fetch = Some(fail);
        p.refresh_now();
        tokio::time::sleep(Duration::from_millis(1)).await;
        let st = p.latest();
        assert_eq!(st.value.as_deref(), Some(&42));
        assert_eq!(st.failures, 1);
        assert_eq!(st.error, Some(DsmError::Transport("down".into())));
    }

    #[tokio::test(start_paused = true)]
    async fn backs_off_after_transport_errors() {
        let p = Poller::new(S(5));
        let n = Arc::new(AtomicU32::new(0));
        p.set_fetch(Some(failing(n.clone(), DsmError::Transport("down".into()))));
        let _a = p.subscribe("a", None);
        // Polls at t=0, then waits 10 s (1 failure), then 20 s (2 failures).
        tokio::time::sleep(Duration::from_millis(29_000)).await;
        assert_eq!(n.load(SeqCst), 2);
        tokio::time::sleep(Duration::from_millis(2_000)).await;
        assert_eq!(n.load(SeqCst), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn pauses_on_errors_the_user_must_fix_until_woken() {
        let p = Poller::new(S(5));
        let n = Arc::new(AtomicU32::new(0));
        p.set_fetch(Some(failing(n.clone(), DsmError::Auth(AuthError::BadCredentials))));
        let _a = p.subscribe("a", None);
        tokio::time::sleep(S(3600)).await;
        assert_eq!(n.load(SeqCst), 1, "no retry of a wrong password");
        p.refresh_now();
        tokio::time::sleep(Duration::from_millis(1)).await;
        assert_eq!(n.load(SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn without_a_fetch_it_idles_until_one_is_set() {
        let p = Poller::new(S(5));
        let mut rx = p.subscribe("a", None);
        tokio::time::sleep(S(60)).await;
        assert!(rx.borrow_and_update().value.is_none());
        let n = Arc::new(AtomicU32::new(0));
        p.set_fetch(Some(counting(n.clone())));
        tokio::time::sleep(Duration::from_millis(1)).await;
        assert_eq!(n.load(SeqCst), 1);
    }
}
```

Add `mod poller;` to `src/main.rs`.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test poller::`
Expected: compile errors (`Poller`, `backoff` etc. not found).

- [ ] **Step 3: Implement the poller above the tests**

```rust
//! One background poller per DSM endpoint. It runs only while some key or
//! dial is subscribed, at the shortest interval any of them asked for, and
//! broadcasts every result on a `watch` channel - so ten keys reading the
//! same endpoint cost one request per refresh.

use crate::dsm::error::DsmError;
use futures::future::BoxFuture;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{Notify, watch};

pub const MIN_INTERVAL: Duration = Duration::from_secs(2);
pub const MAX_BACKOFF: Duration = Duration::from_secs(300);

#[derive(Debug)]
pub struct PollState<T> {
    /// Last good value - kept through failures, so keys go stale, not blank.
    pub value: Option<Arc<T>>,
    /// The latest attempt's error; cleared by the next success.
    pub error: Option<DsmError>,
    /// Consecutive failed attempts.
    pub failures: u32,
}

impl<T> Default for PollState<T> {
    fn default() -> Self {
        Self { value: None, error: None, failures: 0 }
    }
}

impl<T> Clone for PollState<T> {
    fn clone(&self) -> Self {
        Self { value: self.value.clone(), error: self.error.clone(), failures: self.failures }
    }
}

pub type Fetch<T> = Arc<dyn Fn() -> BoxFuture<'static, Result<T, DsmError>> + Send + Sync>;

/// How long to wait after `failures` consecutive failures: the interval
/// doubled per failure, capped at `MAX_BACKOFF` (but never below the interval).
pub fn backoff(interval: Duration, failures: u32) -> Duration {
    let factor = 2u32.saturating_pow(failures.min(16));
    interval.saturating_mul(factor).min(MAX_BACKOFF.max(interval))
}

struct Registry<T> {
    subscribers: HashMap<String, Duration>,
    fetch: Option<Fetch<T>>,
    /// Bumped by `set_fetch`, so a request started on the old connection
    /// can't overwrite the new connection's state when it finishes.
    generation: u64,
    running: bool,
}

struct Inner<T> {
    default_interval: Duration,
    registry: Mutex<Registry<T>>,
    tx: watch::Sender<PollState<T>>,
    wake: Notify,
}

pub struct Poller<T> {
    inner: Arc<Inner<T>>,
}

impl<T: Send + Sync + 'static> Poller<T> {
    pub fn new(default_interval: Duration) -> Self {
        let (tx, _) = watch::channel(PollState::default());
        Self {
            inner: Arc::new(Inner {
                default_interval,
                registry: Mutex::new(Registry {
                    subscribers: HashMap::new(),
                    fetch: None,
                    generation: 0,
                    running: false,
                }),
                tx,
                wake: Notify::new(),
            }),
        }
    }

    /// Registers (or re-registers) a subscriber, starting the poll loop if
    /// it isn't running. `interval: None` means the endpoint's default.
    /// Also triggers an immediate poll, so a new key gets fresh data.
    pub fn subscribe(&self, id: &str, interval: Option<Duration>) -> watch::Receiver<PollState<T>> {
        let interval = interval.unwrap_or(self.inner.default_interval).max(MIN_INTERVAL);
        let rx = self.inner.tx.subscribe();
        let start = {
            let mut reg = self.inner.registry.lock().unwrap();
            reg.subscribers.insert(id.to_string(), interval);
            !std::mem::replace(&mut reg.running, true)
        };
        if start {
            tokio::spawn(run(self.inner.clone()));
        } else {
            self.inner.wake.notify_one();
        }
        rx
    }

    pub fn unsubscribe(&self, id: &str) {
        let running = {
            let mut reg = self.inner.registry.lock().unwrap();
            reg.subscribers.remove(id);
            reg.running
        };
        // Let the loop re-plan: longer interval, or exit if nobody is left.
        self.wake_if(running);
    }

    /// Swaps what a poll does - a new session after the settings changed, or
    /// `None` while unconfigured. Clears the last value: it belonged to the
    /// old connection.
    pub fn set_fetch(&self, fetch: Option<Fetch<T>>) {
        let running = {
            let mut reg = self.inner.registry.lock().unwrap();
            reg.fetch = fetch;
            reg.generation += 1;
            reg.running
        };
        self.inner.tx.send_replace(PollState::default());
        self.wake_if(running);
    }

    /// Polls now instead of waiting out the interval or a pause.
    pub fn refresh_now(&self) {
        let running = self.inner.registry.lock().unwrap().running;
        self.wake_if(running);
    }

    /// `Notify` stores a permit when nobody is waiting; waking a loop that
    /// isn't running would leave one behind and cause a spurious extra poll
    /// right after the next start.
    fn wake_if(&self, running: bool) {
        if running {
            self.inner.wake.notify_one();
        }
    }

    pub fn effective_interval(&self) -> Option<Duration> {
        self.inner.registry.lock().unwrap().subscribers.values().min().copied()
    }

    pub fn latest(&self) -> PollState<T> {
        self.inner.tx.borrow().clone()
    }
}

async fn run<T: Send + Sync + 'static>(inner: Arc<Inner<T>>) {
    loop {
        let (interval, fetch, generation) = {
            let mut reg = inner.registry.lock().unwrap();
            let Some(interval) = reg.subscribers.values().min().copied() else {
                reg.running = false;
                return;
            };
            (interval, reg.fetch.clone(), reg.generation)
        };
        // `None` = wait until woken (unconfigured, or an error only the user can fix).
        let wait = match fetch {
            None => None,
            Some(fetch) => {
                let result = fetch().await;
                if inner.registry.lock().unwrap().generation != generation {
                    continue; // the connection changed mid-request; discard
                }
                let mut next = inner.tx.borrow().clone();
                let wait = match result {
                    Ok(v) => {
                        next = PollState { value: Some(Arc::new(v)), error: None, failures: 0 };
                        Some(interval)
                    }
                    Err(e) => {
                        next.failures += 1;
                        let wait = (!e.needs_user()).then(|| backoff(interval, next.failures));
                        next.error = Some(e);
                        wait
                    }
                };
                inner.tx.send_replace(next);
                wait
            }
        };
        match wait {
            Some(d) => {
                tokio::select! {
                    _ = tokio::time::sleep(d) => {}
                    _ = inner.wake.notified() => {}
                }
            }
            None => inner.wake.notified().await,
        }
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test poller::`
Expected: PASS (8 tests).

If `polls_at_the_shortest_subscriber_interval` counts 5 or 7, don't loosen the assertion. Print `tokio::time::Instant::now()` in the fetch to see the actual poll times, then fix the loop's wake/sleep logic.

Run: `cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add src/poller.rs src/main.rs
git commit -m "feat: add a subscription-driven poller with backoff and pause

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---
### Task 6: Unit formatting

**Files:**
- Create: `src/format.rs`
- Modify: `src/main.rs` (add `mod format;`)

**Interfaces:**
- Consumes: `settings::TempUnit` (Task 4)
- Produces, all in `format::`:
  - `percent(f64) -> String`
  - `temperature(celsius: f64, TempUnit) -> String`
  - `bytes(u64) -> String`
  - `used_of_total(used: u64, total: u64) -> String`
  - `rate(bytes_per_sec: u64) -> String`
  - `uptime(secs: u64) -> String`
  - `load(f64) -> String`

- [ ] **Step 1: Write the failing tests**

`src/format.rs` (tests only):
```rust
#[cfg(test)]
mod tests {
    use super::*;

    const GIB: u64 = 1024 * 1024 * 1024;
    const TIB: u64 = 1024 * GIB;

    #[test]
    fn percentages_round_to_whole_numbers() {
        assert_eq!(percent(37.4), "37%");
        assert_eq!(percent(99.6), "100%");
    }

    #[test]
    fn temperatures_follow_the_unit() {
        assert_eq!(temperature(48.0, TempUnit::Celsius), "48°C");
        assert_eq!(temperature(48.0, TempUnit::Fahrenheit), "118°F");
    }

    #[test]
    fn bytes_use_binary_multiples_with_dsm_labels() {
        assert_eq!(bytes(512), "512 B");
        assert_eq!(bytes(6 * GIB), "6.0 GB");
        assert_eq!(bytes(16 * GIB), "16 GB");
        assert_eq!(bytes(7 * TIB + TIB / 2), "7.5 TB");
    }

    #[test]
    fn used_of_total_shares_the_totals_unit() {
        assert_eq!(used_of_total(6 * GIB, 16 * GIB), "6.0/16 GB");
        assert_eq!(used_of_total(5_452_800_000_000, 7_680_000_000_000), "5.0/7.0 TB");
        assert_eq!(used_of_total(512 * 1024 * 1024, 2 * TIB), "0.0/2.0 TB");
    }

    #[test]
    fn rates_scale_per_second() {
        assert_eq!(rate(900), "900 B/s");
        assert_eq!(rate(524_288), "512 KB/s");
        assert_eq!(rate(13_002_342), "12.4 MB/s");
        assert_eq!(rate(150 * 1024 * 1024), "150 MB/s");
    }

    #[test]
    fn uptime_shows_the_two_largest_units() {
        assert_eq!(uptime(1_055_111), "12d 5h");
        assert_eq!(uptime(4 * 3600 + 12 * 60), "4h 12m");
        assert_eq!(uptime(59), "0m");
    }

    #[test]
    fn load_averages_have_two_decimals() {
        assert_eq!(load(0.42), "0.42");
        assert_eq!(load(3.0), "3.00");
    }
}
```

Add `mod format;` to `src/main.rs`.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test format::`
Expected: compile errors.

- [ ] **Step 3: Implement above the tests**

```rust
//! How numbers look on a key. Sizes use binary multiples but DSM's labels
//! (a GiB shows as "GB"), so the plugin agrees with DSM's own UI.

use crate::settings::TempUnit;

const UNITS: [&str; 6] = ["B", "KB", "MB", "GB", "TB", "PB"];

pub fn percent(v: f64) -> String {
    format!("{v:.0}%")
}

pub fn temperature(celsius: f64, unit: TempUnit) -> String {
    match unit {
        TempUnit::Celsius => format!("{celsius:.0}°C"),
        TempUnit::Fahrenheit => format!("{:.0}°F", celsius * 9.0 / 5.0 + 32.0),
    }
}

/// (value scaled into the largest unit where it is >= 1, that unit's index)
fn scale(n: u64) -> (f64, usize) {
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    (v, i)
}

/// One decimal below 10 ("6.0"), none above ("16"); bytes never get decimals.
fn number(v: f64, unit: usize) -> String {
    if unit == 0 || v >= 10.0 { format!("{v:.0}") } else { format!("{v:.1}") }
}

pub fn bytes(n: u64) -> String {
    let (v, i) = scale(n);
    format!("{} {}", number(v, i), UNITS[i])
}

/// "5.0/7.0 TB": both numbers in the unit of the total.
pub fn used_of_total(used: u64, total: u64) -> String {
    let (t, i) = scale(total);
    let u = used as f64 / 1024f64.powi(i as i32);
    format!("{}/{} {}", number(u, i), number(t, i), UNITS[i])
}

pub fn rate(bytes_per_sec: u64) -> String {
    let (v, i) = scale(bytes_per_sec);
    let n = if i == 0 || v >= 100.0 { format!("{v:.0}") } else { format!("{v:.1}") };
    format!("{n} {}/s", UNITS[i])
}

pub fn uptime(secs: u64) -> String {
    let (d, h, m) = (secs / 86_400, secs % 86_400 / 3600, secs % 3600 / 60);
    if d > 0 {
        format!("{d}d {h}h")
    } else if h > 0 {
        format!("{h}h {m}m")
    } else {
        format!("{m}m")
    }
}

pub fn load(v: f64) -> String {
    format!("{v:.2}")
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test format::`
Expected: PASS.

`rate(524_288)` is exactly 512.0 KB, which is ≥ 100, so it gets no decimals: `512 KB/s`. `uptime(1_055_111)` is 12 days 5 h 5 m.

Run: `cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add src/format.rs src/main.rs
git commit -m "feat: add unit formatting for percentages, sizes, rates and uptime

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---
### Task 7: Metric readings, dial rotation and target options

**Files:**
- Create: `src/metrics.rs`
- Modify: `src/main.rs` (add `mod metrics;`)

**Interfaces:**
- Consumes:
  - `dsm::model::*` (Task 3)
  - `dsm::error::{AuthError, DsmError}` (Task 3)
  - `metric::Metric` (Task 4)
  - `settings::{ActionSettings, Amount, CpuView, Direction, TempUnit}` (Task 4)
  - `status::ConnStatus` (Task 4)
  - `poller::PollState` (Task 5)
  - `format::*` (Task 6)
- Produces:
  - `metrics::Level { Normal, Warn, Crit, Stale, Error }` (`Ord`, where `Normal < Warn < Crit`)
  - `metrics::Reading { title: &'static str, value: String, subject: String, level: Level, bar: Option<f64>, pager: Option<(usize, usize)> }`
  - `metrics::Context<'a> { status: &'a ConnStatus, unit: TempUnit }`
  - `metrics::read(Metric, &PollState<Payload>, &ActionSettings, &Context) -> Reading`
  - `metrics::rotate(Metric, &mut ActionSettings, Option<&Payload>, ticks: i16)`
  - `metrics::target_options(Metric, &Payload) -> Vec<(Option<String>, String)>`
  - `metrics::STALE_AFTER: u32 = 3`

- [ ] **Step 1: Write the failing tests**

`src/metrics.rs` (tests only):
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::dsm::model::{parse_storage, parse_system_info, parse_update, parse_utilization};
    use serde_json::{Value, json};
    use std::sync::Arc;

    fn fixture(name: &str) -> Value {
        let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }
    fn util() -> Payload {
        Payload::Utilization(parse_utilization(&fixture("utilization.json")).unwrap())
    }
    fn storage(name: &str) -> Payload {
        Payload::Storage(parse_storage(&fixture(name)).unwrap())
    }
    fn system(v: Value) -> Payload {
        Payload::SystemInfo(parse_system_info(&v).unwrap())
    }
    fn state(p: Payload) -> PollState<Payload> {
        PollState { value: Some(Arc::new(p)), error: None, failures: 0 }
    }
    fn connected() -> ConnStatus {
        ConnStatus::Connected { account: "jf".into() }
    }
    fn read_as(metric: Metric, p: Payload, view: &ActionSettings) -> Reading {
        let status = connected();
        read(metric, &state(p), view, &Context { status: &status, unit: TempUnit::Celsius })
    }
    fn view() -> ActionSettings {
        ActionSettings::default()
    }

    #[test]
    fn cpu_total_and_load_views() {
        let r = read_as(Metric::Cpu, util(), &view());
        assert_eq!((r.title, r.value.as_str(), r.subject.as_str()), ("CPU", "37%", "Usage"));
        assert_eq!((r.level, r.bar, r.pager), (Level::Normal, Some(37.0), Some((0, 4))));
        let v = ActionSettings { cpu_view: CpuView::Load1, ..view() };
        let r = read_as(Metric::Cpu, util(), &v);
        assert_eq!((r.value.as_str(), r.subject.as_str(), r.pager), ("0.42", "Load 1 min", Some((1, 4))));
    }

    #[test]
    fn thresholds_default_per_metric_and_can_be_overridden() {
        assert_eq!(read_as(Metric::Cpu, util(), &view()).level, Level::Normal);
        let v = ActionSettings { warn: Some(30.0), ..view() };
        assert_eq!(read_as(Metric::Cpu, util(), &v).level, Level::Warn);
        let v = ActionSettings { warn: Some(10.0), crit: Some(35.0), ..view() };
        assert_eq!(read_as(Metric::Cpu, util(), &v).level, Level::Crit);
    }

    #[test]
    fn ram_shows_percent_or_used_of_total() {
        let r = read_as(Metric::Ram, util(), &view());
        assert_eq!((r.value.as_str(), r.pager), ("37%", Some((0, 2))));
        let v = ActionSettings { amount: Amount::Used, ..view() };
        assert_eq!(read_as(Metric::Ram, util(), &v).value, "6.0/16 GB");
    }

    #[test]
    fn network_directions_and_interfaces() {
        let r = read_as(Metric::Network, util(), &view());
        assert_eq!((r.value.as_str(), r.subject.as_str()), ("↓12.4 MB/s", "All interfaces"));
        assert_eq!((r.level, r.bar), (Level::Normal, None), "no thresholds unless set");
        let v = ActionSettings { direction: Direction::Out, target: Some("eth1".into()), ..view() };
        let r = read_as(Metric::Network, util(), &v);
        assert_eq!((r.value.as_str(), r.subject.as_str(), r.pager), ("↑4.2 KB/s", "eth1", Some((1, 3))));
        let v = ActionSettings { target: Some("bond0".into()), ..view() };
        let r = read_as(Metric::Network, util(), &v);
        assert_eq!((r.value.as_str(), r.level), ("Missing", Level::Crit));
    }

    #[test]
    fn network_thresholds_are_in_megabytes_per_second() {
        let v = ActionSettings { warn: Some(5.0), crit: Some(10.0), ..view() };
        let r = read_as(Metric::Network, util(), &v);
        assert_eq!((r.level, r.bar), (Level::Crit, Some(100.0)));
    }

    #[test]
    fn system_temperature_and_missing_sensor() {
        let r = read_as(Metric::SysTemp, system(fixture("system.json")), &view());
        assert_eq!((r.value.as_str(), r.level), ("48°C", Level::Normal));
        let r = read_as(Metric::SysTemp, system(json!({ "up_time": "1:0:0" })), &view());
        assert_eq!((r.value.as_str(), r.level), ("N/A", Level::Normal));
        let status = connected();
        let ctx = Context { status: &status, unit: TempUnit::Fahrenheit };
        let r = read(Metric::SysTemp, &state(system(fixture("system.json"))), &view(), &ctx);
        assert_eq!(r.value, "118°F");
    }

    #[test]
    fn uptime_is_formatted() {
        let r = read_as(Metric::Uptime, system(fixture("system.json")), &view());
        assert_eq!(r.value, "12d 5h");
    }

    #[test]
    fn disk_temperature_hottest_specific_missing_and_sensorless() {
        let r = read_as(Metric::DiskTemp, storage("storage.json"), &view());
        assert_eq!((r.value.as_str(), r.subject.as_str(), r.pager), ("44°C", "Hottest: Drive 2", Some((3, 4))));
        let v = ActionSettings { target: Some("sata1".into()), ..view() };
        let r = read_as(Metric::DiskTemp, storage("storage.json"), &v);
        assert_eq!((r.value.as_str(), r.subject.as_str(), r.pager), ("38°C", "Drive 1", Some((0, 4))));
        let v = ActionSettings { target: Some("nvme0n1".into()), ..view() };
        assert_eq!(read_as(Metric::DiskTemp, storage("storage.json"), &v).value, "N/A");
        let v = ActionSettings { target: Some("sata9".into()), ..view() };
        let r = read_as(Metric::DiskTemp, storage("storage.json"), &v);
        assert_eq!((r.value.as_str(), r.level), ("Missing", Level::Crit));
        let r = read_as(Metric::DiskTemp, storage("storage_degraded.json"), &view());
        assert_eq!(r.level, Level::Crit, "61 °C is over the 60 °C default");
    }

    #[test]
    fn disk_health_worst_and_specific() {
        let r = read_as(Metric::DiskHealth, storage("storage.json"), &view());
        assert_eq!((r.value.as_str(), r.subject.as_str(), r.level), ("OK", "All 3 disks", Level::Normal));
        let r = read_as(Metric::DiskHealth, storage("storage_degraded.json"), &view());
        assert_eq!((r.value.as_str(), r.subject.as_str(), r.level), ("Failing", "Drive 2", Level::Crit));
        let v = ActionSettings { target: Some("sata1".into()), ..view() };
        assert_eq!(read_as(Metric::DiskHealth, storage("storage_degraded.json"), &v).value, "OK");
    }

    #[test]
    fn volume_percent_used_and_status() {
        let r = read_as(Metric::Volume, storage("storage.json"), &view());
        assert_eq!((r.value.as_str(), r.subject.as_str(), r.level), ("71%", "Volume 1", Level::Normal));
        let v = ActionSettings { amount: Amount::Used, ..view() };
        assert_eq!(read_as(Metric::Volume, storage("storage.json"), &v).value, "5.0/7.0 TB");
        let Payload::Storage(mut s) = storage("storage.json") else { unreachable!() };
        s.volumes[0].status = "degraded".into();
        assert_eq!(read_as(Metric::Volume, Payload::Storage(s), &view()).level, Level::Crit);
    }

    #[test]
    fn pool_states() {
        let r = read_as(Metric::Pool, storage("storage.json"), &view());
        assert_eq!((r.value.as_str(), r.subject.as_str(), r.level, r.bar), ("Normal", "Pool 1", Level::Normal, None));
        let r = read_as(Metric::Pool, storage("storage_degraded.json"), &view());
        assert_eq!((r.value.as_str(), r.level, r.pager), ("Degraded", Level::Crit, Some((0, 2))));
        let v = ActionSettings { target: Some("reuse_2".into()), ..view() };
        let r = read_as(Metric::Pool, storage("storage_degraded.json"), &v);
        assert_eq!((r.value.as_str(), r.level, r.bar), ("Rebuild 43%", Level::Warn, Some(43.0)));
    }

    #[test]
    fn update_available_or_not() {
        let p = Payload::Update(parse_update(&fixture("update.json")).unwrap());
        let r = read_as(Metric::Update, p, &view());
        assert_eq!((r.value.as_str(), r.subject.as_str(), r.level), ("Update", "7.2.2-72806 Update 4", Level::Warn));
        let p = Payload::Update(parse_update(&json!({ "available": false })).unwrap());
        assert_eq!(read_as(Metric::Update, p, &view()).value, "Up to date");
    }

    #[test]
    fn goes_stale_after_three_failures_but_keeps_the_value() {
        let status = connected();
        let ctx = Context { status: &status, unit: TempUnit::Celsius };
        let mut st = state(util());
        st.error = Some(DsmError::Transport("down".into()));
        st.failures = 2;
        assert_eq!(read(Metric::Cpu, &st, &view(), &ctx).level, Level::Normal);
        st.failures = STALE_AFTER;
        let r = read(Metric::Cpu, &st, &view(), &ctx);
        assert_eq!((r.value.as_str(), r.level), ("37%", Level::Stale));
    }

    #[test]
    fn placeholders_and_errors_without_a_value() {
        let status = connected();
        let ctx = Context { status: &status, unit: TempUnit::Celsius };
        let r = read(Metric::Cpu, &PollState::default(), &view(), &ctx);
        assert_eq!(r.value, "…");
        let st = PollState { value: None, error: Some(DsmError::Transport("x".into())), failures: 1 };
        assert_eq!(read(Metric::Cpu, &st, &view(), &ctx).value, "Offline");
        let st = PollState { value: None, error: Some(DsmError::Permission { api: "x".into() }), failures: 1 };
        let r = read(Metric::Volume, &st, &view(), &ctx);
        assert_eq!((r.value.as_str(), r.subject.as_str(), r.level), ("Denied", "No permission", Level::Error));
    }

    #[test]
    fn connection_problems_override_values() {
        let status = ConnStatus::Auth(AuthError::NeedOtp);
        let ctx = Context { status: &status, unit: TempUnit::Celsius };
        let r = read(Metric::Cpu, &state(util()), &view(), &ctx);
        assert_eq!((r.value.as_str(), r.level), ("2FA", Level::Warn));
        let status = ConnStatus::NotConfigured;
        let ctx = Context { status: &status, unit: TempUnit::Celsius };
        assert_eq!(read(Metric::Cpu, &PollState::default(), &view(), &ctx).value, "Set up");
    }

    #[test]
    fn rotation_cycles_views_with_wraparound() {
        let mut v = view();
        rotate(Metric::Cpu, &mut v, None, -1);
        assert_eq!(v.cpu_view, CpuView::Load15);
        rotate(Metric::Cpu, &mut v, None, 2);
        assert_eq!(v.cpu_view, CpuView::Load1);
        rotate(Metric::Network, &mut v, None, 1);
        assert_eq!(v.direction, Direction::Out);
        rotate(Metric::Ram, &mut v, None, 1);
        assert_eq!(v.amount, Amount::Used);
    }

    #[test]
    fn rotation_steps_through_disks_then_the_aggregate() {
        let p = storage("storage.json");
        let mut v = view();
        rotate(Metric::DiskTemp, &mut v, Some(&p), 1);
        assert_eq!(v.target.as_deref(), Some("sata1"));
        rotate(Metric::DiskTemp, &mut v, Some(&p), -1);
        assert_eq!(v.target, None);
        rotate(Metric::DiskTemp, &mut v, Some(&p), -1);
        assert_eq!(v.target.as_deref(), Some("nvme0n1"));
        let mut v = view();
        rotate(Metric::DiskTemp, &mut v, None, 1);
        assert_eq!(v.target, None, "no data yet: nothing to rotate through");
    }

    #[test]
    fn rotation_through_pools_starts_from_the_first() {
        let p = storage("storage_degraded.json");
        let mut v = view();
        rotate(Metric::Pool, &mut v, Some(&p), 1);
        assert_eq!(v.target.as_deref(), Some("reuse_2"));
    }

    #[test]
    fn target_options_for_the_settings_panel() {
        let opts = target_options(Metric::DiskHealth, &storage("storage.json"));
        assert_eq!(opts[0], (None, "Worst disk".to_string()));
        assert_eq!(opts[1], (Some("sata1".into()), "Drive 1".to_string()));
        let opts = target_options(Metric::Network, &util());
        assert_eq!(opts.len(), 3, "all interfaces + eth0 + eth1, not `total`");
        assert!(target_options(Metric::Cpu, &util()).is_empty());
    }
}
```

Add `mod metrics;` to `src/main.rs`.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test metrics::`
Expected: compile errors.

- [ ] **Step 3: Implement above the tests**

```rust
//! Turns the latest poll of an endpoint into what one key or dial shows.
//! Pure: no I/O and no clocks - everything it needs is passed in.

use crate::dsm::error::{AuthError, DsmError};
use crate::dsm::model::{Disk, Payload, Storage, SystemInfo, UpdateStatus, Utilization};
use crate::format;
use crate::metric::Metric;
use crate::poller::PollState;
use crate::settings::{ActionSettings, Amount, CpuView, Direction, TempUnit};
use crate::status::ConnStatus;
use std::cmp::Ordering;

/// Consecutive failed polls before a still-shown value is marked stale.
pub const STALE_AFTER: u32 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Normal,
    Warn,
    Crit,
    Stale,
    Error,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Reading {
    pub title: &'static str,
    pub value: String,
    pub subject: String,
    pub level: Level,
    /// 0-100 fill for the dial's bar; `None` draws a full bar in the level's colour.
    pub bar: Option<f64>,
    /// (position, count) when turning the dial has somewhere to go.
    pub pager: Option<(usize, usize)>,
}

impl Reading {
    fn new(metric: Metric, value: impl Into<String>, level: Level) -> Self {
        Self { title: metric.title(), value: value.into(), subject: String::new(), level, bar: None, pager: None }
    }
    fn subject(mut self, s: impl Into<String>) -> Self {
        self.subject = s.into();
        self
    }
    fn bar(mut self, pct: f64) -> Self {
        self.bar = Some(pct.clamp(0.0, 100.0));
        self
    }
    fn pager(mut self, pos: usize, count: usize) -> Self {
        if count > 1 {
            self.pager = Some((pos, count));
        }
        self
    }
}

pub struct Context<'a> {
    pub status: &'a ConnStatus,
    pub unit: TempUnit,
}

const CPU_VIEWS: [CpuView; 4] = [CpuView::Total, CpuView::Load1, CpuView::Load5, CpuView::Load15];
const AMOUNTS: [Amount; 2] = [Amount::Percent, Amount::Used];
const DIRECTIONS: [Direction; 3] = [Direction::In, Direction::Out, Direction::Combined];

pub fn read(metric: Metric, state: &PollState<Payload>, view: &ActionSettings, ctx: &Context) -> Reading {
    if let Some(r) = connection_reading(metric, ctx.status) {
        return r;
    }
    match (&state.value, &state.error) {
        (_, Some(e)) if e.needs_user() => error_reading(metric, e),
        (None, Some(e)) => error_reading(metric, e),
        (None, None) => Reading::new(metric, "…", Level::Normal),
        (Some(p), _) => {
            let mut r = value_reading(metric, p, view, ctx.unit);
            if state.failures >= STALE_AFTER {
                r.level = Level::Stale;
            }
            r
        }
    }
}

/// When the connection itself needs the user, every key says so.
fn connection_reading(metric: Metric, status: &ConnStatus) -> Option<Reading> {
    let (value, subject, level) = match status {
        ConnStatus::NotConfigured => ("Set up", "Open settings", Level::Normal),
        ConnStatus::Auth(AuthError::NeedOtp | AuthError::BadOtp) => ("2FA", "Enter code", Level::Warn),
        ConnStatus::Auth(_) => ("Login", "Check settings", Level::Error),
        ConnStatus::Certificate { .. } => ("Cert", "Check settings", Level::Error),
        _ => return None,
    };
    Some(Reading::new(metric, value, level).subject(subject))
}

fn error_reading(metric: Metric, e: &DsmError) -> Reading {
    let (value, subject) = match e {
        DsmError::NotConfigured => ("Set up", "Open settings".to_string()),
        DsmError::Transport(_) => ("Offline", String::new()),
        DsmError::Auth(_) => ("Login", "Check settings".to_string()),
        DsmError::CertificateNotTrusted { .. } | DsmError::CertificateChanged { .. } => {
            ("Cert", "Check settings".to_string())
        }
        DsmError::Permission { .. } => ("Denied", "No permission".to_string()),
        DsmError::Api { code, .. } => ("Error", format!("DSM {code}")),
        DsmError::Parse { .. } => ("Error", "Bad data".to_string()),
    };
    Reading::new(metric, value, Level::Error).subject(subject)
}

fn value_reading(metric: Metric, p: &Payload, v: &ActionSettings, unit: TempUnit) -> Reading {
    match (metric, p) {
        (Metric::Cpu, Payload::Utilization(u)) => cpu(u, v),
        (Metric::Ram, Payload::Utilization(u)) => ram(u, v),
        (Metric::Network, Payload::Utilization(u)) => network(u, v),
        (Metric::SysTemp, Payload::SystemInfo(s)) => sys_temp(s, v, unit),
        (Metric::Uptime, Payload::SystemInfo(s)) => uptime(s),
        (Metric::DiskTemp, Payload::Storage(s)) => disk_temp(s, v, unit),
        (Metric::DiskHealth, Payload::Storage(s)) => disk_health(s, v),
        (Metric::Volume, Payload::Storage(s)) => volume(s, v),
        (Metric::Pool, Payload::Storage(s)) => pool(s, v),
        (Metric::Update, Payload::Update(u)) => update(u),
        _ => Reading::new(metric, "Error", Level::Error),
    }
}

fn thresholds(metric: Metric, v: &ActionSettings) -> (Option<f64>, Option<f64>) {
    let d = metric.default_thresholds();
    (v.warn.or(d.map(|t| t.0)), v.crit.or(d.map(|t| t.1)))
}

fn level_for(value: f64, (warn, crit): (Option<f64>, Option<f64>)) -> Level {
    if crit.is_some_and(|c| value >= c) {
        Level::Crit
    } else if warn.is_some_and(|w| value >= w) {
        Level::Warn
    } else {
        Level::Normal
    }
}

fn index_of<T: PartialEq>(list: &[T], x: &T) -> usize {
    list.iter().position(|y| y == x).unwrap_or(0)
}

fn missing(metric: Metric, what: &str) -> Reading {
    Reading::new(metric, "Missing", Level::Crit).subject(what)
}

fn cpu(u: &Utilization, v: &ActionSettings) -> Reading {
    let c = &u.cpu;
    let (value, subject) = match v.cpu_view {
        CpuView::Total => (format::percent(c.total_pct), "Usage"),
        CpuView::Load1 => (format::load(c.load1), "Load 1 min"),
        CpuView::Load5 => (format::load(c.load5), "Load 5 min"),
        CpuView::Load15 => (format::load(c.load15), "Load 15 min"),
    };
    Reading::new(Metric::Cpu, value, level_for(c.total_pct, thresholds(Metric::Cpu, v)))
        .subject(subject)
        .bar(c.total_pct)
        .pager(index_of(&CPU_VIEWS, &v.cpu_view), CPU_VIEWS.len())
}

fn ram(u: &Utilization, v: &ActionSettings) -> Reading {
    let m = &u.memory;
    let value = match v.amount {
        Amount::Percent => format::percent(m.used_pct),
        Amount::Used => format::used_of_total(m.used_bytes, m.total_bytes),
    };
    Reading::new(Metric::Ram, value, level_for(m.used_pct, thresholds(Metric::Ram, v)))
        .subject("Used")
        .bar(m.used_pct)
        .pager(index_of(&AMOUNTS, &v.amount), AMOUNTS.len())
}

fn network(u: &Utilization, v: &ActionSettings) -> Reading {
    let device = v.target.as_deref().unwrap_or("total");
    let Some(nic) = u.network.iter().find(|n| n.device == device) else {
        return missing(Metric::Network, device);
    };
    let (bps, arrow) = match v.direction {
        Direction::In => (nic.rx, "↓"),
        Direction::Out => (nic.tx, "↑"),
        Direction::Combined => (nic.rx.saturating_add(nic.tx), "↕"),
    };
    let mbps = bps as f64 / 1_048_576.0;
    let subject = if device == "total" { "All interfaces" } else { device };
    let r = Reading::new(Metric::Network, format!("{arrow}{}", format::rate(bps)), level_for(mbps, (v.warn, v.crit)))
        .subject(subject)
        .pager(index_of(&DIRECTIONS, &v.direction), DIRECTIONS.len());
    match v.crit.filter(|c| *c > 0.0) {
        Some(crit) => r.bar(mbps / crit * 100.0),
        None => r,
    }
}

fn sys_temp(s: &SystemInfo, v: &ActionSettings, unit: TempUnit) -> Reading {
    let Some(c) = s.sys_temp_c else {
        return Reading::new(Metric::SysTemp, "N/A", Level::Normal).subject("No sensor");
    };
    Reading::new(Metric::SysTemp, format::temperature(c, unit), level_for(c, thresholds(Metric::SysTemp, v)))
        .subject("Temperature")
        .bar(c)
}

fn uptime(s: &SystemInfo) -> Reading {
    match s.uptime_secs {
        Some(secs) => Reading::new(Metric::Uptime, format::uptime(secs), Level::Normal),
        None => Reading::new(Metric::Uptime, "N/A", Level::Normal),
    }
}

/// What turning the dial steps through, `None` being the aggregate entry
/// (hottest/worst disk). Volumes and pools have no aggregate.
fn rotation_targets(metric: Metric, s: &Storage) -> Vec<Option<String>> {
    match metric {
        Metric::DiskTemp | Metric::DiskHealth => {
            s.disks.iter().map(|d| Some(d.id.clone())).chain([None]).collect()
        }
        Metric::Volume => s.volumes.iter().map(|x| Some(x.id.clone())).collect(),
        Metric::Pool => s.pools.iter().map(|x| Some(x.id.clone())).collect(),
        _ => Vec::new(),
    }
}

/// The target actually shown: for volumes and pools, unset means the first.
fn resolved_target(metric: Metric, s: &Storage, v: &ActionSettings) -> Option<String> {
    match (metric, &v.target) {
        (Metric::Volume, None) => s.volumes.first().map(|x| x.id.clone()),
        (Metric::Pool, None) => s.pools.first().map(|x| x.id.clone()),
        (_, t) => t.clone(),
    }
}

fn position(metric: Metric, s: &Storage, v: &ActionSettings) -> (usize, usize) {
    let cycle = rotation_targets(metric, s);
    (index_of(&cycle, &resolved_target(metric, s, v)), cycle.len())
}

fn disk_temp(s: &Storage, v: &ActionSettings, unit: TempUnit) -> Reading {
    let (pos, count) = position(Metric::DiskTemp, s, v);
    let (disk, subject) = match v.target.as_deref() {
        Some(id) => match s.disks.iter().find(|d| d.id == id) {
            Some(d) => (Some(d), d.name.clone()),
            None => return missing(Metric::DiskTemp, id),
        },
        None => {
            let hottest = s
                .disks
                .iter()
                .filter(|d| d.temp_c.is_some())
                .max_by(|a, b| a.temp_c.partial_cmp(&b.temp_c).unwrap_or(Ordering::Equal));
            let subject = hottest.map_or_else(|| "No sensors".to_string(), |d| format!("Hottest: {}", d.name));
            (hottest, subject)
        }
    };
    let Some(c) = disk.and_then(|d| d.temp_c) else {
        return Reading::new(Metric::DiskTemp, "N/A", Level::Normal).subject(subject).pager(pos, count);
    };
    Reading::new(Metric::DiskTemp, format::temperature(c, unit), level_for(c, thresholds(Metric::DiskTemp, v)))
        .subject(subject)
        .bar(c)
        .pager(pos, count)
}

/// Worst of the S.M.A.R.T. verdict and the drive's own status. Unknown
/// words count as a warning: better a false alarm than a silent failure.
fn disk_level(d: &Disk) -> Level {
    let smart = match d.smart_status.as_str() {
        "normal" => Level::Normal,
        "failing" | "crashed" | "damage" => Level::Crit,
        _ => Level::Warn,
    };
    let status = match d.status.as_str() {
        "normal" | "initialized" | "not_initialized" => Level::Normal,
        "crashed" | "failing" | "system_partition_failed" => Level::Crit,
        _ => Level::Warn,
    };
    smart.max(status)
}

fn health_word(level: Level) -> &'static str {
    match level {
        Level::Normal => "OK",
        Level::Warn => "Warning",
        _ => "Failing",
    }
}

fn disk_health(s: &Storage, v: &ActionSettings) -> Reading {
    let (pos, count) = position(Metric::DiskHealth, s, v);
    let (level, subject) = match v.target.as_deref() {
        Some(id) => match s.disks.iter().find(|d| d.id == id) {
            Some(d) => (disk_level(d), d.name.clone()),
            None => return missing(Metric::DiskHealth, id),
        },
        // `rev` so that among equally bad disks the first one is named.
        None => match s.disks.iter().rev().max_by_key(|d| disk_level(d)) {
            None => return Reading::new(Metric::DiskHealth, "N/A", Level::Normal).subject("No disks"),
            Some(d) if disk_level(d) == Level::Normal => {
                (Level::Normal, format!("All {} disks", s.disks.len()))
            }
            Some(d) => (disk_level(d), d.name.clone()),
        },
    };
    Reading::new(Metric::DiskHealth, health_word(level), level).subject(subject).pager(pos, count)
}

/// Volume and pool states share DSM's vocabulary.
fn state_level(status: &str) -> Level {
    match status {
        "normal" => Level::Normal,
        "degraded" | "crashed" => Level::Crit,
        _ => Level::Warn,
    }
}

fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    chars.next().map_or_else(String::new, |c| c.to_uppercase().chain(chars).collect())
}

fn volume(s: &Storage, v: &ActionSettings) -> Reading {
    let (pos, count) = position(Metric::Volume, s, v);
    let vol = match v.target.as_deref() {
        Some(id) => match s.volumes.iter().find(|x| x.id == id) {
            Some(x) => x,
            None => return missing(Metric::Volume, id),
        },
        None => match s.volumes.first() {
            Some(x) => x,
            None => return Reading::new(Metric::Volume, "N/A", Level::Normal).subject("No volumes"),
        },
    };
    let pct = if vol.total_bytes == 0 { 0.0 } else { vol.used_bytes as f64 / vol.total_bytes as f64 * 100.0 };
    let value = match v.amount {
        Amount::Percent => format::percent(pct),
        Amount::Used => format::used_of_total(vol.used_bytes, vol.total_bytes),
    };
    let level = level_for(pct, thresholds(Metric::Volume, v)).max(state_level(&vol.status));
    Reading::new(Metric::Volume, value, level).subject(vol.name.clone()).bar(pct).pager(pos, count)
}

fn pool(s: &Storage, v: &ActionSettings) -> Reading {
    let (pos, count) = position(Metric::Pool, s, v);
    let p = match v.target.as_deref() {
        Some(id) => match s.pools.iter().find(|x| x.id == id) {
            Some(x) => x,
            None => return missing(Metric::Pool, id),
        },
        None => match s.pools.first() {
            Some(x) => x,
            None => return Reading::new(Metric::Pool, "N/A", Level::Normal).subject("No pools"),
        },
    };
    let verb = match p.status.as_str() {
        "repairing" => "Rebuild".to_string(),
        "expanding" => "Expand".to_string(),
        "verifying" | "data_scrubbing" => "Check".to_string(),
        other => capitalize(other),
    };
    let value = match (p.status.as_str(), p.progress_pct) {
        ("normal", _) => "Normal".to_string(),
        (_, Some(pct)) => format!("{verb} {pct:.0}%"),
        (_, None) => verb,
    };
    let r = Reading::new(Metric::Pool, value, state_level(&p.status)).subject(p.name.clone()).pager(pos, count);
    match p.progress_pct {
        Some(pct) if p.status != "normal" => r.bar(pct),
        _ => r,
    }
}

fn update(u: &UpdateStatus) -> Reading {
    if u.available {
        Reading::new(Metric::Update, "Update", Level::Warn).subject(u.version.clone().unwrap_or_default())
    } else {
        Reading::new(Metric::Update, "Up to date", Level::Normal)
    }
}

fn step(i: usize, n: usize, ticks: i16) -> usize {
    (i as i64 + i64::from(ticks)).rem_euclid(n as i64) as usize
}

/// Applies a dial turn to an instance's in-memory view, wrapping at the ends.
pub fn rotate(metric: Metric, view: &mut ActionSettings, latest: Option<&Payload>, ticks: i16) {
    match metric {
        Metric::Cpu => view.cpu_view = CPU_VIEWS[step(index_of(&CPU_VIEWS, &view.cpu_view), CPU_VIEWS.len(), ticks)],
        Metric::Ram => view.amount = AMOUNTS[step(index_of(&AMOUNTS, &view.amount), AMOUNTS.len(), ticks)],
        Metric::Network => {
            view.direction = DIRECTIONS[step(index_of(&DIRECTIONS, &view.direction), DIRECTIONS.len(), ticks)]
        }
        Metric::DiskTemp | Metric::DiskHealth | Metric::Volume | Metric::Pool => {
            let Some(Payload::Storage(s)) = latest else { return };
            let cycle = rotation_targets(metric, s);
            if cycle.is_empty() {
                return;
            }
            let i = index_of(&cycle, &resolved_target(metric, s, view));
            view.target = cycle[step(i, cycle.len(), ticks)].clone();
        }
        Metric::SysTemp | Metric::Uptime | Metric::Update => {}
    }
}

/// Choices for the settings panel's target dropdown: (setting value, label),
/// a `None` value meaning the aggregate.
pub fn target_options(metric: Metric, p: &Payload) -> Vec<(Option<String>, String)> {
    let disks = |s: &Storage, aggregate: &str| -> Vec<(Option<String>, String)> {
        std::iter::once((None, aggregate.to_string()))
            .chain(s.disks.iter().map(|d| (Some(d.id.clone()), d.name.clone())))
            .collect()
    };
    match (metric, p) {
        (Metric::Network, Payload::Utilization(u)) => std::iter::once((None, "All interfaces".to_string()))
            .chain(
                u.network
                    .iter()
                    .filter(|n| n.device != "total")
                    .map(|n| (Some(n.device.clone()), n.device.clone())),
            )
            .collect(),
        (Metric::DiskTemp, Payload::Storage(s)) => disks(s, "Hottest disk"),
        (Metric::DiskHealth, Payload::Storage(s)) => disks(s, "Worst disk"),
        (Metric::Volume, Payload::Storage(s)) => {
            s.volumes.iter().map(|x| (Some(x.id.clone()), x.name.clone())).collect()
        }
        (Metric::Pool, Payload::Storage(s)) => s.pools.iter().map(|x| (Some(x.id.clone()), x.name.clone())).collect(),
        _ => Vec::new(),
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test metrics::`
Expected: PASS (19 tests). The expected values come from the Task 3 fixtures:
- eth1 `tx` = 4288 B/s = 4.19 KB/s, shown as `4.2 KB/s`
- the volume is 5452.8 / 7680 = 71 %
- 12.4 MB/s is over the 10 MB/s crit threshold, so the bar fills to 100

Run: `cargo fmt && cargo clippy --all-targets -- -D warnings`
Expected: clean. Run `cargo fmt` (not `--check`) first, because some lines above are longer than rustfmt allows.

- [ ] **Step 5: Commit**

```bash
git add src/metrics.rs src/main.rs
git commit -m "feat: turn poll results into key and dial readings for all ten metrics

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---
### Task 8: Pinning certificate verifier

**Files:**
- Create: `src/dsm/tls.rs`
- Modify: `src/dsm/mod.rs` (add `pub mod tls;`)

**Interfaces:**
- Consumes: nothing from earlier tasks
- Produces:
  - `dsm::tls::fingerprint(der: &[u8]) -> String` (lowercase hex SHA-256)
  - `dsm::tls::Rejection { NotTrusted(String), Changed(String) }`
  - `dsm::tls::PinningVerifier`:
    - `new(pinned: Option<String>, roots: RootCertStore, provider: Arc<CryptoProvider>) -> Self`
    - `with_system_roots(pinned: Option<String>) -> Self`
    - `take_rejection(&self) -> Option<Rejection>`
    - `client_config(self: Arc<Self>) -> rustls::ClientConfig`
    - implements `rustls::client::danger::ServerCertVerifier`

- [ ] **Step 1: Write the failing tests**

`src/dsm/tls.rs` (tests only):
```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn self_signed() -> CertificateDer<'static> {
        rcgen::generate_simple_self_signed(vec!["nas.lan".to_string()]).unwrap().cert.der().clone()
    }

    fn verifier(pinned: Option<String>) -> PinningVerifier {
        PinningVerifier::new(pinned, RootCertStore::empty(), Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
    }

    fn verify(v: &PinningVerifier, cert: &CertificateDer<'_>) -> Result<ServerCertVerified, Error> {
        v.verify_server_cert(cert, &[], &ServerName::try_from("nas.lan").unwrap(), &[], UnixTime::now())
    }

    #[test]
    fn fingerprint_is_lowercase_sha256_hex() {
        assert_eq!(fingerprint(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    #[test]
    fn unknown_certificate_is_rejected_with_its_fingerprint() {
        let cert = self_signed();
        let v = verifier(None);
        assert!(verify(&v, &cert).is_err());
        assert_eq!(v.take_rejection(), Some(Rejection::NotTrusted(fingerprint(cert.as_ref()))));
        assert_eq!(v.take_rejection(), None, "reading clears it");
    }

    #[test]
    fn pinned_certificate_is_accepted_case_insensitively() {
        let cert = self_signed();
        let v = verifier(Some(fingerprint(cert.as_ref()).to_uppercase()));
        assert!(verify(&v, &cert).is_ok());
        assert_eq!(v.take_rejection(), None);
    }

    #[test]
    fn a_different_certificate_than_the_pin_is_a_change() {
        let pinned = fingerprint(self_signed().as_ref());
        let other = self_signed();
        let v = verifier(Some(pinned));
        assert!(verify(&v, &other).is_err());
        assert_eq!(v.take_rejection(), Some(Rejection::Changed(fingerprint(other.as_ref()))));
    }
}
```

Add `pub mod tls;` to `src/dsm/mod.rs`.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test dsm::tls`
Expected: compile errors.

- [ ] **Step 3: Implement above the tests**

```rust
//! Certificate trust for a NAS that usually has a self-signed certificate:
//! accept what the system roots accept, or exactly the certificate the user
//! pinned - never "any certificate".

use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, DigitallySignedStruct, Error, RootCertStore, SignatureScheme};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::sync::{Arc, Mutex};

pub fn fingerprint(der: &[u8]) -> String {
    Sha256::digest(der).iter().fold(String::with_capacity(64), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Why the last handshake was refused, carrying the offending certificate's
/// fingerprint so the settings panel can offer to trust it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rejection {
    NotTrusted(String),
    Changed(String),
}

#[derive(Debug)]
pub struct PinningVerifier {
    roots: Option<Arc<WebPkiServerVerifier>>,
    pinned: Option<String>,
    provider: Arc<CryptoProvider>,
    rejected: Mutex<Option<Rejection>>,
}

impl PinningVerifier {
    pub fn new(pinned: Option<String>, roots: RootCertStore, provider: Arc<CryptoProvider>) -> Self {
        let roots = if roots.is_empty() {
            None
        } else {
            WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone()).build().ok()
        };
        Self { roots, pinned: pinned.map(|p| p.to_lowercase()), provider, rejected: Mutex::new(None) }
    }

    pub fn with_system_roots(pinned: Option<String>) -> Self {
        let loaded = rustls_native_certs::load_native_certs();
        for e in &loaded.errors {
            log::warn!("system certificate store: {e}");
        }
        let mut roots = RootCertStore::empty();
        roots.add_parsable_certificates(loaded.certs);
        Self::new(pinned, roots, Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
    }

    /// Why the last handshake was refused, if it was. Reading clears it.
    pub fn take_rejection(&self) -> Option<Rejection> {
        self.rejected.lock().unwrap().take()
    }

    pub fn client_config(self: Arc<Self>) -> rustls::ClientConfig {
        rustls::ClientConfig::builder_with_provider(self.provider.clone())
            .with_safe_default_protocol_versions()
            .expect("the default provider supports the default TLS versions")
            .dangerous()
            .with_custom_certificate_verifier(self)
            .with_no_client_auth()
    }
}

impl ServerCertVerifier for PinningVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let fp = fingerprint(end_entity.as_ref());
        // The pin is the trust anchor, so the hostname isn't checked for it:
        // users reach their NAS by IP as often as by name.
        if self.pinned.as_deref() == Some(fp.as_str()) {
            return Ok(ServerCertVerified::assertion());
        }
        if let Some(roots) = &self.roots
            && roots.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now).is_ok()
        {
            return Ok(ServerCertVerified::assertion());
        }
        let rejection = if self.pinned.is_some() { Rejection::Changed(fp) } else { Rejection::NotTrusted(fp) };
        *self.rejected.lock().unwrap() = Some(rejection);
        Err(Error::InvalidCertificate(CertificateError::UnknownIssuer))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test dsm::tls`
Expected: PASS (4 tests). If `rcgen` 0.14's `generate_simple_self_signed` returns a different shape, check it with `cargo doc -p rcgen --open`. Only `.cert.der()` is used here.

Run: `cargo fmt && cargo clippy --all-targets -- -D warnings`
Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add src/dsm/tls.rs src/dsm/mod.rs
git commit -m "feat: add a certificate verifier that trusts system roots or a pinned fingerprint

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 9: HTTP transport and API discovery

**Files:**
- Create: `src/dsm/transport.rs`, `src/dsm/api.rs`
- Modify: `src/dsm/mod.rs` (add `pub mod api; pub mod transport;`), `Cargo.toml` (dev-dependencies)

**Interfaces:**
- Consumes:
  - `settings::Connection` (Task 4)
  - `dsm::error::DsmError` (Task 3)
  - `dsm::tls::{PinningVerifier, Rejection}` (Task 8)
- Produces:
  - `dsm::transport::Transport` (async trait, `Send + Sync`), with `call(&self, path: &str, form: &[(&str, &str)]) -> Result<Result<Value, i64>, DsmError>`. The outer `Err` is a transport, TLS or body failure. The inner `Err(code)` is DSM's own error code.
  - `dsm::transport::HttpTransport::new(&Connection) -> Result<HttpTransport, DsmError>`
  - `dsm::transport::unwrap_envelope(Value) -> Result<Result<Value, i64>, DsmError>`
  - `dsm::api::{AUTH, UTILIZATION, SYSTEM, STORAGE, UPGRADE}: &str` constants
  - `dsm::api::ApiInfo { path: String, version: u32 }` and `dsm::api::ApiMap = HashMap<String, ApiInfo>`
  - `dsm::api::discover(&dyn Transport) -> Result<ApiMap, DsmError>`
  - `dsm::api::parse_api_info(&Value) -> Result<ApiMap, DsmError>`

- [ ] **Step 1: Add the test-only dependencies**

In `Cargo.toml`, replace the `[dev-dependencies]` section with:
```toml
[dev-dependencies]
tokio = { version = "1.48", features = ["test-util", "macros", "rt", "rt-multi-thread", "net", "io-util"] }
rcgen = "0.14"
tokio-rustls = { version = "0.26", default-features = false, features = ["aws_lc_rs"] }
```

- [ ] **Step 2: Write the failing tests**

`src/dsm/transport.rs` (tests only):
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::dsm::tls::fingerprint;
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use serde_json::json;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::oneshot;

    const OK_BODY: &str = r#"{"success":true,"data":{"ok":1}}"#;

    fn response() -> String {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{OK_BODY}",
            OK_BODY.len()
        )
    }

    fn conn(port: u16, https: bool, pinned: Option<String>) -> Connection {
        Connection { host: "127.0.0.1".into(), port, https, account: "jf".into(), pinned_sha256: pinned }
    }

    /// Plain-HTTP server answering one request; hands back the raw request.
    async fn http_server() -> (u16, oneshot::Receiver<String>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = oneshot::channel();
        tokio::spawn(async move {
            let (mut tcp, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 16 * 1024];
            let n = tcp.read(&mut buf).await.unwrap();
            let _ = tx.send(String::from_utf8_lossy(&buf[..n]).into_owned());
            tcp.write_all(response().as_bytes()).await.unwrap();
        });
        (port, rx)
    }

    /// HTTPS server with a fresh self-signed certificate; returns its port
    /// and the certificate's fingerprint.
    async fn tls_server() -> (u16, String) {
        let ck = rcgen::generate_simple_self_signed(vec!["nas.lan".to_string()]).unwrap();
        let fp = fingerprint(ck.cert.der().as_ref());
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der()));
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![ck.cert.der().clone()], key)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let (tcp, _) = listener.accept().await.unwrap();
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    if let Ok(mut tls) = acceptor.accept(tcp).await {
                        let mut buf = vec![0u8; 16 * 1024];
                        let _ = tls.read(&mut buf).await;
                        let _ = tls.write_all(response().as_bytes()).await;
                        let _ = tls.shutdown().await;
                    }
                });
            }
        });
        (port, fp)
    }

    #[test]
    fn unwraps_dsm_envelopes() {
        assert_eq!(unwrap_envelope(json!({ "success": true, "data": { "a": 1 } })), Ok(Ok(json!({ "a": 1 }))));
        assert_eq!(unwrap_envelope(json!({ "success": true })), Ok(Ok(Value::Null)));
        assert_eq!(unwrap_envelope(json!({ "success": false, "error": { "code": 119 } })), Ok(Err(119)));
        assert!(matches!(unwrap_envelope(json!("<html>")), Err(DsmError::Transport(_))));
    }

    #[tokio::test]
    async fn posts_a_form_body_and_keeps_secrets_out_of_the_url() {
        let (port, request) = http_server().await;
        let t = HttpTransport::new(&conn(port, false, None)).unwrap();
        let out = t.call("entry.cgi", &[("api", "SYNO.API.Auth"), ("passwd", "p&ss=w+rd%ü")]).await.unwrap();
        assert_eq!(out, Ok(json!({ "ok": 1 })));
        let raw = request.await.unwrap();
        let (head, body) = raw.split_once("\r\n\r\n").unwrap();
        assert!(head.starts_with("POST /webapi/entry.cgi HTTP/1.1"), "{head}");
        assert!(!head.contains("passwd"), "no secrets in the request line or headers");
        assert_eq!(body, "api=SYNO.API.Auth&passwd=p%26ss%3Dw%2Brd%25%C3%BC");
    }

    #[tokio::test]
    async fn unreachable_host_is_a_transport_error() {
        let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let t = HttpTransport::new(&conn(port, false, None)).unwrap();
        let err = t.call("query.cgi", &[]).await.unwrap_err();
        assert!(matches!(err, DsmError::Transport(_)), "{err:?}");
    }

    #[tokio::test]
    async fn untrusted_certificate_reports_its_fingerprint() {
        let (port, fp) = tls_server().await;
        let t = HttpTransport::new(&conn(port, true, None)).unwrap();
        let err = t.call("query.cgi", &[]).await.unwrap_err();
        assert_eq!(err, DsmError::CertificateNotTrusted { fingerprint: fp });
    }

    #[tokio::test]
    async fn pinned_certificate_connects() {
        let (port, fp) = tls_server().await;
        let t = HttpTransport::new(&conn(port, true, Some(fp))).unwrap();
        assert_eq!(t.call("query.cgi", &[]).await.unwrap(), Ok(json!({ "ok": 1 })));
    }

    #[tokio::test]
    async fn a_new_certificate_behind_a_pin_is_reported_as_changed() {
        let (port, fp) = tls_server().await;
        let t = HttpTransport::new(&conn(port, true, Some("00".repeat(32)))).unwrap();
        let err = t.call("query.cgi", &[]).await.unwrap_err();
        assert_eq!(err, DsmError::CertificateChanged { fingerprint: fp });
    }
}
```

`src/dsm/api.rs` (tests only):
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn info() -> Value {
        json!({
            "SYNO.API.Auth": { "maxVersion": 7, "minVersion": 1, "path": "entry.cgi" },
            "SYNO.Core.System.Utilization": { "maxVersion": 1, "minVersion": 1, "path": "entry.cgi" },
            "SYNO.Core.System": { "maxVersion": 3, "minVersion": 1, "path": "entry.cgi" },
            "SYNO.Storage.CGI.Storage": { "maxVersion": 1, "minVersion": 1, "path": "entry.cgi" },
            "SYNO.Core.Upgrade.Server": { "maxVersion": 4, "minVersion": 2, "path": "entry.cgi" }
        })
    }

    #[test]
    fn picks_our_version_clamped_to_what_the_nas_offers() {
        let map = parse_api_info(&info()).unwrap();
        assert_eq!(map[AUTH], ApiInfo { path: "entry.cgi".into(), version: 6 });
        assert_eq!(map[SYSTEM].version, 1);
        assert_eq!(map[UPGRADE].version, 2, "raised to the NAS's minimum");
    }

    #[test]
    fn dsm_6_is_refused_with_a_clear_message() {
        let mut v = info();
        v["SYNO.API.Auth"]["maxVersion"] = json!(4);
        let err = parse_api_info(&v).unwrap_err();
        assert!(err.to_string().contains("DSM 7"), "{err}");
    }

    #[test]
    fn missing_optional_apis_are_skipped() {
        let mut v = info();
        v.as_object_mut().unwrap().remove(UPGRADE);
        let map = parse_api_info(&v).unwrap();
        assert!(!map.contains_key(UPGRADE));
        assert!(map.contains_key(AUTH));
    }

    #[test]
    fn recorded_api_info_parses() {
        let path = format!("{}/tests/fixtures/real/api_info.json", env!("CARGO_MANIFEST_DIR"));
        let Ok(raw) = std::fs::read_to_string(&path) else {
            eprintln!("skipping: api_info.json not recorded");
            return;
        };
        let map = parse_api_info(&serde_json::from_str(&raw).unwrap()).unwrap();
        assert!(map.contains_key(AUTH));
    }
}
```

Add both modules to `src/dsm/mod.rs`:
```rust
pub mod api;
pub mod error;
pub mod model;
pub mod tls;
pub mod transport;
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cargo test dsm::transport dsm::api`
Expected: compile errors.

- [ ] **Step 4: Implement `src/dsm/transport.rs` above its tests**

```rust
//! The wire: POST a form to `/webapi/<path>` and unwrap DSM's
//! `{success, data | error}` envelope. Every parameter goes in the POST
//! body, so the password, 2FA code and session id never appear in a URL,
//! a proxy log or an error message.

use crate::dsm::error::DsmError;
use crate::dsm::tls::{PinningVerifier, Rejection};
use crate::settings::Connection;
use async_trait::async_trait;
use serde_json::Value;
use std::sync::Arc;
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(10);

#[async_trait]
pub trait Transport: Send + Sync {
    /// `Ok(Ok(data))` on success, `Ok(Err(code))` when DSM answered with an
    /// error code, `Err` when there was no usable answer at all.
    async fn call(&self, path: &str, form: &[(&str, &str)]) -> Result<Result<Value, i64>, DsmError>;
}

pub struct HttpTransport {
    client: reqwest::Client,
    base: String,
    verifier: Option<Arc<PinningVerifier>>,
}

impl HttpTransport {
    pub fn new(conn: &Connection) -> Result<Self, DsmError> {
        // The NAS is on the LAN: a system proxy would only get in the way.
        let mut builder = reqwest::Client::builder().timeout(TIMEOUT).no_proxy();
        let verifier = if conn.https {
            let v = Arc::new(PinningVerifier::with_system_roots(conn.pinned_sha256.clone()));
            builder = builder.tls_backend_preconfigured(v.clone().client_config());
            Some(v)
        } else {
            None
        };
        let client = builder.build().map_err(|e| DsmError::Transport(e.to_string()))?;
        Ok(Self { client, base: conn.base_url(), verifier })
    }

    fn send_error(&self, e: reqwest::Error) -> DsmError {
        match self.verifier.as_ref().and_then(|v| v.take_rejection()) {
            Some(Rejection::NotTrusted(fingerprint)) => DsmError::CertificateNotTrusted { fingerprint },
            Some(Rejection::Changed(fingerprint)) => DsmError::CertificateChanged { fingerprint },
            None => DsmError::Transport(e.without_url().to_string()),
        }
    }
}

#[async_trait]
impl Transport for HttpTransport {
    async fn call(&self, path: &str, form: &[(&str, &str)]) -> Result<Result<Value, i64>, DsmError> {
        let url = format!("{}/webapi/{path}", self.base);
        let response = self.client.post(&url).form(form).send().await.map_err(|e| self.send_error(e))?;
        let response = response.error_for_status().map_err(|e| DsmError::Transport(e.without_url().to_string()))?;
        let body: Value = response
            .json()
            .await
            .map_err(|e| DsmError::Transport(format!("unreadable response: {}", e.without_url())))?;
        unwrap_envelope(body)
    }
}

pub fn unwrap_envelope(body: Value) -> Result<Result<Value, i64>, DsmError> {
    match body["success"].as_bool() {
        Some(true) => Ok(Ok(body.get("data").cloned().unwrap_or(Value::Null))),
        Some(false) => Ok(Err(body["error"]["code"].as_i64().unwrap_or(-1))),
        None => Err(DsmError::Transport("the response is not a DSM API reply".into())),
    }
}
```

- [ ] **Step 5: Implement `src/dsm/api.rs` above its tests**

```rust
//! Which DSM web APIs we use, at which version, and where they live.
//! `SYNO.API.Info` tells us, since paths and versions vary between releases.

use crate::dsm::error::DsmError;
use crate::dsm::transport::Transport;
use serde_json::Value;
use std::collections::HashMap;

pub const AUTH: &str = "SYNO.API.Auth";
pub const UTILIZATION: &str = "SYNO.Core.System.Utilization";
pub const SYSTEM: &str = "SYNO.Core.System";
pub const STORAGE: &str = "SYNO.Storage.CGI.Storage";
pub const UPGRADE: &str = "SYNO.Core.Upgrade.Server";

/// (api, version this plugin is written against). The version actually used
/// is clamped into the range the NAS offers.
const WANTED: [(&str, u64); 5] = [(AUTH, 6), (UTILIZATION, 1), (SYSTEM, 1), (STORAGE, 1), (UPGRADE, 1)];

/// Device tokens (2FA "remember this device") need Auth v6, i.e. DSM 7.
const MIN_AUTH_VERSION: u64 = 6;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiInfo {
    pub path: String,
    pub version: u32,
}

pub type ApiMap = HashMap<String, ApiInfo>;

pub async fn discover(t: &dyn Transport) -> Result<ApiMap, DsmError> {
    let names = WANTED.map(|(name, _)| name).join(",");
    let form = [("api", "SYNO.API.Info"), ("version", "1"), ("method", "query"), ("query", names.as_str())];
    match t.call("query.cgi", &form).await? {
        Ok(data) => parse_api_info(&data),
        Err(code) => Err(DsmError::Api { api: "SYNO.API.Info".into(), code }),
    }
}

pub fn parse_api_info(data: &Value) -> Result<ApiMap, DsmError> {
    let mut map = ApiMap::new();
    for (name, wanted) in WANTED {
        let e = &data[name];
        let (Some(path), Some(min), Some(max)) = (e["path"].as_str(), e["minVersion"].as_u64(), e["maxVersion"].as_u64())
        else {
            if name == AUTH {
                return Err(DsmError::Parse { api: "SYNO.API.Info".into(), detail: "the NAS offers no SYNO.API.Auth".into() });
            }
            continue; // that endpoint's keys will show the error when polled
        };
        if name == AUTH && max < MIN_AUTH_VERSION {
            return Err(DsmError::Parse {
                api: AUTH.into(),
                detail: format!("needs DSM 7 (SYNO.API.Auth v{MIN_AUTH_VERSION}+), the NAS offers up to v{max}"),
            });
        }
        map.insert(name.to_string(), ApiInfo { path: path.to_string(), version: wanted.clamp(min, max) as u32 });
    }
    Ok(map)
}
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cargo test dsm::transport dsm::api`
Expected: PASS (6 transport + 4 api tests).

These tests are the only check that `reqwest` really uses our verifier through `tls_backend_preconfigured`. If `untrusted_certificate_reports_its_fingerprint` gets a plain `Transport` error, reqwest isn't calling `PinningVerifier` (a rustls version mismatch between our crate and reqwest makes reqwest treat the config as an unknown backend). Run `cargo tree -i rustls` and make both use the same rustls 0.23.x. Don't weaken the test.

Run: `cargo fmt && cargo clippy --all-targets -- -D warnings`
Expected: clean.

- [ ] **Step 7: Commit**

```bash
git add Cargo.toml Cargo.lock src/dsm
git commit -m "feat: add the DSM HTTP transport and API discovery

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---
### Task 10: DSM session: login, 2FA device token, single-flight re-login

**Files:**
- Create: `src/dsm/session.rs`, `src/dsm/fake.rs`
- Modify: `src/dsm/mod.rs` (add `pub mod session;` and `#[cfg(test)] pub mod fake;`)

**Interfaces:**
- Consumes:
  - `dsm::transport::Transport` (Task 9)
  - `dsm::api::{discover, ApiInfo, ApiMap, AUTH}` (Task 9)
  - `dsm::error::{AuthError, DsmError}` (Task 3)
- Produces:
  - `dsm::session::Credentials { account: String, password: String, did: Option<String>, device_name: String }` (its `Debug` redacts the secrets)
  - `dsm::session::DidListener = Arc<dyn Fn(Option<String>) + Send + Sync>`
  - `dsm::session::Session`:
    - `new(transport: Arc<dyn Transport>, creds: Credentials, on_did: DidListener) -> Self`
    - `call(&self, api: &str, method: &str, params: &[(&str, &str)]) -> Result<Value, DsmError>`
    - `submit_otp(&self, code: &str) -> Result<(), DsmError>`
    - `logout(&self)`
  - `dsm::session::SESSION_NAME = "OpenDeck"`
  - test-only `dsm::fake::FakeDsm`:
    - `new(handler: impl Fn(&Req) -> Result<Value, i64> + Send + Sync + 'static) -> Arc<Self>`
    - `count(&self, method: &str) -> usize`
    - `requests(&self) -> Vec<Req>`
    - `Req = HashMap<String, String>` (includes the key `_path`)
    - `dsm::fake::api_info() -> Value`

- [ ] **Step 1: Write the test fake**

`src/dsm/fake.rs`:
```rust
//! A scripted stand-in for a NAS, for tests. The handler sees each request
//! as a map of its form fields (plus `_path`) and answers like DSM would:
//! `Ok(data)` or `Err(error code)`.

use crate::dsm::error::DsmError;
use crate::dsm::transport::Transport;
use async_trait::async_trait;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

pub type Req = HashMap<String, String>;
type Handler = Box<dyn Fn(&Req) -> Result<Value, i64> + Send + Sync>;

pub struct FakeDsm {
    handler: Handler,
    log: Mutex<Vec<Req>>,
}

impl FakeDsm {
    pub fn new(handler: impl Fn(&Req) -> Result<Value, i64> + Send + Sync + 'static) -> Arc<Self> {
        Arc::new(Self { handler: Box::new(handler), log: Mutex::new(Vec::new()) })
    }

    /// How many requests used this `method` (e.g. "login").
    pub fn count(&self, method: &str) -> usize {
        self.log.lock().unwrap().iter().filter(|r| r.get("method").map(String::as_str) == Some(method)).count()
    }

    pub fn requests(&self) -> Vec<Req> {
        self.log.lock().unwrap().clone()
    }
}

#[async_trait]
impl Transport for FakeDsm {
    async fn call(&self, path: &str, form: &[(&str, &str)]) -> Result<Result<Value, i64>, DsmError> {
        let mut req: Req = form.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        req.insert("_path".into(), path.into());
        self.log.lock().unwrap().push(req.clone());
        // Let concurrent callers interleave, like real network I/O would.
        tokio::task::yield_now().await;
        if req.get("api").map(String::as_str) == Some("SYNO.API.Info") {
            return Ok(Ok(api_info()));
        }
        Ok((self.handler)(&req))
    }
}

pub fn api_info() -> Value {
    let e = |max: u64| json!({ "maxVersion": max, "minVersion": 1, "path": "entry.cgi" });
    json!({
        "SYNO.API.Auth": e(7),
        "SYNO.Core.System.Utilization": e(1),
        "SYNO.Core.System": e(3),
        "SYNO.Storage.CGI.Storage": e(1),
        "SYNO.Core.Upgrade.Server": e(3),
    })
}
```

Update `src/dsm/mod.rs`:
```rust
pub mod api;
pub mod error;
#[cfg(test)]
pub mod fake;
pub mod model;
pub mod session;
pub mod tls;
pub mod transport;
```

- [ ] **Step 2: Write the failing session tests**

`src/dsm/session.rs` (tests only):
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::dsm::api::UTILIZATION;
    use crate::dsm::fake::{FakeDsm, Req};
    use serde_json::json;
    use std::sync::Mutex as StdMutex;
    use std::sync::atomic::{AtomicU32, Ordering::SeqCst};

    fn creds(did: Option<&str>) -> Credentials {
        Credentials {
            account: "jf".into(),
            password: "p&ss=w+rd%ü".into(),
            did: did.map(str::to_string),
            device_name: "OpenDeck-desk".into(),
        }
    }

    fn get(r: &Req, k: &str) -> Option<String> {
        r.get(k).cloned()
    }

    /// Records every `on_did` call.
    fn did_log() -> (DidListener, Arc<StdMutex<Vec<Option<String>>>>) {
        let log = Arc::new(StdMutex::new(Vec::new()));
        let l = log.clone();
        (Arc::new(move |d| l.lock().unwrap().push(d)), log)
    }

    #[tokio::test]
    async fn logs_in_once_and_reuses_the_sid() {
        let fake = FakeDsm::new(|r| match get(r, "method").as_deref() {
            Some("login") => Ok(json!({ "sid": "s1" })),
            _ if get(r, "_sid").as_deref() == Some("s1") => Ok(json!({ "cpu": 1 })),
            _ => Err(119),
        });
        let (on_did, _) = did_log();
        let s = Session::new(fake.clone(), creds(None), on_did);
        assert_eq!(s.call(UTILIZATION, "get", &[]).await.unwrap(), json!({ "cpu": 1 }));
        assert_eq!(s.call(UTILIZATION, "get", &[]).await.unwrap(), json!({ "cpu": 1 }));
        assert_eq!(fake.count("login"), 1);
        let login = fake.requests().into_iter().find(|r| get(r, "method").as_deref() == Some("login")).unwrap();
        assert_eq!(get(&login, "passwd").as_deref(), Some("p&ss=w+rd%ü"), "password passed through untouched");
        assert_eq!(get(&login, "session").as_deref(), Some(SESSION_NAME));
        assert_eq!(get(&login, "version").as_deref(), Some("6"));
        assert_eq!(get(&login, "device_id"), None, "no device token yet");
    }

    #[tokio::test]
    async fn two_factor_flow_stores_the_device_token() {
        let fake = FakeDsm::new(|r| match (get(r, "method").as_deref(), get(r, "otp_code").as_deref()) {
            (Some("login"), Some("123456")) if get(r, "enable_device_token").as_deref() == Some("yes") => {
                Ok(json!({ "sid": "s1", "did": "dev-1" }))
            }
            (Some("login"), Some(_)) => Err(404),
            (Some("login"), None) => Err(403),
            _ => Ok(json!({ "ok": true })),
        });
        let (on_did, dids) = did_log();
        let s = Session::new(fake.clone(), creds(None), on_did);
        assert_eq!(s.call(UTILIZATION, "get", &[]).await, Err(DsmError::Auth(AuthError::NeedOtp)));
        assert_eq!(s.call(UTILIZATION, "get", &[]).await, Err(DsmError::Auth(AuthError::NeedOtp)));
        assert_eq!(fake.count("login"), 1, "waits for the user instead of retrying");

        assert_eq!(s.submit_otp("000000").await, Err(DsmError::Auth(AuthError::BadOtp)));
        s.submit_otp("123456").await.unwrap();
        assert_eq!(dids.lock().unwrap().as_slice(), &[Some("dev-1".to_string())]);
        assert!(s.call(UTILIZATION, "get", &[]).await.is_ok());
        let last_login = fake.requests().into_iter().rev().find(|r| get(r, "method").as_deref() == Some("login")).unwrap();
        assert_eq!(get(&last_login, "device_name").as_deref(), Some("OpenDeck-desk"));
    }

    #[tokio::test]
    async fn a_stored_device_token_skips_the_code() {
        let fake = FakeDsm::new(|r| match get(r, "method").as_deref() {
            Some("login") if get(r, "device_id").as_deref() == Some("dev-1") => Ok(json!({ "sid": "s1" })),
            Some("login") => Err(403),
            _ => Ok(json!({ "ok": true })),
        });
        let (on_did, dids) = did_log();
        let s = Session::new(fake.clone(), creds(Some("dev-1")), on_did);
        assert!(s.call(UTILIZATION, "get", &[]).await.is_ok());
        assert!(dids.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_rejected_device_token_is_dropped() {
        let fake = FakeDsm::new(|r| match get(r, "method").as_deref() {
            Some("login") => Err(403),
            _ => Ok(json!({})),
        });
        let (on_did, dids) = did_log();
        let s = Session::new(fake.clone(), creds(Some("revoked")), on_did);
        assert_eq!(s.call(UTILIZATION, "get", &[]).await, Err(DsmError::Auth(AuthError::NeedOtp)));
        assert_eq!(dids.lock().unwrap().as_slice(), &[None]);
    }

    #[tokio::test]
    async fn never_retries_a_wrong_password() {
        let fake = FakeDsm::new(|r| match get(r, "method").as_deref() {
            Some("login") => Err(400),
            _ => Ok(json!({})),
        });
        let (on_did, _) = did_log();
        let s = Session::new(fake.clone(), creds(None), on_did);
        for _ in 0..3 {
            assert_eq!(s.call(UTILIZATION, "get", &[]).await, Err(DsmError::Auth(AuthError::BadCredentials)));
        }
        assert_eq!(fake.count("login"), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_callers_share_one_relogin() {
        let logins = Arc::new(AtomicU32::new(0));
        let l = logins.clone();
        let fake = FakeDsm::new(move |r| match get(r, "method").as_deref() {
            Some("login") => Ok(json!({ "sid": format!("s{}", l.fetch_add(1, SeqCst) + 1) })),
            // The first session expires; the second one works.
            _ if get(r, "_sid").as_deref() == Some("s2") => Ok(json!({ "ok": true })),
            _ => Err(119),
        });
        let (on_did, _) = did_log();
        let s = Arc::new(Session::new(fake.clone(), creds(None), on_did));
        let calls = (0..4).map(|_| {
            let s = s.clone();
            tokio::spawn(async move { s.call(UTILIZATION, "get", &[]).await })
        });
        for r in futures::future::join_all(calls).await {
            assert!(r.unwrap().is_ok());
        }
        assert_eq!(logins.load(SeqCst), 2, "initial login + exactly one re-login");
    }

    #[tokio::test]
    async fn persistent_105_is_a_permission_error() {
        let fake = FakeDsm::new(|r| match get(r, "method").as_deref() {
            Some("login") => Ok(json!({ "sid": "s1" })),
            _ => Err(105),
        });
        let (on_did, _) = did_log();
        let s = Session::new(fake.clone(), creds(None), on_did);
        assert_eq!(
            s.call(crate::dsm::api::STORAGE, "load_info", &[]).await,
            Err(DsmError::Permission { api: "SYNO.Storage.CGI.Storage".into() })
        );
        assert_eq!(fake.count("login"), 2, "one re-login to rule out a lost session");
    }

    #[tokio::test]
    async fn other_error_codes_surface_as_api_errors() {
        let fake = FakeDsm::new(|r| match get(r, "method").as_deref() {
            Some("login") => Ok(json!({ "sid": "s1" })),
            _ => Err(117),
        });
        let (on_did, _) = did_log();
        let s = Session::new(fake.clone(), creds(None), on_did);
        assert_eq!(
            s.call(UTILIZATION, "get", &[]).await,
            Err(DsmError::Api { api: UTILIZATION.into(), code: 117 })
        );
        assert_eq!(fake.count("login"), 1);
    }

    #[tokio::test]
    async fn logout_ends_the_session() {
        let fake = FakeDsm::new(|r| match get(r, "method").as_deref() {
            Some("login") => Ok(json!({ "sid": "s1" })),
            _ => Ok(json!({})),
        });
        let (on_did, _) = did_log();
        let s = Session::new(fake.clone(), creds(None), on_did);
        s.call(UTILIZATION, "get", &[]).await.unwrap();
        s.logout().await;
        let last = fake.requests().pop().unwrap();
        assert_eq!(get(&last, "method").as_deref(), Some("logout"));
        assert_eq!(get(&last, "_sid").as_deref(), Some("s1"));
    }

    #[test]
    fn debug_output_hides_secrets() {
        let text = format!("{:?}", creds(Some("dev-1")));
        assert!(!text.contains("p&ss") && !text.contains("dev-1"), "{text}");
    }
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cargo test dsm::session`
Expected: compile errors.

- [ ] **Step 4: Implement above the tests**

```rust
//! One DSM login shared by every poller.
//!
//! - A single async `Mutex` around the session state serialises logins:
//!   when several pollers find the session expired at once, the first logs
//!   in again and the rest reuse its sid (they see a newer `generation`).
//! - Credential failures are remembered (`blocked`) and returned without
//!   contacting DSM until the settings change or a 2FA code is submitted -
//!   retrying a wrong password is what trips DSM's auto-block.

use crate::dsm::api::{AUTH, ApiInfo, ApiMap, discover};
use crate::dsm::error::{AuthError, DsmError};
use crate::dsm::transport::Transport;
use serde_json::Value;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

/// DSM lists sessions by this name (Control Panel › Security › Account activity).
pub const SESSION_NAME: &str = "OpenDeck";

/// Codes meaning "your session is gone", worth one silent re-login.
const SESSION_LOST: [i64; 3] = [106, 107, 119];
/// "No permission" - also what a just-expired session can look like, so it
/// gets one re-login before being believed.
const NO_PERMISSION: i64 = 105;
/// DSM's "API does not exist".
const NO_SUCH_API: i64 = 102;

#[derive(Clone)]
pub struct Credentials {
    pub account: String,
    pub password: String,
    /// 2FA device token from an earlier OTP login.
    pub did: Option<String>,
    /// How this device appears in DSM's trusted-device list.
    pub device_name: String,
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("account", &self.account)
            .field("password", &"<redacted>")
            .field("did", &self.did.as_ref().map(|_| "<redacted>"))
            .field("device_name", &self.device_name)
            .finish()
    }
}

/// Told about a new device token (`Some`) or one DSM stopped honouring (`None`).
pub type DidListener = Arc<dyn Fn(Option<String>) + Send + Sync>;

struct State {
    apis: Option<Arc<ApiMap>>,
    sid: Option<String>,
    generation: u64,
    blocked: Option<AuthError>,
    creds: Credentials,
}

pub struct Session {
    transport: Arc<dyn Transport>,
    state: Mutex<State>,
    on_did: DidListener,
}

impl Session {
    pub fn new(transport: Arc<dyn Transport>, creds: Credentials, on_did: DidListener) -> Self {
        Self {
            transport,
            state: Mutex::new(State { apis: None, sid: None, generation: 0, blocked: None, creds }),
            on_did,
        }
    }

    /// Calls `api`.`method` with the current session, logging in first if
    /// needed and once more if DSM says the session is gone.
    pub async fn call(&self, api: &str, method: &str, params: &[(&str, &str)]) -> Result<Value, DsmError> {
        let (apis, sid, generation) = self.ensure_login().await?;
        let info = apis.get(api).ok_or_else(|| DsmError::Api { api: api.into(), code: NO_SUCH_API })?;
        match self.request(info, api, method, &sid, params).await? {
            Ok(data) => return Ok(data),
            Err(code) if SESSION_LOST.contains(&code) || code == NO_PERMISSION => {}
            Err(code) => return Err(DsmError::Api { api: api.into(), code }),
        }
        let sid = self.relogin(generation).await?;
        match self.request(info, api, method, &sid, params).await? {
            Ok(data) => Ok(data),
            Err(NO_PERMISSION) => Err(DsmError::Permission { api: api.into() }),
            Err(code) => Err(DsmError::Api { api: api.into(), code }),
        }
    }

    /// Logs in with a 2FA code, asking DSM to remember this device; the new
    /// device token goes to `on_did` for safekeeping.
    pub async fn submit_otp(&self, code: &str) -> Result<(), DsmError> {
        let mut st = self.state.lock().await;
        match st.blocked.take() {
            None | Some(AuthError::NeedOtp | AuthError::BadOtp) => {}
            Some(other) => {
                st.blocked = Some(other); // a code can't fix a wrong password
                return Err(other.into());
            }
        }
        self.discover_once(&mut st).await?;
        self.login(&mut st, Some(code)).await
    }

    /// Best effort; never takes more than a second.
    pub async fn logout(&self) {
        let _ = tokio::time::timeout(Duration::from_secs(1), async {
            let st = self.state.lock().await;
            let (Some(apis), Some(sid)) = (&st.apis, &st.sid) else { return };
            let Some(info) = apis.get(AUTH) else { return };
            let version = info.version.to_string();
            let form = [
                ("api", AUTH),
                ("version", version.as_str()),
                ("method", "logout"),
                ("session", SESSION_NAME),
                ("_sid", sid.as_str()),
            ];
            let _ = self.transport.call(&info.path, &form).await;
        })
        .await;
    }

    async fn request(
        &self,
        info: &ApiInfo,
        api: &str,
        method: &str,
        sid: &str,
        params: &[(&str, &str)],
    ) -> Result<Result<Value, i64>, DsmError> {
        let version = info.version.to_string();
        let mut form = vec![("api", api), ("version", version.as_str()), ("method", method), ("_sid", sid)];
        form.extend_from_slice(params);
        self.transport.call(&info.path, &form).await
    }

    async fn discover_once(&self, st: &mut State) -> Result<(), DsmError> {
        if st.apis.is_none() {
            st.apis = Some(Arc::new(discover(self.transport.as_ref()).await?));
        }
        Ok(())
    }

    /// (apis, sid, generation), logging in first if there is no session.
    async fn ensure_login(&self) -> Result<(Arc<ApiMap>, String, u64), DsmError> {
        let mut st = self.state.lock().await;
        if let Some(e) = st.blocked {
            return Err(e.into());
        }
        self.discover_once(&mut st).await?;
        if st.sid.is_none() {
            self.login(&mut st, None).await?;
        }
        let apis = st.apis.clone().expect("discovered above");
        let sid = st.sid.clone().expect("logged in above");
        Ok((apis, sid, st.generation))
    }

    /// Replaces the session the caller saw expire - unless another caller
    /// already did (the generation moved on), in which case its sid is reused.
    async fn relogin(&self, seen_generation: u64) -> Result<String, DsmError> {
        let mut st = self.state.lock().await;
        if let Some(e) = st.blocked {
            return Err(e.into());
        }
        if st.generation == seen_generation || st.sid.is_none() {
            st.sid = None;
            self.login(&mut st, None).await?;
        }
        Ok(st.sid.clone().expect("logged in above"))
    }

    async fn login(&self, st: &mut State, otp: Option<&str>) -> Result<(), DsmError> {
        let apis = st.apis.clone().expect("discover before login");
        let info = apis.get(AUTH).expect("discover guarantees SYNO.API.Auth");
        let version = info.version.to_string();
        let c = st.creds.clone();
        let mut form = vec![
            ("api", AUTH),
            ("version", version.as_str()),
            ("method", "login"),
            ("account", c.account.as_str()),
            ("passwd", c.password.as_str()),
            ("session", SESSION_NAME),
            ("format", "sid"),
        ];
        match (otp, c.did.as_deref()) {
            (Some(code), _) => form.extend([
                ("otp_code", code),
                ("enable_device_token", "yes"),
                ("device_name", c.device_name.as_str()),
            ]),
            (None, Some(did)) => form.extend([("device_id", did), ("device_name", c.device_name.as_str())]),
            (None, None) => {}
        }
        match self.transport.call(&info.path, &form).await? {
            Ok(data) => {
                let sid = data["sid"].as_str().filter(|s| !s.is_empty()).ok_or_else(|| DsmError::Parse {
                    api: AUTH.into(),
                    detail: "login returned no session id".into(),
                })?;
                st.sid = Some(sid.to_string());
                st.generation += 1;
                if otp.is_some()
                    && let Some(did) = data["did"].as_str().filter(|d| !d.is_empty())
                {
                    st.creds.did = Some(did.to_string());
                    (self.on_did)(Some(did.to_string()));
                }
                Ok(())
            }
            Err(code) => {
                let Some(err) = AuthError::from_login_code(code) else {
                    return Err(DsmError::Api { api: AUTH.into(), code });
                };
                if err == AuthError::NeedOtp && st.creds.did.take().is_some() {
                    // DSM no longer honours the stored device token.
                    (self.on_did)(None);
                }
                st.sid = None;
                st.blocked = Some(err);
                Err(err.into())
            }
        }
    }
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test dsm::session`
Expected: PASS (10 tests).

Run: `cargo fmt && cargo clippy --all-targets -- -D warnings`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add src/dsm
git commit -m "feat: add the DSM session with 2FA device tokens and single-flight re-login

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---
### Task 11: Secret store (system keyring)

**Files:**
- Create: `src/secrets.rs`
- Modify: `src/main.rs` (add `mod secrets;`)

**Interfaces:**
- Consumes: nothing
- Produces:
  - `secrets::SecretStore` trait (`Send + Sync`), with `get(&self, key: &str) -> Result<Option<String>, String>` and `set(&self, key: &str, value: Option<&str>) -> Result<(), String>`. `set` with `None` deletes. Both are blocking: call them through `spawn_blocking`.
  - `secrets::KeyringStore` (the Secret Service keyring, service name `com.jfms7s.synology`)
  - `secrets::{password_key(scope: &str) -> String, did_key(scope: &str) -> String}`
  - test-only `secrets::MemoryStore` (`Default`) and `MemoryStore::broken()`

- [ ] **Step 1: Write the failing tests**

`src/secrets.rs` (tests only):
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_scoped_per_account_and_host() {
        assert_eq!(password_key("jf@nas.lan"), "jf@nas.lan/password");
        assert_eq!(did_key("jf@nas.lan"), "jf@nas.lan/did");
    }

    #[test]
    fn memory_store_round_trips_and_deletes() {
        let s = MemoryStore::default();
        assert_eq!(s.get("k"), Ok(None));
        s.set("k", Some("v")).unwrap();
        assert_eq!(s.get("k"), Ok(Some("v".into())));
        s.set("k", None).unwrap();
        assert_eq!(s.get("k"), Ok(None));
    }

    #[test]
    fn a_broken_store_errors() {
        let s = MemoryStore::broken();
        assert!(s.get("k").is_err());
        assert!(s.set("k", Some("v")).is_err());
    }

    /// Talks to the real Secret Service. Run by hand on a desktop session:
    /// `cargo test keyring_round_trip -- --ignored`
    #[test]
    #[ignore]
    fn keyring_round_trip() {
        let s = KeyringStore;
        let key = "test/opendeck-synology-roundtrip";
        s.set(key, Some("secret")).unwrap();
        assert_eq!(s.get(key), Ok(Some("secret".into())));
        s.set(key, None).unwrap();
        assert_eq!(s.get(key), Ok(None));
    }
}
```

Add `mod secrets;` to `src/main.rs`.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test secrets::`
Expected: compile errors.

- [ ] **Step 3: Implement above the tests**

```rust
//! Where the password and the 2FA device token live: the system keyring
//! (Secret Service), keeping them out of OpenDeck's plain-JSON settings file.

pub const SERVICE: &str = "com.jfms7s.synology";

/// Blocking key-value secret storage. Call through `spawn_blocking`.
pub trait SecretStore: Send + Sync {
    /// `Ok(None)`: no such secret. `Err`: no usable keyring at all.
    fn get(&self, key: &str) -> Result<Option<String>, String>;
    /// `None` deletes (deleting a missing secret is not an error).
    fn set(&self, key: &str, value: Option<&str>) -> Result<(), String>;
}

pub fn password_key(scope: &str) -> String {
    format!("{scope}/password")
}

pub fn did_key(scope: &str) -> String {
    format!("{scope}/did")
}

pub struct KeyringStore;

impl SecretStore for KeyringStore {
    fn get(&self, key: &str) -> Result<Option<String>, String> {
        let entry = keyring::Entry::new(SERVICE, key).map_err(|e| e.to_string())?;
        match entry.get_password() {
            Ok(v) => Ok(Some(v)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }

    fn set(&self, key: &str, value: Option<&str>) -> Result<(), String> {
        let entry = keyring::Entry::new(SERVICE, key).map_err(|e| e.to_string())?;
        match value {
            Some(v) => entry.set_password(v).map_err(|e| e.to_string()),
            None => match entry.delete_credential() {
                Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
                Err(e) => Err(e.to_string()),
            },
        }
    }
}

#[cfg(test)]
#[derive(Default)]
pub struct MemoryStore {
    map: std::sync::Mutex<std::collections::HashMap<String, String>>,
    broken: bool,
}

#[cfg(test)]
impl MemoryStore {
    /// Behaves like a machine without a usable keyring.
    pub fn broken() -> Self {
        Self { broken: true, ..Self::default() }
    }
}

#[cfg(test)]
impl SecretStore for MemoryStore {
    fn get(&self, key: &str) -> Result<Option<String>, String> {
        if self.broken {
            return Err("no keyring".into());
        }
        Ok(self.map.lock().unwrap().get(key).cloned())
    }

    fn set(&self, key: &str, value: Option<&str>) -> Result<(), String> {
        if self.broken {
            return Err("no keyring".into());
        }
        let mut map = self.map.lock().unwrap();
        match value {
            Some(v) => map.insert(key.to_string(), v.to_string()),
            None => map.remove(key),
        };
        Ok(())
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test secrets::`
Expected: PASS (3 tests, 1 ignored).

Run the ignored keyring test once by hand on the desktop session: `cargo test keyring_round_trip -- --ignored`
Expected: PASS. If it fails with a D-Bus or "platform failure" error, record the message in the task report. The plugin still works through the settings-file fallback (Task 12), but the README should mention it.

Run: `cargo fmt && cargo clippy --all-targets -- -D warnings`
Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add src/secrets.rs src/main.rs
git commit -m "feat: store the DSM password and device token in the system keyring

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 12: Services: connection, secrets, session and pollers wired together

**Files:**
- Create: `src/services.rs`
- Modify: `src/main.rs` (add `mod services;`)

**Interfaces:**
- Consumes:
  - `settings::*` and `status::ConnStatus` (Task 4)
  - `metric::Endpoint` (Task 4)
  - `poller::{Poller, Fetch}` (Task 5)
  - `dsm::model::*` (Task 3)
  - `dsm::api::{UTILIZATION, SYSTEM, STORAGE, UPGRADE}` (Task 9)
  - `dsm::transport::Transport` (Task 9)
  - `dsm::session::{Session, Credentials, DidListener}` (Task 10)
  - `secrets::*` (Task 11)
  - test-only `dsm::fake::FakeDsm` (Task 10)
- Produces:
  - `services::SettingsSink` async trait, with `save(&self, &GlobalSettings)`
  - `services::TransportFactory = Arc<dyn Fn(&Connection) -> Result<Arc<dyn Transport>, DsmError> + Send + Sync>`
  - `services::Services`:
    - `new(secrets: Arc<dyn SecretStore>, sink: Arc<dyn SettingsSink>, transports: TransportFactory, device_name: String) -> Arc<Services>`
    - `poller(&self, Endpoint) -> &Poller<Payload>`
    - `status(&self) -> watch::Receiver<ConnStatus>`
    - `current_status(&self) -> ConnStatus`
    - `global(&self) -> GlobalSettings`
    - `has_password(&self) -> bool`
    - `load_global(self: &Arc<Self>, GlobalSettings)`
    - `save_connection(self: &Arc<Self>, Connection, password: Option<String>)`
    - `set_temp_unit(self: &Arc<Self>, TempUnit)`
    - `submit_otp(&self, code: &str) -> Result<(), DsmError>`
    - `trust_certificate(self: &Arc<Self>)`
    - `logout(&self)`
  - `services::fetch_endpoint(&Session, Endpoint) -> Result<Payload, DsmError>`
  - test-only `services::testing::{RecordingSink, services_with(fake: Arc<FakeDsm>, secrets: Arc<MemoryStore>) -> (Arc<Services>, Arc<RecordingSink>), healthy_nas() -> Arc<FakeDsm>, conn() -> Connection}`

- [ ] **Step 1: Write the failing tests**

`src/services.rs` (the test support module and the tests, for now):
```rust
#[cfg(test)]
pub mod testing {
    use super::*;
    use crate::dsm::fake::FakeDsm;
    use crate::secrets::MemoryStore;
    use serde_json::json;

    #[derive(Default)]
    pub struct RecordingSink(pub Mutex<Vec<GlobalSettings>>);

    impl RecordingSink {
        pub fn last(&self) -> GlobalSettings {
            self.0.lock().unwrap().last().cloned().expect("nothing saved")
        }
    }

    #[async_trait]
    impl SettingsSink for RecordingSink {
        async fn save(&self, s: &GlobalSettings) {
            self.0.lock().unwrap().push(s.clone());
        }
    }

    pub fn services_with(fake: Arc<FakeDsm>, secrets: Arc<MemoryStore>) -> (Arc<Services>, Arc<RecordingSink>) {
        let sink = Arc::new(RecordingSink::default());
        let transports: TransportFactory = Arc::new(move |_| Ok(fake.clone() as Arc<dyn Transport>));
        (Services::new(secrets, sink.clone(), transports, "OpenDeck-test".into()), sink)
    }

    fn fixture(name: &str) -> Value {
        let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    /// A NAS without 2FA that answers every endpoint from the fixtures.
    pub fn healthy_nas() -> Arc<FakeDsm> {
        FakeDsm::new(|r| match r.get("method").map(String::as_str) {
            Some("login") => Ok(json!({ "sid": "s1" })),
            Some("get") => Ok(fixture("utilization.json")),
            Some("info") => Ok(fixture("system.json")),
            Some("load_info") => Ok(fixture("storage.json")),
            Some("check") => Ok(fixture("update.json")),
            _ => Ok(json!({})),
        })
    }

    pub fn conn() -> Connection {
        Connection { host: "nas.lan".into(), account: "jf".into(), ..Connection::default() }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;
    use crate::dsm::error::AuthError;
    use crate::dsm::fake::FakeDsm;
    use crate::secrets::{MemoryStore, did_key, password_key};
    use serde_json::json;
    use std::time::Duration;

    async fn wait_for(s: &Services, want: impl Fn(&ConnStatus) -> bool) {
        let mut rx = s.status();
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if want(&rx.borrow_and_update()) {
                    return;
                }
                rx.changed().await.unwrap();
            }
        })
        .await
        .unwrap_or_else(|_| panic!("status stuck at {:?}", s.current_status()));
    }

    fn connected(s: &ConnStatus) -> bool {
        matches!(s, ConnStatus::Connected { .. })
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn starts_unconfigured() {
        let (s, _) = services_with(healthy_nas(), Arc::new(MemoryStore::default()));
        s.load_global(GlobalSettings::default()).await;
        assert_eq!(s.current_status(), ConnStatus::NotConfigured);
        assert!(!s.has_password());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn saving_a_connection_keeps_the_password_out_of_the_settings_file() {
        let secrets = Arc::new(MemoryStore::default());
        let (s, sink) = services_with(healthy_nas(), secrets.clone());
        s.load_global(GlobalSettings::default()).await;
        s.save_connection(conn(), Some("pw".into())).await;
        assert_eq!(secrets.get(&password_key("jf@nas.lan")), Ok(Some("pw".into())));
        assert_eq!(sink.last().fallback_secrets, None);
        assert!(s.has_password());
        let _rx = s.poller(Endpoint::Utilization).subscribe("key-1", None);
        wait_for(&s, connected).await;
        assert!(s.poller(Endpoint::Utilization).latest().value.is_some());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn without_a_keyring_secrets_fall_back_to_the_settings_file() {
        let (s, sink) = services_with(healthy_nas(), Arc::new(MemoryStore::broken()));
        s.load_global(GlobalSettings::default()).await;
        s.save_connection(conn(), Some("pw".into())).await;
        assert_eq!(sink.last().fallback_secrets.and_then(|f| f.password), Some("pw".into()));
        let _rx = s.poller(Endpoint::SystemInfo).subscribe("key-1", None);
        wait_for(&s, connected).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_new_host_drops_the_certificate_pin() {
        let (s, _) = services_with(healthy_nas(), Arc::new(MemoryStore::default()));
        let mut g = GlobalSettings::default();
        g.connection = Connection { pinned_sha256: Some("ab".into()), ..conn() };
        s.load_global(g).await;
        s.save_connection(conn(), None).await;
        assert_eq!(s.global().connection.pinned_sha256.as_deref(), Some("ab"), "same NAS keeps it");
        s.save_connection(Connection { host: "other.lan".into(), ..conn() }, None).await;
        assert_eq!(s.global().connection.pinned_sha256, None);
    }

    /// Refuses the certificate until one is pinned.
    struct UntrustedCert;
    #[async_trait]
    impl Transport for UntrustedCert {
        async fn call(&self, _: &str, _: &[(&str, &str)]) -> Result<Result<Value, i64>, DsmError> {
            Err(DsmError::CertificateNotTrusted { fingerprint: "ab".into() })
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn trusting_the_certificate_pins_it_and_reconnects() {
        let sink = Arc::new(RecordingSink::default());
        let nas = healthy_nas();
        let transports: TransportFactory = Arc::new(move |c: &Connection| match c.pinned_sha256 {
            None => Ok(Arc::new(UntrustedCert) as Arc<dyn Transport>),
            Some(_) => Ok(nas.clone() as Arc<dyn Transport>),
        });
        let s = Services::new(Arc::new(MemoryStore::default()), sink.clone(), transports, "t".into());
        s.load_global(GlobalSettings::default()).await;
        s.save_connection(conn(), Some("pw".into())).await;
        let _rx = s.poller(Endpoint::Utilization).subscribe("key-1", None);
        wait_for(&s, |st| matches!(st, ConnStatus::Certificate { changed: false, .. })).await;
        s.trust_certificate().await;
        assert_eq!(sink.last().connection.pinned_sha256.as_deref(), Some("ab"));
        wait_for(&s, connected).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_2fa_code_connects_and_stores_the_device_token() {
        let nas = FakeDsm::new(|r| match (r.get("method").map(String::as_str), r.get("otp_code")) {
            (Some("login"), Some(_)) => Ok(json!({ "sid": "s1", "did": "dev-1" })),
            (Some("login"), None) => Err(403),
            _ => Ok(serde_json::from_str(include_str!("../tests/fixtures/utilization.json")).unwrap()),
        });
        let secrets = Arc::new(MemoryStore::default());
        let (s, _) = services_with(nas, secrets.clone());
        s.load_global(GlobalSettings::default()).await;
        s.save_connection(conn(), Some("pw".into())).await;
        let _rx = s.poller(Endpoint::Utilization).subscribe("key-1", None);
        wait_for(&s, |st| *st == ConnStatus::Auth(AuthError::NeedOtp)).await;
        s.submit_otp("123456").await.unwrap();
        wait_for(&s, connected).await;
        tokio::time::timeout(Duration::from_secs(5), async {
            while secrets.get(&did_key("jf@nas.lan")) != Ok(Some("dev-1".into())) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("device token stored in the keyring");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn changing_the_unit_saves_and_redraws() {
        let (s, sink) = services_with(healthy_nas(), Arc::new(MemoryStore::default()));
        s.load_global(GlobalSettings::default()).await;
        let mut rx = s.status();
        rx.borrow_and_update();
        s.set_temp_unit(TempUnit::Fahrenheit).await;
        assert_eq!(sink.last().temp_unit, TempUnit::Fahrenheit);
        assert!(rx.has_changed().unwrap(), "render loops are woken to redraw");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn reloading_identical_settings_does_not_reconnect() {
        let nas = healthy_nas();
        let (s, _) = services_with(nas.clone(), Arc::new(MemoryStore::default()));
        s.load_global(GlobalSettings::default()).await;
        s.save_connection(conn(), Some("pw".into())).await;
        let _rx = s.poller(Endpoint::Utilization).subscribe("key-1", None);
        wait_for(&s, connected).await;
        s.load_global(s.global()).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(nas.count("login"), 1);
    }
}
```

Add `mod services;` to `src/main.rs`.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test services::`
Expected: compile errors.

- [ ] **Step 3: Implement above the test modules**

```rust
//! The plugin's shared state: the connection settings, the one DSM
//! session, the four endpoint pollers every key and dial subscribes to, and
//! the connection status they all watch.

use crate::dsm::api::{STORAGE, SYSTEM, UPGRADE, UTILIZATION};
use crate::dsm::error::DsmError;
use crate::dsm::model::{self, Payload};
use crate::dsm::session::{Credentials, DidListener, Session};
use crate::dsm::transport::Transport;
use crate::metric::Endpoint;
use crate::poller::{Fetch, Poller};
use crate::secrets::{SecretStore, did_key, password_key};
use crate::settings::{Connection, FallbackSecrets, GlobalSettings, TempUnit};
use crate::status::ConnStatus;
use async_trait::async_trait;
use serde_json::Value;
use std::sync::atomic::{AtomicBool, Ordering::SeqCst};
use std::sync::{Arc, Mutex};
use tokio::sync::watch;

#[async_trait]
pub trait SettingsSink: Send + Sync {
    /// Persists the plugin-wide settings (OpenDeck's `setGlobalSettings`).
    async fn save(&self, settings: &GlobalSettings);
}

pub type TransportFactory = Arc<dyn Fn(&Connection) -> Result<Arc<dyn Transport>, DsmError> + Send + Sync>;

#[derive(Debug, Clone, Copy)]
enum Secret {
    Password,
    Did,
}

pub struct Services {
    utilization: Poller<Payload>,
    system: Poller<Payload>,
    storage: Poller<Payload>,
    update: Poller<Payload>,
    global: Mutex<GlobalSettings>,
    loaded: AtomicBool,
    session: Mutex<Option<Arc<Session>>>,
    has_password: AtomicBool,
    status: watch::Sender<ConnStatus>,
    secrets: Arc<dyn SecretStore>,
    sink: Arc<dyn SettingsSink>,
    transports: TransportFactory,
    device_name: String,
}

impl Services {
    pub fn new(
        secrets: Arc<dyn SecretStore>,
        sink: Arc<dyn SettingsSink>,
        transports: TransportFactory,
        device_name: String,
    ) -> Arc<Self> {
        let poller = |e: Endpoint| Poller::new(e.default_interval());
        Arc::new(Self {
            utilization: poller(Endpoint::Utilization),
            system: poller(Endpoint::SystemInfo),
            storage: poller(Endpoint::Storage),
            update: poller(Endpoint::Update),
            global: Mutex::new(GlobalSettings::default()),
            loaded: AtomicBool::new(false),
            session: Mutex::new(None),
            has_password: AtomicBool::new(false),
            // Until OpenDeck hands over the saved settings, keys show "…".
            status: watch::Sender::new(ConnStatus::Connecting),
            secrets,
            sink,
            transports,
            device_name,
        })
    }

    pub fn poller(&self, e: Endpoint) -> &Poller<Payload> {
        match e {
            Endpoint::Utilization => &self.utilization,
            Endpoint::SystemInfo => &self.system,
            Endpoint::Storage => &self.storage,
            Endpoint::Update => &self.update,
        }
    }

    pub fn status(&self) -> watch::Receiver<ConnStatus> {
        self.status.subscribe()
    }

    pub fn current_status(&self) -> ConnStatus {
        self.status.borrow().clone()
    }

    pub fn global(&self) -> GlobalSettings {
        self.global.lock().unwrap().clone()
    }

    pub fn has_password(&self) -> bool {
        self.has_password.load(SeqCst)
    }

    /// Adopts settings loaded from OpenDeck, at startup or when they change.
    pub async fn load_global(self: &Arc<Self>, g: GlobalSettings) {
        let unchanged = {
            let mut cur = self.global.lock().unwrap();
            let same = *cur == g;
            *cur = g;
            same
        };
        if self.loaded.swap(true, SeqCst) && unchanged {
            return;
        }
        self.reconnect().await;
    }

    /// Saves the connection block of the settings panel. `password: None`
    /// keeps the stored password.
    pub async fn save_connection(self: &Arc<Self>, mut conn: Connection, password: Option<String>) {
        let mut g = self.global();
        // Another NAS has another certificate: the old pin must not carry over.
        let same_nas = conn.host() == g.connection.host() && conn.port == g.connection.port;
        conn.pinned_sha256 = if same_nas { g.connection.pinned_sha256.clone() } else { None };
        g.connection = conn;
        if let Some(pw) = password {
            self.put_secret(&mut g, Secret::Password, Some(pw)).await;
        }
        self.persist(g).await;
        self.reconnect().await;
    }

    pub async fn set_temp_unit(self: &Arc<Self>, unit: TempUnit) {
        let mut g = self.global();
        g.temp_unit = unit;
        self.persist(g).await;
        // Nothing about the connection changed, but every key must redraw.
        self.status.send_modify(|_| {});
    }

    pub async fn submit_otp(&self, code: &str) -> Result<(), DsmError> {
        let session = self.session.lock().unwrap().clone().ok_or(DsmError::NotConfigured)?;
        let result = session.submit_otp(code).await;
        match &result {
            Ok(()) => {
                self.set_status(ConnStatus::Connecting);
                for e in Endpoint::ALL {
                    self.poller(e).refresh_now();
                }
            }
            Err(e) => {
                if let Some(s) = ConnStatus::from_error(e) {
                    self.set_status(s);
                }
            }
        }
        result
    }

    /// Pins the certificate the last failed handshake presented.
    pub async fn trust_certificate(self: &Arc<Self>) {
        let ConnStatus::Certificate { fingerprint, .. } = self.current_status() else { return };
        let mut g = self.global();
        g.connection.pinned_sha256 = Some(fingerprint);
        self.persist(g).await;
        self.reconnect().await;
    }

    pub async fn logout(&self) {
        let session = self.session.lock().unwrap().clone();
        if let Some(s) = session {
            s.logout().await;
        }
    }

    async fn persist(&self, g: GlobalSettings) {
        *self.global.lock().unwrap() = g.clone();
        self.sink.save(&g).await;
    }

    fn set_status(&self, next: ConnStatus) {
        self.status.send_if_modified(|cur| {
            let changed = *cur != next;
            *cur = next;
            changed
        });
    }

    /// Replaces the session and points every poller at it.
    async fn reconnect(self: &Arc<Self>) {
        let old = self.session.lock().unwrap().take();
        if let Some(old) = old {
            tokio::spawn(async move { old.logout().await });
        }
        let g = self.global();
        let password = self.read_secret(&g, Secret::Password).await.filter(|p| !p.is_empty());
        self.has_password.store(password.is_some(), SeqCst);
        let Some(password) = password.filter(|_| g.connection.is_complete()) else {
            return self.go_idle(ConnStatus::NotConfigured);
        };
        let transport = match (self.transports)(&g.connection) {
            Ok(t) => t,
            Err(e) => {
                let status = ConnStatus::from_error(&e).unwrap_or_else(|| ConnStatus::Unreachable(e.to_string()));
                return self.go_idle(status);
            }
        };
        let creds = Credentials {
            account: g.connection.account.trim().to_string(),
            password,
            did: self.read_secret(&g, Secret::Did).await,
            device_name: self.device_name.clone(),
        };
        let session = Arc::new(Session::new(transport, creds, self.did_listener()));
        *self.session.lock().unwrap() = Some(session.clone());
        self.set_status(ConnStatus::Connecting);
        for e in Endpoint::ALL {
            self.poller(e).set_fetch(Some(self.fetch_for(e, &session)));
        }
    }

    fn go_idle(&self, status: ConnStatus) {
        self.set_status(status);
        for e in Endpoint::ALL {
            self.poller(e).set_fetch(None);
        }
    }

    fn fetch_for(self: &Arc<Self>, e: Endpoint, session: &Arc<Session>) -> Fetch<Payload> {
        let this = Arc::downgrade(self);
        let session = session.clone();
        Arc::new(move || {
            let (this, session) = (this.clone(), session.clone());
            Box::pin(async move {
                let result = fetch_endpoint(&session, e).await;
                if let Some(s) = this.upgrade() {
                    s.observe(&session, &result);
                }
                result
            })
        })
    }

    /// Updates the connection status from a poll result - unless it came
    /// from a session that has since been replaced.
    fn observe(&self, session: &Arc<Session>, result: &Result<Payload, DsmError>) {
        let current = self.session.lock().unwrap().as_ref().is_some_and(|s| Arc::ptr_eq(s, session));
        if !current {
            return;
        }
        let next = match result {
            Ok(_) => ConnStatus::Connected { account: self.global().connection.account.trim().to_string() },
            Err(e) => match ConnStatus::from_error(e) {
                Some(s) => s,
                None => return,
            },
        };
        self.set_status(next);
    }

    fn did_listener(self: &Arc<Self>) -> DidListener {
        let this = Arc::downgrade(self);
        Arc::new(move |did| {
            if let Some(s) = this.upgrade() {
                tokio::spawn(async move { s.store_did(did).await });
            }
        })
    }

    async fn store_did(&self, did: Option<String>) {
        let mut g = self.global();
        let before = g.clone();
        self.put_secret(&mut g, Secret::Did, did).await;
        if g != before {
            self.persist(g).await;
        }
    }

    fn secret_key(g: &GlobalSettings, which: Secret) -> String {
        let scope = g.connection.secret_scope();
        match which {
            Secret::Password => password_key(&scope),
            Secret::Did => did_key(&scope),
        }
    }

    async fn read_secret(&self, g: &GlobalSettings, which: Secret) -> Option<String> {
        let key = Self::secret_key(g, which);
        let store = self.secrets.clone();
        let from_keyring = tokio::task::spawn_blocking(move || store.get(&key)).await.ok().and_then(Result::ok).flatten();
        from_keyring.or_else(|| {
            let f = g.fallback_secrets.as_ref()?;
            match which {
                Secret::Password => f.password.clone(),
                Secret::Did => f.did.clone(),
            }
        })
    }

    /// Stores (or with `None`, deletes) a secret in the keyring, falling back
    /// to the settings file - with a warning - when there is no keyring.
    async fn put_secret(&self, g: &mut GlobalSettings, which: Secret, value: Option<String>) {
        let key = Self::secret_key(g, which);
        let store = self.secrets.clone();
        let v = value.clone();
        let result = tokio::task::spawn_blocking(move || store.set(&key, v.as_deref()))
            .await
            .unwrap_or_else(|e| Err(e.to_string()));
        let fallback = g.fallback_secrets.get_or_insert_with(FallbackSecrets::default);
        let slot = match which {
            Secret::Password => &mut fallback.password,
            Secret::Did => &mut fallback.did,
        };
        match result {
            Ok(()) => *slot = None,
            Err(e) => {
                log::warn!("no usable system keyring ({e}); keeping the {which:?} in OpenDeck's settings file");
                *slot = value;
            }
        }
        if g.fallback_secrets == Some(FallbackSecrets::default()) {
            g.fallback_secrets = None;
        }
    }
}

pub async fn fetch_endpoint(session: &Session, e: Endpoint) -> Result<Payload, DsmError> {
    let (api, method) = match e {
        Endpoint::Utilization => (UTILIZATION, "get"),
        Endpoint::SystemInfo => (SYSTEM, "info"),
        Endpoint::Storage => (STORAGE, "load_info"),
        Endpoint::Update => (UPGRADE, "check"),
    };
    let data = session.call(api, method, &[]).await?;
    parse_payload(e, &data).map_err(|detail| DsmError::Parse { api: api.into(), detail })
}

fn parse_payload(e: Endpoint, data: &Value) -> Result<Payload, String> {
    match e {
        Endpoint::Utilization => model::parse_utilization(data).map(Payload::Utilization),
        Endpoint::SystemInfo => model::parse_system_info(data).map(Payload::SystemInfo),
        Endpoint::Storage => model::parse_storage(data).map(Payload::Storage),
        Endpoint::Update => model::parse_update(data).map(Payload::Update),
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test services::`
Expected: PASS (8 tests).

Run: `cargo fmt && cargo clippy --all-targets -- -D warnings`
Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add src/services.rs src/main.rs
git commit -m "feat: wire connection settings, keyring secrets, session and pollers together

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---
### Task 13: Rendering: key images and dial feedback

**Files:**
- Create: `src/render/mod.rs`, `src/render/glyphs.rs`, `src/render/key.rs`, `src/render/dial.rs`, `assets/layouts/metric.json`
- Modify: `src/main.rs` (add `mod render;`)

**Interfaces:**
- Consumes:
  - `metrics::{Reading, Level}` (Task 7)
  - `metric::Metric` (Task 4)
- Produces:
  - `render::{background(Level) -> &'static str, accent(Level) -> &'static str, TEXT, MUTED}`
  - `render::glyphs::{paths(Metric) -> &'static str, svg(Metric) -> String}`
  - `render::key::{key_svg(Metric, &Reading) -> String, key_image(Metric, &Reading) -> String}` (the image is a `data:image/svg+xml;base64,` URI)
  - `render::dial::{feedback(Metric, &Reading) -> serde_json::Value, subject_line(&Reading) -> String}`
  - layout file `assets/layouts/metric.json`, with item keys `icon`, `title`, `value`, `bar`, `subject`

- [ ] **Step 1: Write the dial layout**

`assets/layouts/metric.json`:
```json
{
	"$schema": "https://schemas.elgato.com/streamdeck/plugins/layout.json",
	"id": "com.jfms7s.synology.metric-layout",
	"items": [
		{ "key": "icon", "type": "pixmap", "rect": [10, 6, 20, 20] },
		{
			"key": "title",
			"type": "text",
			"rect": [36, 4, 156, 24],
			"alignment": "left",
			"color": "#d1d5db",
			"value": "",
			"font": { "size": 14, "weight": 600 }
		},
		{
			"key": "value",
			"type": "text",
			"rect": [4, 28, 192, 32],
			"alignment": "center",
			"color": "white",
			"value": "--",
			"font": { "size": 24, "weight": 700 }
		},
		{
			"key": "bar",
			"type": "bar",
			"rect": [16, 62, 168, 10],
			"value": 0,
			"bar_bg_c": "#374151",
			"bar_fill_c": "#22c55e",
			"bar_border_c": "#111827",
			"border_w": 1,
			"subtype": 0
		},
		{
			"key": "subject",
			"type": "text",
			"rect": [0, 76, 200, 22],
			"alignment": "center",
			"color": "#d1d5db",
			"value": "",
			"font": { "size": 13, "weight": 500 }
		}
	]
}
```

- [ ] **Step 2: Write the failing tests**

`src/render/key.rs` (tests only):
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;

    fn reading(level: Level) -> Reading {
        Reading {
            title: "Disk",
            value: "44°C".into(),
            subject: "Drive <2> & co".into(),
            level,
            bar: Some(44.0),
            pager: None,
        }
    }

    #[test]
    fn draws_title_value_and_escaped_subject() {
        let svg = key_svg(Metric::DiskTemp, &reading(Level::Normal));
        assert!(svg.contains(">Disk</text>"), "{svg}");
        assert!(svg.contains(">44°C</text>"), "{svg}");
        assert!(svg.contains(">Drive &lt;2&gt; &amp; co</text>"), "{svg}");
    }

    #[test]
    fn background_follows_the_level_and_problems_get_a_badge() {
        let normal = key_svg(Metric::Cpu, &reading(Level::Normal));
        assert!(normal.contains(&format!(r#"fill="{}""#, background(Level::Normal))));
        assert!(!normal.contains("<circle"));
        let crit = key_svg(Metric::Cpu, &reading(Level::Crit));
        assert!(crit.contains(&format!(r#"fill="{}""#, background(Level::Crit))));
        assert!(key_svg(Metric::Cpu, &reading(Level::Stale)).contains("<circle"));
        assert!(key_svg(Metric::Cpu, &reading(Level::Error)).contains("<circle"));
    }

    #[test]
    fn long_lines_are_squeezed_to_fit() {
        let mut r = reading(Level::Normal);
        r.subject = "Hottest: M.2 Drive 1 (cache)".into();
        assert!(key_svg(Metric::DiskTemp, &r).contains(r#"textLength="94""#));
    }

    #[test]
    fn key_image_is_an_inline_svg_data_uri() {
        let uri = key_image(Metric::Cpu, &reading(Level::Normal));
        let b64 = uri.strip_prefix("data:image/svg+xml;base64,").expect(&uri);
        let svg = String::from_utf8(STANDARD.decode(b64).unwrap()).unwrap();
        assert!(svg.starts_with("<svg"));
    }
}
```

`src/render/dial.rs` (tests only):
```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn reading() -> Reading {
        Reading { title: "Pool", value: "Rebuild 43%".into(), subject: "Pool 2".into(), level: Level::Warn, bar: Some(43.0), pager: Some((1, 2)) }
    }

    #[test]
    fn feedback_keys_match_the_shipped_layout() {
        let layout: Value = serde_json::from_str(include_str!("../../assets/layouts/metric.json")).unwrap();
        let keys: Vec<&str> = layout["items"].as_array().unwrap().iter().map(|i| i["key"].as_str().unwrap()).collect();
        let fb = feedback(Metric::Pool, &reading());
        for k in fb.as_object().unwrap().keys() {
            assert!(keys.contains(&k.as_str()), "layout has no item keyed {k}");
        }
    }

    #[test]
    fn feedback_colours_value_and_bar_by_level() {
        let fb = feedback(Metric::Pool, &reading());
        assert_eq!(fb["value"]["value"], "Rebuild 43%");
        assert_eq!(fb["value"]["color"], accent(Level::Warn));
        assert_eq!(fb["bar"]["value"], 43.0);
        assert_eq!(fb["bar"]["bar_fill_c"], accent(Level::Warn));
        assert_eq!(fb["title"], "Pool");
        assert!(fb["icon"].as_str().unwrap().starts_with("<svg"));
    }

    #[test]
    fn state_readings_fill_the_bar() {
        let mut r = reading();
        r.bar = None;
        r.level = Level::Normal;
        let fb = feedback(Metric::Pool, &r);
        assert_eq!(fb["bar"]["value"], 100.0);
        assert_eq!(fb["value"]["color"], TEXT);
        assert_eq!(fb["bar"]["bar_fill_c"], NEUTRAL);
    }

    #[test]
    fn subject_shows_where_rotation_is() {
        assert_eq!(subject_line(&reading()), "‹ Pool 2 · 2/2 ›");
        let mut r = reading();
        r.subject.clear();
        assert_eq!(subject_line(&r), "‹ 2/2 ›");
        r.pager = None;
        r.subject = "Usage".into();
        assert_eq!(subject_line(&r), "Usage");
    }
}
```

`src/render/glyphs.rs` (tests only):
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_metric_has_a_glyph() {
        for m in Metric::ALL {
            let svg = svg(m);
            assert!(svg.starts_with("<svg") && svg.ends_with("</svg>"));
            assert!(!paths(m).is_empty(), "{m:?}");
        }
    }
}
```

`src/render/mod.rs`:
```rust
//! Drawing a `Reading`: `key` makes a keypad image, `dial` a touch-strip
//! payload for `assets/layouts/metric.json`. Both colour by level the same
//! way, so a key and a dial showing the same metric can never disagree.

pub mod dial;
pub mod glyphs;
pub mod key;

use crate::metrics::Level;

pub const TEXT: &str = "#f9fafb";
pub const MUTED: &str = "#d1d5db";
/// Bar colour for a healthy state-based metric (nothing to measure).
pub const NEUTRAL: &str = "#4b5563";

/// Key background: neutral, amber, red, grey.
pub fn background(level: Level) -> &'static str {
    match level {
        Level::Normal => "#111827",
        Level::Warn => "#78350f",
        Level::Crit | Level::Error => "#7f1d1d",
        Level::Stale => "#374151",
    }
}

/// Bright counterpart used for dial values, bars and the key's `!` badge.
pub fn accent(level: Level) -> &'static str {
    match level {
        Level::Normal => "#22c55e",
        Level::Warn => "#f59e0b",
        Level::Crit | Level::Error => "#ef4444",
        Level::Stale => "#9ca3af",
    }
}
```

Add `mod render;` to `src/main.rs`.

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cargo test render::`
Expected: compile errors.

- [ ] **Step 4: Implement `src/render/glyphs.rs` above its tests**

```rust
//! One line-art glyph per metric, drawn on a 24×24 grid with round strokes.

use crate::metric::Metric;
use crate::render::TEXT;

pub fn paths(metric: Metric) -> &'static str {
    match metric {
        Metric::Cpu => r#"<rect x="6" y="6" width="12" height="12" rx="1"/><path d="M9 2v4M15 2v4M9 18v4M15 18v4M2 9h4M2 15h4M18 9h4M18 15h4"/>"#,
        Metric::Ram => r#"<rect x="2" y="7" width="20" height="10" rx="1"/><path d="M6 11v2M10 11v2M14 11v2M18 11v2M5 17v3M19 17v3"/>"#,
        Metric::Network => r#"<path d="M7 4v14M3 14l4 4 4-4M17 20V6M13 10l4-4 4 4"/>"#,
        Metric::SysTemp | Metric::DiskTemp => {
            r#"<path d="M14 14.8V4a2 2 0 0 0-4 0v10.8a4 4 0 1 0 4 0z"/><path d="M12 18v-6"/>"#
        }
        Metric::Uptime => r#"<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>"#,
        Metric::DiskHealth => r#"<path d="M3 12h4l2-5 4 10 2-5h6"/>"#,
        Metric::Volume => {
            r#"<ellipse cx="12" cy="6" rx="8" ry="3"/><path d="M4 6v12c0 1.7 3.6 3 8 3s8-1.3 8-3V6M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/>"#
        }
        Metric::Pool => r#"<path d="M12 3l9 5-9 5-9-5z"/><path d="M3 13l9 5 9-5"/>"#,
        Metric::Update => r#"<path d="M12 3v12M7 10l5 5 5-5M4 20h16"/>"#,
    }
}

/// A standalone SVG of the glyph, as a dial `pixmap` item accepts it.
pub fn svg(metric: Metric) -> String {
    format!(
        r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><g fill="none" stroke="{TEXT}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">{}</g></svg>"#,
        paths(metric)
    )
}
```

- [ ] **Step 5: Implement `src/render/key.rs` above its tests**

```rust
//! A key's image: glyph and title on top, the value large in the middle,
//! the subject small at the bottom, on a background tinted by level.
//!
//! Text is drawn inside the image rather than sent as the native title:
//! OpenDeck paints native titles with each key's own font and size on top
//! of the image, which on a small key is hard to read.

use crate::metric::Metric;
use crate::metrics::{Level, Reading};
use crate::render::{MUTED, TEXT, accent, background, glyphs};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

/// Widest a text line may render, in viewBox units (of 100).
const MAX_TEXT_WIDTH: f64 = 94.0;
/// Rough average glyph advance as a fraction of font size - only used to
/// decide when a line needs squeezing, so erring wide is the safe side.
const REGULAR_CHAR_WIDTH: f64 = 0.58;
const BOLD_CHAR_WIDTH: f64 = 0.64;

fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

/// One horizontally centred line with its baseline at `y`, squeezed with
/// `textLength` rather than clipped when it would overflow the key.
fn text_line(y: f64, size: f64, bold: bool, color: &str, content: &str) -> String {
    let char_width = if bold { BOLD_CHAR_WIDTH } else { REGULAR_CHAR_WIDTH };
    let fit = if content.chars().count() as f64 * size * char_width > MAX_TEXT_WIDTH {
        format!(r#" textLength="{MAX_TEXT_WIDTH}" lengthAdjust="spacingAndGlyphs""#)
    } else {
        String::new()
    };
    let weight = if bold { "700" } else { "500" };
    format!(
        r#"<text x="50" y="{y}" text-anchor="middle" font-family="sans-serif" font-size="{size}" font-weight="{weight}" fill="{color}"{fit}>{}</text>"#,
        escape_xml(content)
    )
}

pub fn key_svg(metric: Metric, r: &Reading) -> String {
    let bg = background(r.level);
    let glyph = glyphs::paths(metric);
    let title = format!(
        r#"<text x="30" y="21" font-family="sans-serif" font-size="14" font-weight="600" fill="{MUTED}">{}</text>"#,
        escape_xml(r.title)
    );
    let value = text_line(62.0, 28.0, true, TEXT, &r.value);
    let subject = text_line(88.0, 13.0, false, MUTED, &r.subject);
    let badge = if matches!(r.level, Level::Stale | Level::Error) {
        format!(
            r##"<circle cx="88" cy="13" r="8" fill="{}"/><text x="88" y="18" text-anchor="middle" font-family="sans-serif" font-size="13" font-weight="700" fill="#111827">!</text>"##,
            accent(r.level)
        )
    } else {
        String::new()
    };
    format!(
        r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><rect width="100" height="100" fill="{bg}"/><svg x="6" y="6" width="20" height="20" viewBox="0 0 24 24"><g fill="none" stroke="{TEXT}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">{glyph}</g></svg>{title}{value}{subject}{badge}</svg>"#
    )
}

/// The `image` string `setImage` expects. OpenDeck only treats it as inline
/// data when it starts with `data:`; anything else is read as a file path.
pub fn key_image(metric: Metric, r: &Reading) -> String {
    format!("data:image/svg+xml;base64,{}", STANDARD.encode(key_svg(metric, r)))
}
```

- [ ] **Step 6: Implement `src/render/dial.rs` above its tests**

```rust
//! A dial's touch strip (`assets/layouts/metric.json`): glyph and title,
//! the value, a bar (the measured share, or full for state metrics) and the
//! subject with a "where am I" hint when turning the dial has more views.

use crate::metric::Metric;
use crate::metrics::{Level, Reading};
use crate::render::{NEUTRAL, TEXT, accent, glyphs};
use serde_json::{Value, json};

pub fn subject_line(r: &Reading) -> String {
    match r.pager {
        Some((i, n)) if r.subject.is_empty() => format!("‹ {}/{n} ›", i + 1),
        Some((i, n)) => format!("‹ {} · {}/{n} ›", r.subject, i + 1),
        None => r.subject.clone(),
    }
}

pub fn feedback(metric: Metric, r: &Reading) -> Value {
    let value_color = if r.level == Level::Normal { TEXT } else { accent(r.level) };
    let bar_color = if r.bar.is_none() && r.level == Level::Normal { NEUTRAL } else { accent(r.level) };
    json!({
        "icon": glyphs::svg(metric),
        "title": r.title,
        "value": { "value": r.value, "color": value_color },
        "bar": { "value": r.bar.unwrap_or(100.0), "bar_fill_c": bar_color },
        "subject": subject_line(r),
    })
}
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `cargo test render::`
Expected: PASS (9 tests).

Run: `cargo fmt && cargo clippy --all-targets -- -D warnings`
Expected: clean.

- [ ] **Step 8: Commit**

```bash
git add src/render src/main.rs assets/layouts
git commit -m "feat: draw readings as key images and dial touch-strip feedback

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---
### Task 14: The ten actions, live instances, manifest and icons

**Files:**
- Create: `src/instances.rs`, `src/actions.rs`, `assets/manifest.json`, `scripts/render-icons.sh`, `assets/icons/source/*.svg` and `assets/icons/*.png` (generated)
- Modify: `src/render/glyphs.rs` (add the icon writer test), `src/main.rs` (add `mod actions; mod instances;`)

**Interfaces:**
- Consumes:
  - `services::Services` and `services::testing::*` (Task 12)
  - `metrics::{read, rotate, Context}` (Task 7)
  - `render::{key, dial}` (Task 13)
  - `settings::ActionSettings` (Task 4)
  - `metric::Metric` (Task 4)
  - `poller::PollState` (Task 5)
- Produces:
  - `instances::Instances` (`Default`):
    - `show(&self, services: &Arc<Services>, metric: Metric, id: &str, is_key: bool, settings: ActionSettings)`
    - `hide(&self, services: &Services, id: &str)`
    - `rotate(&self, services: &Services, id: &str, ticks: i16)`
    - `view(&self, id: &str) -> Option<ActionSettings>`
  - `actions::MetricKind` trait (`const METRIC: Metric`), with marker types `Cpu, Ram, Network, SysTemp, Uptime, DiskTemp, DiskHealth, Volume, Pool, Update`
  - `actions::MetricAction<K>`, which implements `openaction::Action` with `UUID = K::METRIC.uuid()` and `Settings = ActionSettings`
  - `actions::register_all(services: &Arc<Services>, instances: &Arc<Instances>)` (async)

- [ ] **Step 1: Write the manifest**

`assets/manifest.json`. Every action has the same shape, only the UUID, name, icon, tooltip and trigger descriptions differ:
```json
{
	"Name": "Synology",
	"Author": "jfms7s",
	"Version": "0.1.0",
	"Category": "Synology",
	"Description": "Live, read-only status of a Synology NAS running DSM 7 - CPU, RAM, temperatures, disk health, volumes, storage pools, network, uptime and updates - on keys and dials. Talks only to your NAS; works with 2FA accounts.",
	"Icon": "icons/icon",
	"OS": [{ "Platform": "linux" }],
	"CodePaths": { "x86_64-unknown-linux-gnu": "opendeck-synology-x86_64-unknown-linux-gnu" },
	"CodePathLin": "opendeck-synology-x86_64-unknown-linux-gnu",
	"Actions": [
		{
			"UUID": "com.jfms7s.synology.cpu",
			"Name": "CPU",
			"Icon": "icons/cpu",
			"Tooltip": "CPU usage. On a dial, rotate for the 1, 5 and 15 minute load averages. Press to refresh",
			"Controllers": ["Keypad", "Encoder"],
			"PropertyInspectorPath": "propertyInspector/index.html",
			"States": [{ "Image": "icons/cpu" }],
			"Encoder": { "layout": "layouts/metric.json", "TriggerDescription": { "Rotate": "Usage / load averages", "Push": "Refresh", "Touch": "Refresh" } }
		},
		{
			"UUID": "com.jfms7s.synology.ram",
			"Name": "RAM",
			"Icon": "icons/ram",
			"Tooltip": "Memory in use. On a dial, rotate between percent and used of total. Press to refresh",
			"Controllers": ["Keypad", "Encoder"],
			"PropertyInspectorPath": "propertyInspector/index.html",
			"States": [{ "Image": "icons/ram" }],
			"Encoder": { "layout": "layouts/metric.json", "TriggerDescription": { "Rotate": "Percent / used of total", "Push": "Refresh", "Touch": "Refresh" } }
		},
		{
			"UUID": "com.jfms7s.synology.network",
			"Name": "Network",
			"Icon": "icons/network",
			"Tooltip": "Network throughput, in, out or combined. On a dial, rotate to switch direction. Press to refresh",
			"Controllers": ["Keypad", "Encoder"],
			"PropertyInspectorPath": "propertyInspector/index.html",
			"States": [{ "Image": "icons/network" }],
			"Encoder": { "layout": "layouts/metric.json", "TriggerDescription": { "Rotate": "In / out / combined", "Push": "Refresh", "Touch": "Refresh" } }
		},
		{
			"UUID": "com.jfms7s.synology.systemp",
			"Name": "System Temperature",
			"Icon": "icons/systemp",
			"Tooltip": "The NAS's system temperature. Press to refresh",
			"Controllers": ["Keypad", "Encoder"],
			"PropertyInspectorPath": "propertyInspector/index.html",
			"States": [{ "Image": "icons/systemp" }],
			"Encoder": { "layout": "layouts/metric.json", "TriggerDescription": { "Push": "Refresh", "Touch": "Refresh" } }
		},
		{
			"UUID": "com.jfms7s.synology.uptime",
			"Name": "Uptime",
			"Icon": "icons/uptime",
			"Tooltip": "How long the NAS has been running. Press to refresh",
			"Controllers": ["Keypad", "Encoder"],
			"PropertyInspectorPath": "propertyInspector/index.html",
			"States": [{ "Image": "icons/uptime" }],
			"Encoder": { "layout": "layouts/metric.json", "TriggerDescription": { "Push": "Refresh", "Touch": "Refresh" } }
		},
		{
			"UUID": "com.jfms7s.synology.disktemp",
			"Name": "Disk Temperature",
			"Icon": "icons/disktemp",
			"Tooltip": "One disk's temperature, or the hottest disk's. On a dial, rotate through the disks. Press to refresh",
			"Controllers": ["Keypad", "Encoder"],
			"PropertyInspectorPath": "propertyInspector/index.html",
			"States": [{ "Image": "icons/disktemp" }],
			"Encoder": { "layout": "layouts/metric.json", "TriggerDescription": { "Rotate": "Next disk", "Push": "Refresh", "Touch": "Refresh" } }
		},
		{
			"UUID": "com.jfms7s.synology.diskhealth",
			"Name": "Disk Health",
			"Icon": "icons/diskhealth",
			"Tooltip": "S.M.A.R.T. health of one disk, or the worst disk. On a dial, rotate through the disks. Press to refresh",
			"Controllers": ["Keypad", "Encoder"],
			"PropertyInspectorPath": "propertyInspector/index.html",
			"States": [{ "Image": "icons/diskhealth" }],
			"Encoder": { "layout": "layouts/metric.json", "TriggerDescription": { "Rotate": "Next disk", "Push": "Refresh", "Touch": "Refresh" } }
		},
		{
			"UUID": "com.jfms7s.synology.volume",
			"Name": "Volume",
			"Icon": "icons/volume",
			"Tooltip": "How full a volume is. On a dial, rotate through the volumes. Press to refresh",
			"Controllers": ["Keypad", "Encoder"],
			"PropertyInspectorPath": "propertyInspector/index.html",
			"States": [{ "Image": "icons/volume" }],
			"Encoder": { "layout": "layouts/metric.json", "TriggerDescription": { "Rotate": "Next volume", "Push": "Refresh", "Touch": "Refresh" } }
		},
		{
			"UUID": "com.jfms7s.synology.pool",
			"Name": "Storage Pool",
			"Icon": "icons/pool",
			"Tooltip": "Storage pool / RAID state: normal, degraded, or rebuild progress. On a dial, rotate through the pools. Press to refresh",
			"Controllers": ["Keypad", "Encoder"],
			"PropertyInspectorPath": "propertyInspector/index.html",
			"States": [{ "Image": "icons/pool" }],
			"Encoder": { "layout": "layouts/metric.json", "TriggerDescription": { "Rotate": "Next pool", "Push": "Refresh", "Touch": "Refresh" } }
		},
		{
			"UUID": "com.jfms7s.synology.update",
			"Name": "DSM Update",
			"Icon": "icons/update",
			"Tooltip": "Whether a DSM update is available. Press to check now",
			"Controllers": ["Keypad", "Encoder"],
			"PropertyInspectorPath": "propertyInspector/index.html",
			"States": [{ "Image": "icons/update" }],
			"Encoder": { "layout": "layouts/metric.json", "TriggerDescription": { "Push": "Check now", "Touch": "Check now" } }
		}
	]
}
```

- [ ] **Step 2: Add the icon writer and generate the icons**

Append to the `tests` module in `src/render/glyphs.rs`:
```rust
    /// A 144×144 action icon: the glyph, white on the plugin's dark tile.
    fn icon_svg(metric: Metric) -> String {
        format!(
            r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 144 144"><rect width="144" height="144" rx="24" fill="#111827"/><svg x="30" y="30" width="84" height="84" viewBox="0 0 24 24"><g fill="none" stroke="{TEXT}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">{}</g></svg></svg>"##,
            paths(metric)
        )
    }

    /// Writes the SVG sources of the PNG icons. Use `scripts/render-icons.sh`,
    /// which runs this and converts the result.
    #[test]
    #[ignore]
    fn write_icon_sources() {
        let dir = format!("{}/assets/icons/source", env!("CARGO_MANIFEST_DIR"));
        std::fs::create_dir_all(&dir).unwrap();
        for m in Metric::ALL {
            let name = m.uuid().rsplit('.').next().unwrap();
            std::fs::write(format!("{dir}/{name}.svg"), icon_svg(m)).unwrap();
        }
        // The plugin's own icon: a NAS is, above all, its storage pool.
        std::fs::write(format!("{dir}/icon.svg"), icon_svg(Metric::Pool)).unwrap();
    }
```

`scripts/render-icons.sh`:
```bash
#!/usr/bin/env bash
# Regenerates assets/icons/*.png (72 px and @2x 144 px) from the glyphs in
# src/render/glyphs.rs. Needs ImageMagick 7 (`magick`).
set -euo pipefail
cd "$(dirname "$0")/.."
cargo test --quiet write_icon_sources -- --ignored
for svg in assets/icons/source/*.svg; do
	name=$(basename "$svg" .svg)
	magick -background none -density 384 "$svg" -resize 72x72 "assets/icons/$name.png"
	magick -background none -density 384 "$svg" -resize 144x144 "assets/icons/$name@2x.png"
done
echo "rendered $(ls assets/icons/*.png | wc -l) icons"
```

```bash
chmod +x scripts/render-icons.sh
scripts/render-icons.sh
```
Expected: `rendered 22 icons` (10 actions plus the plugin icon, each at 1× and 2×). Open two of the PNGs with the Read tool to check they show a white glyph on a dark rounded tile.

- [ ] **Step 3: Write the failing tests**

`src/instances.rs` (tests only):
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::metric::Endpoint;
    use crate::secrets::MemoryStore;
    use crate::services::testing::{conn, healthy_nas, services_with};
    use crate::settings::GlobalSettings;
    use std::time::Duration as StdDuration;

    async fn connected_services() -> Arc<Services> {
        let (s, _) = services_with(healthy_nas(), Arc::new(MemoryStore::default()));
        s.load_global(GlobalSettings::default()).await;
        s.save_connection(conn(), Some("pw".into())).await;
        s
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn showing_subscribes_and_hiding_unsubscribes() {
        let s = connected_services().await;
        let live = Instances::default();
        live.show(&s, Metric::Cpu, "k1", true, ActionSettings::default());
        assert_eq!(s.poller(Endpoint::Utilization).effective_interval(), Some(StdDuration::from_secs(5)));
        let faster = ActionSettings { interval_secs: Some(3), ..ActionSettings::default() };
        live.show(&s, Metric::Cpu, "k1", true, faster);
        assert_eq!(s.poller(Endpoint::Utilization).effective_interval(), Some(StdDuration::from_secs(3)));
        live.hide(&s, "k1");
        assert_eq!(s.poller(Endpoint::Utilization).effective_interval(), None);
        assert!(live.view("k1").is_none());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn new_settings_reset_the_dial_view() {
        let s = connected_services().await;
        let live = Instances::default();
        live.show(&s, Metric::Cpu, "d1", false, ActionSettings::default());
        live.rotate(&s, "d1", 1);
        assert_eq!(live.view("d1").unwrap().cpu_view, crate::settings::CpuView::Load1);
        live.show(&s, Metric::Cpu, "d1", false, ActionSettings::default());
        assert_eq!(live.view("d1").unwrap().cpu_view, crate::settings::CpuView::Load1, "same settings keep it");
        let other = ActionSettings { warn: Some(50.0), ..ActionSettings::default() };
        live.show(&s, Metric::Cpu, "d1", false, other);
        assert_eq!(live.view("d1").unwrap().cpu_view, crate::settings::CpuView::Total);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn rotating_a_disk_dial_uses_the_latest_storage_data() {
        let s = connected_services().await;
        let live = Instances::default();
        live.show(&s, Metric::DiskTemp, "d1", false, ActionSettings::default());
        tokio::time::timeout(StdDuration::from_secs(5), async {
            while s.poller(Endpoint::Storage).latest().value.is_none() {
                tokio::time::sleep(StdDuration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        live.rotate(&s, "d1", 1);
        assert_eq!(live.view("d1").unwrap().target.as_deref(), Some("sata1"));
    }
}
```

`src/actions.rs` (tests only):
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn manifest() -> Value {
        serde_json::from_str(include_str!("../assets/manifest.json")).unwrap()
    }

    #[test]
    fn every_metric_is_in_the_manifest_on_keys_and_dials() {
        let m = manifest();
        let actions = m["Actions"].as_array().unwrap();
        assert_eq!(actions.len(), Metric::ALL.len());
        for metric in Metric::ALL {
            let a = actions.iter().find(|a| a["UUID"] == metric.uuid()).unwrap_or_else(|| panic!("{metric:?} missing"));
            assert_eq!(a["Controllers"], serde_json::json!(["Keypad", "Encoder"]));
            assert_eq!(a["Encoder"]["layout"], "layouts/metric.json");
            let icon = a["Icon"].as_str().unwrap();
            let png = format!("{}/assets/{icon}.png", env!("CARGO_MANIFEST_DIR"));
            assert!(std::path::Path::new(&png).exists(), "{png} missing - run scripts/render-icons.sh");
        }
        assert_eq!(m["Category"], "Synology");
    }

    #[test]
    fn action_uuids_come_from_the_metric() {
        assert_eq!(<MetricAction<Cpu> as Action>::UUID, "com.jfms7s.synology.cpu");
        assert_eq!(<MetricAction<Pool> as Action>::UUID, "com.jfms7s.synology.pool");
    }
}
```

Add to `src/main.rs`:
```rust
mod actions;
mod instances;
```

- [ ] **Step 4: Run the tests to verify they fail**

Run: `cargo test instances:: actions::`
Expected: compile errors.

- [ ] **Step 5: Implement `src/instances.rs` above its tests**

```rust
//! Keys and dials currently on screen. Each has a render task that redraws
//! when its endpoint's poll result, the connection status, or its dial view
//! changes - so nothing redraws on a timer.

use crate::dsm::model::Payload;
use crate::metric::Metric;
use crate::metrics::{self, Context, Reading};
use crate::poller::PollState;
use crate::render::{dial, key};
use crate::services::Services;
use crate::settings::ActionSettings;
use dashmap::DashMap;
use openaction::{Instance, OpenActionResult};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{Notify, watch};
use tokio::task::JoinHandle;

struct Live {
    metric: Metric,
    /// As saved; a change re-subscribes and resets the view.
    settings: ActionSettings,
    /// The settings as turned on the dial (never saved).
    view: Arc<Mutex<ActionSettings>>,
    redraw: Arc<Notify>,
    task: JoinHandle<()>,
}

#[derive(Default)]
pub struct Instances {
    live: DashMap<String, Live>,
}

impl Instances {
    pub fn show(&self, services: &Arc<Services>, metric: Metric, id: &str, is_key: bool, settings: ActionSettings) {
        if let Some(l) = self.live.get(id)
            && l.settings == settings
        {
            l.redraw.notify_one();
            return;
        }
        self.hide(services, id);
        let interval = settings.interval_secs.map(Duration::from_secs);
        let rx = services.poller(metric.endpoint()).subscribe(id, interval);
        let view = Arc::new(Mutex::new(settings.clone()));
        let redraw = Arc::new(Notify::new());
        let task = tokio::spawn(render_loop(
            services.clone(),
            metric,
            id.to_string(),
            is_key,
            rx,
            view.clone(),
            redraw.clone(),
        ));
        self.live.insert(id.to_string(), Live { metric, settings, view, redraw, task });
    }

    pub fn hide(&self, services: &Services, id: &str) {
        if let Some((_, l)) = self.live.remove(id) {
            l.task.abort();
            services.poller(l.metric.endpoint()).unsubscribe(id);
        }
    }

    pub fn rotate(&self, services: &Services, id: &str, ticks: i16) {
        let Some(l) = self.live.get(id) else { return };
        let latest = services.poller(l.metric.endpoint()).latest();
        metrics::rotate(l.metric, &mut l.view.lock().unwrap(), latest.value.as_deref(), ticks);
        l.redraw.notify_one();
    }

    pub fn view(&self, id: &str) -> Option<ActionSettings> {
        self.live.get(id).map(|l| l.view.lock().unwrap().clone())
    }
}

async fn render_loop(
    services: Arc<Services>,
    metric: Metric,
    id: String,
    is_key: bool,
    mut rx: watch::Receiver<PollState<Payload>>,
    view: Arc<Mutex<ActionSettings>>,
    redraw: Arc<Notify>,
) {
    let mut status = services.status();
    // Unchanged readings aren't re-sent, so ten keys don't flood OpenDeck
    // with identical images every 5 s.
    let mut last: Option<Reading> = None;
    loop {
        let state = rx.borrow_and_update().clone();
        let conn = status.borrow_and_update().clone();
        let v = view.lock().unwrap().clone();
        let unit = services.global().temp_unit;
        let reading = metrics::read(metric, &state, &v, &Context { status: &conn, unit });
        if last.as_ref() != Some(&reading)
            && let Some(instance) = openaction::get_instance(id.clone()).await
        {
            match draw(&instance, metric, &reading, is_key).await {
                Ok(()) => last = Some(reading),
                Err(e) => log::warn!("drawing {} failed: {e}", metric.uuid()),
            }
        }
        tokio::select! {
            changed = rx.changed() => if changed.is_err() { return },
            changed = status.changed() => if changed.is_err() { return },
            // An explicit redraw (appear, settings re-sent, dial turned) always draws.
            _ = redraw.notified() => last = None,
        }
    }
}

async fn draw(instance: &Instance, metric: Metric, r: &Reading, is_key: bool) -> OpenActionResult<()> {
    if is_key {
        // The text is inside the image; clear the native title so OpenDeck
        // doesn't paint a second copy on top.
        instance.set_title(Some(String::new()), None).await?;
        instance.set_image(Some(key::key_image(metric, r)), None).await
    } else {
        instance.set_feedback(&dial::feedback(metric, r)).await
    }
}
```

- [ ] **Step 6: Implement `src/actions.rs` above its tests**

```rust
//! The ten actions. They differ only in which metric they show, so one
//! generic `MetricAction` is instantiated per metric through a marker type;
//! everything metric-specific lives in `metrics`.

use crate::instances::Instances;
use crate::metric::Metric;
use crate::services::Services;
use crate::settings::ActionSettings;
use async_trait::async_trait;
use openaction::{Action, Instance, OpenActionResult, register_action};
use serde_json::Value;
use std::marker::PhantomData;
use std::sync::Arc;

/// The wire value OpenDeck sends as `Instance::controller` for a key
/// (a dial is `"Encoder"`).
const KEYPAD: &str = "Keypad";

pub trait MetricKind: Send + Sync + 'static {
    const METRIC: Metric;
}

macro_rules! kinds {
    ($($name:ident),* $(,)?) => {
        $(
            pub struct $name;
            impl MetricKind for $name {
                const METRIC: Metric = Metric::$name;
            }
        )*
    };
}

kinds!(Cpu, Ram, Network, SysTemp, Uptime, DiskTemp, DiskHealth, Volume, Pool, Update);

pub struct MetricAction<K> {
    services: Arc<Services>,
    instances: Arc<Instances>,
    _kind: PhantomData<fn() -> K>,
}

impl<K: MetricKind> MetricAction<K> {
    pub fn new(services: Arc<Services>, instances: Arc<Instances>) -> Self {
        Self { services, instances, _kind: PhantomData }
    }

    fn refresh(&self) {
        self.services.poller(K::METRIC.endpoint()).refresh_now();
    }
}

#[async_trait]
impl<K: MetricKind> Action for MetricAction<K> {
    const UUID: &'static str = K::METRIC.uuid();
    type Settings = ActionSettings;

    async fn will_appear(&self, instance: &Instance, settings: &ActionSettings) -> OpenActionResult<()> {
        let is_key = instance.controller == KEYPAD;
        self.instances.show(&self.services, K::METRIC, &instance.instance_id, is_key, settings.clone());
        Ok(())
    }

    async fn did_receive_settings(&self, instance: &Instance, settings: &ActionSettings) -> OpenActionResult<()> {
        self.will_appear(instance, settings).await
    }

    async fn will_disappear(&self, instance: &Instance, _: &ActionSettings) -> OpenActionResult<()> {
        self.instances.hide(&self.services, &instance.instance_id);
        Ok(())
    }

    async fn key_up(&self, _: &Instance, _: &ActionSettings) -> OpenActionResult<()> {
        self.refresh();
        Ok(())
    }

    async fn dial_up(&self, _: &Instance, _: &ActionSettings) -> OpenActionResult<()> {
        self.refresh();
        Ok(())
    }

    async fn touch_tap(&self, _: &Instance, _: &ActionSettings, _: (u16, u16), _: bool) -> OpenActionResult<()> {
        self.refresh();
        Ok(())
    }

    async fn dial_rotate(&self, instance: &Instance, _: &ActionSettings, ticks: i16, _: bool) -> OpenActionResult<()> {
        self.instances.rotate(&self.services, &instance.instance_id, ticks);
        Ok(())
    }

    async fn send_to_plugin(&self, _: &Instance, _: &ActionSettings, _: &Value) -> OpenActionResult<()> {
        Ok(()) // the settings panel protocol arrives in Task 15
    }
}

pub async fn register_all(services: &Arc<Services>, instances: &Arc<Instances>) {
    macro_rules! register {
        ($($kind:ident),*) => {
            $( register_action(MetricAction::<$kind>::new(services.clone(), instances.clone())).await; )*
        };
    }
    register!(Cpu, Ram, Network, SysTemp, Uptime, DiskTemp, DiskHealth, Volume, Pool, Update);
}
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `cargo test instances:: actions::`
Expected: PASS (3 instance tests, 2 action tests).

Run: `cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test`
Expected: clean; the whole suite passes.

- [ ] **Step 8: Commit**

```bash
git add src/instances.rs src/actions.rs src/render/glyphs.rs src/main.rs assets/manifest.json assets/icons scripts/render-icons.sh
git commit -m "feat: add the ten metric actions with per-instance render loops

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---
### Task 15: Settings panel (property inspector)

**Files:**
- Create: `src/inspector.rs`, `assets/propertyInspector/index.html`
- Modify: `src/actions.rs` (route the panel events), `src/main.rs` (add `mod inspector;`)

**Interfaces:**
- Consumes:
  - `services::Services` and `services::testing::*` (Task 12)
  - `metrics::target_options` (Task 7)
  - `settings::{Connection, TempUnit}` (Task 4)
  - `status::ConnStatus::{kind, describe}` (Task 4)
- Produces:
  - `inspector::Request` (serde, tag `event`, camelCase): `GetState`, `SaveConnection { host, port, https, account, password: Option<String> }`, `SubmitOtp { code }`, `TrustCertificate`, `SetTempUnit { unit }`
  - `inspector::normalise_otp(&str) -> String`
  - `inspector::state_message(&Services, Metric) -> Value`, i.e. `{event:"state", connection:{host,port,https,account}, hasPassword, tempUnit, status:{kind,text,fingerprint,firmware}, targets:[{id,label}], defaults:{warn,crit,interval}}`. It never includes the password.
  - `inspector::handle(&Arc<Services>, Metric, &Instance, &Value) -> OpenActionResult<()>` and `inspector::send_state(&Services, Metric, &Instance) -> OpenActionResult<()>`

- [ ] **Step 1: Write the failing tests**

`src/inspector.rs` (tests only):
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::MemoryStore;
    use crate::services::testing::{healthy_nas, services_with};
    use crate::settings::GlobalSettings;
    use std::time::Duration;

    fn req(v: Value) -> Request {
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn parses_panel_requests() {
        assert_eq!(req(json!({ "event": "getState" })), Request::GetState);
        assert_eq!(req(json!({ "event": "trustCertificate" })), Request::TrustCertificate);
        assert_eq!(req(json!({ "event": "setTempUnit", "unit": "fahrenheit" })), Request::SetTempUnit { unit: TempUnit::Fahrenheit });
        assert_eq!(req(json!({ "event": "submitOtp", "code": "123456" })), Request::SubmitOtp { code: "123456".into() });
        let save = req(json!({ "event": "saveConnection", "host": "nas.lan", "port": 5001, "https": true, "account": "jf", "password": null }));
        assert_eq!(
            save,
            Request::SaveConnection { host: "nas.lan".into(), port: 5001, https: true, account: "jf".into(), password: None }
        );
        assert!(serde_json::from_value::<Request>(json!({ "event": "reboot" })).is_err());
    }

    #[test]
    fn otp_code_is_normalised() {
        assert_eq!(normalise_otp(" 123 456\n"), "123456");
    }

    fn save(password: Option<&str>) -> Request {
        Request::SaveConnection {
            host: "nas.lan".into(),
            port: 5001,
            https: true,
            account: "jf".into(),
            password: password.map(str::to_string),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_password_is_never_echoed_or_saved_in_settings() {
        let (s, sink) = services_with(healthy_nas(), Arc::new(MemoryStore::default()));
        s.load_global(GlobalSettings::default()).await;
        apply(&s, save(Some("pw-secret"))).await;
        let msg = state_message(&s, Metric::Cpu);
        assert_eq!(msg["hasPassword"], true);
        assert!(!msg.to_string().contains("pw-secret"));
        assert!(!serde_json::to_string(&sink.last()).unwrap().contains("pw-secret"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_empty_password_keeps_the_stored_one() {
        let (s, _) = services_with(healthy_nas(), Arc::new(MemoryStore::default()));
        s.load_global(GlobalSettings::default()).await;
        apply(&s, save(Some("pw"))).await;
        apply(&s, save(Some(""))).await;
        assert!(s.has_password());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn state_lists_targets_and_defaults() {
        let (s, _) = services_with(healthy_nas(), Arc::new(MemoryStore::default()));
        s.load_global(GlobalSettings::default()).await;
        apply(&s, save(Some("pw"))).await;
        let _rx = s.poller(Endpoint::Storage).subscribe("k", None);
        tokio::time::timeout(Duration::from_secs(5), async {
            while s.poller(Endpoint::Storage).latest().value.is_none() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let msg = state_message(&s, Metric::DiskTemp);
        assert_eq!(msg["targets"][0], json!({ "id": null, "label": "Hottest disk" }));
        assert_eq!(msg["targets"][1], json!({ "id": "sata1", "label": "Drive 1" }));
        assert_eq!(msg["defaults"], json!({ "warn": 50.0, "crit": 60.0, "interval": 60 }));
        assert_eq!(msg["connection"]["host"], "nas.lan");
    }
}
```

Add `mod inspector;` to `src/main.rs`.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test inspector::`
Expected: compile errors.

- [ ] **Step 3: Implement above the tests**

```rust
//! The settings panel's side channel. The panel saves a key's own settings
//! directly (`setSettings`). Anything plugin-wide or secret - connection,
//! password, 2FA code, certificate trust, temperature unit - comes through
//! here, so the password never lands in a settings file.
//!
//! Payloads are never logged: they can carry the password.

use crate::dsm::model::Payload;
use crate::metric::{Endpoint, Metric};
use crate::metrics;
use crate::services::Services;
use crate::settings::{Connection, TempUnit};
use crate::status::ConnStatus;
use openaction::{Instance, OpenActionResult};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;

// Debug only in tests: a derived Debug would print the password.
#[derive(Deserialize, PartialEq)]
#[cfg_attr(test, derive(Debug))]
#[serde(tag = "event", rename_all = "camelCase")]
pub enum Request {
    GetState,
    SaveConnection {
        host: String,
        port: u16,
        https: bool,
        account: String,
        #[serde(default)]
        password: Option<String>,
    },
    SubmitOtp {
        code: String,
    },
    TrustCertificate,
    SetTempUnit {
        unit: TempUnit,
    },
}

/// Drops whatever surrounds a pasted 2FA code: " 123 456\n" -> "123456".
pub fn normalise_otp(code: &str) -> String {
    code.chars().filter(|c| !c.is_whitespace()).collect()
}

pub fn state_message(services: &Services, metric: Metric) -> Value {
    let g = services.global();
    let status = services.current_status();
    let targets: Vec<Value> = services
        .poller(metric.endpoint())
        .latest()
        .value
        .as_deref()
        .map(|p| metrics::target_options(metric, p))
        .unwrap_or_default()
        .into_iter()
        .map(|(id, label)| json!({ "id": id, "label": label }))
        .collect();
    let firmware = match services.poller(Endpoint::SystemInfo).latest().value.as_deref() {
        Some(Payload::SystemInfo(s)) => s.firmware.clone(),
        _ => None,
    };
    let fingerprint = match &status {
        ConnStatus::Certificate { fingerprint, .. } => Some(fingerprint.clone()),
        _ => None,
    };
    let defaults = metric.default_thresholds();
    json!({
        "event": "state",
        "connection": {
            "host": g.connection.host,
            "port": g.connection.port,
            "https": g.connection.https,
            "account": g.connection.account,
        },
        "hasPassword": services.has_password(),
        "tempUnit": g.temp_unit,
        "status": { "kind": status.kind(), "text": status.describe(), "fingerprint": fingerprint, "firmware": firmware },
        "targets": targets,
        "defaults": {
            "warn": defaults.map(|d| d.0),
            "crit": defaults.map(|d| d.1),
            "interval": metric.endpoint().default_interval().as_secs(),
        },
    })
}

pub async fn send_state(services: &Services, metric: Metric, instance: &Instance) -> OpenActionResult<()> {
    instance.send_to_property_inspector(state_message(services, metric)).await
}

pub async fn handle(services: &Arc<Services>, metric: Metric, instance: &Instance, payload: &Value) -> OpenActionResult<()> {
    match serde_json::from_value::<Request>(payload.clone()) {
        Ok(req) => apply(services, req).await,
        Err(_) => {
            log::warn!("ignoring an unrecognised settings-panel message");
            return Ok(());
        }
    }
    send_state(services, metric, instance).await
}

async fn apply(services: &Arc<Services>, req: Request) {
    match req {
        Request::GetState => {}
        Request::SaveConnection { host, port, https, account, password } => {
            let conn = Connection { host, port, https, account, pinned_sha256: None };
            services.save_connection(conn, password.filter(|p| !p.is_empty())).await;
        }
        Request::SubmitOtp { code } => {
            if let Err(e) = services.submit_otp(&normalise_otp(&code)).await {
                log::info!("2FA sign-in failed: {e}");
            }
        }
        Request::TrustCertificate => services.trust_certificate().await,
        Request::SetTempUnit { unit } => services.set_temp_unit(unit).await,
    }
}
```

`save_connection` takes the pin from the stored settings when the host is unchanged (Task 12), so passing `pinned_sha256: None` here is correct.

- [ ] **Step 4: Route the panel events in `src/actions.rs`**

Add `use crate::inspector;` and replace the placeholder `send_to_plugin` with:
```rust
    async fn property_inspector_did_appear(&self, instance: &Instance, _: &ActionSettings) -> OpenActionResult<()> {
        inspector::send_state(&self.services, K::METRIC, instance).await
    }

    async fn send_to_plugin(&self, instance: &Instance, _: &ActionSettings, payload: &Value) -> OpenActionResult<()> {
        inspector::handle(&self.services, K::METRIC, instance, payload).await
    }
```

- [ ] **Step 5: Write `assets/propertyInspector/index.html`**

```html
<!doctype html>
<html lang="en">
<head>
	<meta charset="utf-8" />
	<meta name="viewport" content="width=device-width, initial-scale=1" />
	<style>
		body { font: 12px system-ui, sans-serif; margin: 0; padding: 8px 12px; }
		h2 { font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; opacity: 0.7; margin: 14px 0 4px; }
		label { display: block; margin-top: 8px; font-size: 11px; opacity: 0.8; }
		input, select, button { box-sizing: border-box; margin-top: 2px; font: inherit; }
		input, select { width: 100%; }
		button { margin-top: 8px; }
		.row { display: flex; gap: 6px; align-items: end; }
		.row > * { flex: 1; }
		.row > .narrow { flex: 0 0 5.5em; }
		.check { display: flex; gap: 6px; align-items: center; margin-top: 8px; }
		.check input { width: auto; margin: 0; }
		.check label { margin: 0; }
		#status { margin-top: 10px; padding: 6px; border-radius: 4px; background: rgba(127, 127, 127, 0.15); }
		#status.ok { background: rgba(34, 197, 94, 0.2); }
		#status.bad { background: rgba(239, 68, 68, 0.2); }
		.hint { font-size: 10px; opacity: 0.7; margin-top: 3px; }
		.fingerprint { font-family: ui-monospace, monospace; font-size: 10px; word-break: break-all; margin-top: 4px; }
		.hidden { display: none; }
	</style>
</head>
<body>
	<h2>NAS connection · shared by all keys</h2>
	<label for="host">Host or IP address</label>
	<input id="host" placeholder="nas.lan or 192.168.1.10" />
	<div class="row">
		<div><label for="account">Account</label><input id="account" autocomplete="username" /></div>
		<div class="narrow"><label for="port">Port</label><input id="port" type="number" min="1" max="65535" /></div>
	</div>
	<label for="password">Password</label>
	<input id="password" type="password" autocomplete="current-password" />
	<div class="hint" id="password-hint"></div>
	<div class="check"><input type="checkbox" id="https" /><label for="https">HTTPS</label></div>
	<div class="hint hidden" id="http-warning">Unencrypted: your password crosses the network in the clear.</div>
	<button id="save">Save and connect</button>

	<div id="status">…</div>
	<div id="otp-box" class="hidden">
		<label for="otp">2FA code from your authenticator app</label>
		<div class="row">
			<input id="otp" inputmode="numeric" autocomplete="one-time-code" />
			<button id="submit-otp" class="narrow">Verify</button>
		</div>
		<div class="hint">DSM then remembers this device (Personal › Security › Trusted devices), so you won't be asked again.</div>
	</div>
	<div id="cert-box" class="hidden">
		<div class="hint">SHA-256 fingerprint of the certificate the NAS presented. Compare it with DSM › Control Panel › Security › Certificate before trusting it.</div>
		<div class="fingerprint" id="fingerprint"></div>
		<button id="trust">Trust this certificate</button>
	</div>

	<label for="temp-unit">Temperature unit</label>
	<select id="temp-unit">
		<option value="celsius">°C</option>
		<option value="fahrenheit">°F</option>
	</select>

	<h2>This key</h2>
	<div id="target-field" class="hidden">
		<label for="target" id="target-label">Show</label>
		<select id="target"></select>
	</div>
	<div id="cpu-field" class="hidden">
		<label for="cpu_view">Show</label>
		<select id="cpu_view">
			<option value="total">Usage %</option>
			<option value="load1">Load average, 1 min</option>
			<option value="load5">Load average, 5 min</option>
			<option value="load15">Load average, 15 min</option>
		</select>
	</div>
	<div id="direction-field" class="hidden">
		<label for="direction">Direction</label>
		<select id="direction">
			<option value="in">In (download)</option>
			<option value="out">Out (upload)</option>
			<option value="combined">Combined</option>
		</select>
	</div>
	<div id="amount-field" class="hidden">
		<label for="amount">Show as</label>
		<select id="amount">
			<option value="percent">Percent</option>
			<option value="used">Used of total</option>
		</select>
	</div>
	<div id="threshold-field" class="hidden">
		<div class="row">
			<div><label for="warn" id="warn-label">Warn at</label><input id="warn" type="number" step="any" /></div>
			<div><label for="crit" id="crit-label">Critical at</label><input id="crit" type="number" step="any" /></div>
		</div>
	</div>
	<label for="interval_secs">Refresh every (seconds)</label>
	<input id="interval_secs" type="number" min="2" step="1" />
	<div class="hint">Keys reading the same data share one request, at the fastest interval any of them asks for.</div>

	<script>
		window.connectOpenActionSocketData = new Promise((resolve) => {
			window.connectOpenActionSocket = (...args) => resolve(args);
			window.connectElgatoStreamDeckSocket = window.connectOpenActionSocket;
		});

		const $ = (id) => document.getElementById(id);
		// Which fields each action shows, keyed by the last part of its UUID.
		const FIELDS = {
			cpu: { cpu: true, thresholds: "%" },
			ram: { amount: true, thresholds: "%" },
			network: { target: "Interface", direction: true, thresholds: "MB/s" },
			systemp: { thresholds: "°C" },
			uptime: {},
			disktemp: { target: "Disk", thresholds: "°C" },
			diskhealth: { target: "Disk" },
			volume: { target: "Volume", amount: true, thresholds: "%" },
			pool: { target: "Pool" },
			update: {},
		};
		let websocket;
		let uuid;
		let action;
		// Always sent whole: setSettings replaces the key's settings, so
		// fields this action ignores must still round-trip untouched.
		let settings = {};
		let pollTimer;
		let connectionShown = false;

		window.connectOpenActionSocketData.then(([inPort, inUUID, inRegisterEvent, _inInfo, inActionInfo]) => {
			uuid = inUUID;
			const actionInfo = JSON.parse(inActionInfo);
			action = actionInfo.action;
			const fields = FIELDS[action.split(".").pop()] || {};
			$("target-field").classList.toggle("hidden", !fields.target);
			$("target-label").textContent = fields.target || "Show";
			$("cpu-field").classList.toggle("hidden", !fields.cpu);
			$("direction-field").classList.toggle("hidden", !fields.direction);
			$("amount-field").classList.toggle("hidden", !fields.amount);
			$("threshold-field").classList.toggle("hidden", !fields.thresholds);
			$("warn-label").textContent = `Warn at (${fields.thresholds || ""})`;
			$("crit-label").textContent = `Critical at (${fields.thresholds || ""})`;

			websocket = new WebSocket(`ws://127.0.0.1:${inPort}`);
			websocket.onopen = () => {
				websocket.send(JSON.stringify({ event: inRegisterEvent, uuid: inUUID }));
				applySettings(actionInfo.payload.settings || {});
				toPlugin({ event: "getState" });
				// The status changes on its own (a login finishing, the NAS
				// going offline), so keep asking while the panel is open.
				pollTimer = setInterval(() => toPlugin({ event: "getState" }), 2000);
			};
			websocket.onclose = () => clearInterval(pollTimer);
			websocket.onmessage = (event) => {
				const message = JSON.parse(event.data);
				if (message.event === "didReceiveSettings") {
					applySettings(message.payload.settings || {});
				} else if (message.event === "sendToPropertyInspector" && message.payload.event === "state") {
					applyState(message.payload);
				}
			};
		});

		function toPlugin(payload) {
			websocket.send(JSON.stringify({ event: "sendToPlugin", action, context: uuid, payload }));
		}

		function sendSettings() {
			websocket.send(JSON.stringify({ event: "setSettings", context: uuid, payload: settings }));
		}

		// An empty field must become null, never "": one field the plugin
		// can't read makes it fall back to default settings for the key.
		function numberOrNull(input) {
			const n = input.valueAsNumber;
			return Number.isFinite(n) ? n : null;
		}

		function secondsOrNull(input) {
			const n = numberOrNull(input);
			return n === null ? null : Math.max(2, Math.round(n));
		}

		function applySettings(s) {
			settings = s;
			$("cpu_view").value = s.cpu_view || "total";
			$("direction").value = s.direction || "in";
			$("amount").value = s.amount || "percent";
			$("warn").value = s.warn ?? "";
			$("crit").value = s.crit ?? "";
			$("interval_secs").value = s.interval_secs ?? "";
			$("target").value = s.target ?? "";
		}

		function applyState(st) {
			// Fill the connection fields once, so polling never overwrites typing.
			if (!connectionShown) {
				connectionShown = true;
				$("host").value = st.connection.host;
				$("port").value = st.connection.port;
				$("account").value = st.connection.account;
				$("https").checked = st.connection.https;
				$("temp-unit").value = st.tempUnit;
			}
			$("http-warning").classList.toggle("hidden", $("https").checked);
			$("password").placeholder = st.hasPassword ? "•••••••• (in the system keyring)" : "";
			$("password-hint").textContent = st.hasPassword ? "Leave empty to keep the saved password." : "";

			const kind = st.status.kind;
			$("status").textContent = st.status.text + (kind === "connected" && st.status.firmware ? ` · ${st.status.firmware}` : "");
			$("status").className = kind === "connected" ? "ok" : ["auth", "certificate", "unreachable"].includes(kind) ? "bad" : "";
			$("otp-box").classList.toggle("hidden", kind !== "needOtp");
			$("cert-box").classList.toggle("hidden", kind !== "certificate");
			$("fingerprint").textContent = st.status.fingerprint || "";

			$("warn").placeholder = st.defaults.warn ?? "";
			$("crit").placeholder = st.defaults.crit ?? "";
			$("interval_secs").placeholder = st.defaults.interval;
			fillTargets(st.targets);
		}

		function fillTargets(targets) {
			const select = $("target");
			const key = JSON.stringify(targets);
			if (select.dataset.key === key) return; // unchanged: keep the open dropdown
			select.dataset.key = key;
			select.innerHTML = "";
			for (const t of targets) {
				const option = document.createElement("option");
				option.value = t.id ?? "";
				option.textContent = t.label;
				select.appendChild(option);
			}
			if (targets.length === 0) {
				const option = document.createElement("option");
				option.value = settings.target ?? "";
				option.textContent = "Waiting for data from the NAS…";
				select.appendChild(option);
			}
			select.value = settings.target ?? (targets[0]?.id ?? "");
		}

		$("save").addEventListener("click", () => {
			toPlugin({
				event: "saveConnection",
				host: $("host").value.trim(),
				port: Number($("port").value) || 5001,
				https: $("https").checked,
				account: $("account").value.trim(),
				password: $("password").value || null,
			});
			$("password").value = "";
		});
		$("https").addEventListener("change", () => {
			$("http-warning").classList.toggle("hidden", $("https").checked);
			$("port").value = $("https").checked ? 5001 : 5000;
		});
		$("submit-otp").addEventListener("click", () => {
			toPlugin({ event: "submitOtp", code: $("otp").value });
			$("otp").value = "";
		});
		$("otp").addEventListener("keydown", (e) => {
			if (e.key === "Enter") $("submit-otp").click();
		});
		$("trust").addEventListener("click", () => toPlugin({ event: "trustCertificate" }));
		$("temp-unit").addEventListener("change", () => toPlugin({ event: "setTempUnit", unit: $("temp-unit").value }));

		$("target").addEventListener("change", () => {
			settings.target = $("target").value || null;
			sendSettings();
		});
		for (const id of ["cpu_view", "direction", "amount"]) {
			$(id).addEventListener("change", () => {
				settings[id] = $(id).value;
				sendSettings();
			});
		}
		for (const id of ["warn", "crit"]) {
			$(id).addEventListener("change", () => {
				settings[id] = numberOrNull($(id));
				sendSettings();
			});
		}
		$("interval_secs").addEventListener("change", () => {
			settings.interval_secs = secondsOrNull($("interval_secs"));
			sendSettings();
		});
	</script>
</body>
</html>
```

- [ ] **Step 6: Run the tests and a syntax check on the panel script**

Run: `cargo test && cargo fmt && cargo clippy --all-targets -- -D warnings`
Expected: PASS (including 5 new inspector tests), no warnings.

Run: `node -e "const h=require('fs').readFileSync('assets/propertyInspector/index.html','utf8'); new Function(h.split('<script>')[1].split('</script>')[0]); console.log('script parses')"`
Expected: `script parses`.

- [ ] **Step 7: Commit**

```bash
git add src/inspector.rs src/actions.rs src/main.rs assets/propertyInspector
git commit -m "feat: add the settings panel with connection, 2FA and certificate trust

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---
### Task 16: Wire up `main`, remove the dead-code allowance, write the README

**Files:**
- Modify: `src/main.rs` (full rewrite), plus whichever files the dead-code step flags
- Create: `README.md`

**Interfaces:**
- Consumes: everything above
- Produces: the runnable plugin binary

- [ ] **Step 1: Rewrite `src/main.rs`**

```rust
mod actions;
mod dsm;
mod format;
mod inspector;
mod instances;
mod metric;
mod metrics;
mod poller;
mod render;
mod secrets;
mod services;
mod settings;
mod status;

use async_trait::async_trait;
use dsm::transport::{HttpTransport, Transport};
use instances::Instances;
use openaction::global_events::{DidReceiveGlobalSettingsEvent, GlobalEventHandler, set_global_event_handler};
use openaction::{OpenActionResult, run};
use secrets::KeyringStore;
use services::{Services, SettingsSink, TransportFactory};
use settings::{Connection, GlobalSettings};
use std::sync::Arc;

/// Persists plugin-wide settings through OpenDeck.
struct OpenDeckSettings;

#[async_trait]
impl SettingsSink for OpenDeckSettings {
    async fn save(&self, settings: &GlobalSettings) {
        if let Err(e) = openaction::set_global_settings(settings).await {
            log::warn!("saving the plugin settings failed: {e}");
        }
    }
}

struct GlobalEvents {
    services: Arc<Services>,
}

#[async_trait]
impl GlobalEventHandler for GlobalEvents {
    async fn plugin_ready(&self) -> OpenActionResult<()> {
        openaction::get_global_settings().await
    }

    async fn did_receive_global_settings(&self, event: DidReceiveGlobalSettingsEvent) -> OpenActionResult<()> {
        let settings = serde_json::from_value(event.payload.settings).unwrap_or_else(|e| {
            log::warn!("unreadable plugin settings, starting from defaults: {e}");
            GlobalSettings::default()
        });
        self.services.load_global(settings).await;
        Ok(())
    }
}

#[tokio::main]
async fn main() -> OpenActionResult<()> {
    simplelog::SimpleLogger::init(log::LevelFilter::Info, simplelog::Config::default()).expect("logger init");

    let device_name = format!("OpenDeck-{}", gethostname::gethostname().to_string_lossy());
    let transports: TransportFactory =
        Arc::new(|conn: &Connection| Ok(Arc::new(HttpTransport::new(conn)?) as Arc<dyn Transport>));
    let services = Services::new(Arc::new(KeyringStore), Arc::new(OpenDeckSettings), transports, device_name);
    let instances = Arc::new(Instances::default());

    // openaction keeps a 'static reference; the handler lives as long as the process.
    set_global_event_handler(Box::leak(Box::new(GlobalEvents { services: services.clone() })));
    actions::register_all(&services, &instances).await;

    let result = run(std::env::args().collect()).await;
    // OpenDeck closed the connection: end the DSM session instead of leaving
    // it to time out.
    services.logout().await;
    result
}
```

Note that the `#![allow(dead_code)]` line from Task 1 is gone.

- [ ] **Step 2: Fix the dead-code warnings**

Run: `cargo clippy --all-targets -- -D warnings`

Expected: a few "never used" errors for items only the tests use. Fix each one in one of two ways:
- **Used by tests only:** mark it `#[cfg(test)]`. Expected candidates: `Poller::effective_interval`, `Instances::view`, `Metric::ALL`.
- **Used by nothing, tests included:** delete it together with its tests. Expected candidate: `format::bytes`, which `metrics` never calls. Delete the function and its test, and keep the private `number` helper that `used_of_total` uses.

Don't add `#[allow(dead_code)]` anywhere. Repeat until clippy is clean, then run `cargo test`.
Expected: clean; all tests pass.

- [ ] **Step 3: Build and package once**

Run:
```bash
cargo build --release --target x86_64-unknown-linux-gnu && node build.mjs x86_64-unknown-linux-gnu && ls dist/com.jfms7s.synology.sdPlugin
```
Expected: the listing shows `manifest.json`, `icons/` (PNG files only, no `source/`), `layouts/`, `propertyInspector/` and `opendeck-synology-x86_64-unknown-linux-gnu`.

- [ ] **Step 4: Write `README.md`**

````markdown
# OpenDeck Synology

An [OpenDeck](https://github.com/nekename/OpenDeck) plugin that turns Stream Deck keys
and dials into a live, read-only status panel for a Synology NAS running **DSM 7**.
It is modelled on *DeckPulse Synology DSM 7* from the Elgato Marketplace, and adds
dial support and sign-in for DSM accounts with **2-factor authentication**.

## Actions

Every action works on a key and on a dial. Pressing a key or a dial refreshes it now.

| Action | Shows | Turning the dial |
|---|---|---|
| CPU | usage % | usage → 1 / 5 / 15 min load average |
| RAM | memory in use | percent → used of total |
| Network | throughput of all interfaces or one | in → out → combined |
| System Temperature | the NAS's system sensor | - |
| Uptime | e.g. `12d 5h` | - |
| Disk Temperature | one disk, or the hottest | each disk → hottest |
| Disk Health | S.M.A.R.T. OK / Warning / Failing, one disk or the worst | each disk → worst |
| Volume | how full, as % or used of total | each volume |
| Storage Pool | Normal / Degraded / Rebuild 43 % | each pool |
| DSM Update | up to date, or the pending version | - |

Numeric actions have **warn** and **critical** thresholds (the key turns amber or red).
The defaults are CPU 70/90 %, RAM 80/95 %, system temperature 60/70 °C, disk temperature
50/60 °C and volume 80/90 %; network thresholds are off until you set them, in MB/s. Each
key can also override its **refresh interval** (at least 2 s). Keys reading the same data
share one request to the NAS at the fastest interval any of them asks for.

When the NAS stops answering, keys keep the last value and turn grey with a `!` after
three missed refreshes; they never drop to a misleading zero.

## Setting up

1. Add any Synology action and open its settings.
2. Enter the NAS's host or IP address, the port (5001 for HTTPS), your DSM account and
   password, then **Save and connect**. These are shared by every key; the password is
   stored in the system keyring (GNOME Keyring / KWallet via Secret Service), not in
   OpenDeck's settings file.
3. **Self-signed certificate** (the DSM default): the panel shows the certificate's SHA-256
   fingerprint. Compare it with DSM › Control Panel › Security › Certificate, then
   **Trust this certificate**. If the certificate later changes, keys show `Cert` until
   you trust the new one.
4. **2FA**: when the status says *Needs 2FA code*, enter a code from your authenticator app.
   DSM then remembers this computer (it appears under Personal › Security › Trusted devices),
   so you're not asked again - not even after restarting OpenDeck or the NAS. Removing the
   device there makes the plugin ask for a code once more.

The **Disk Temperature**, **Disk Health**, **Volume** and **Storage Pool** actions read
DSM's storage manager API, which DSM usually only allows for members of the
*administrators* group. With a non-admin account those four show `Denied`; the rest work.

A wrong password or 2FA code is never retried automatically, so the plugin can't trip
DSM's auto-block. If your IP does get blocked, unblock it in Control Panel › Security ›
Protection.

## Privacy

The plugin talks only to the NAS you configure. No analytics, telemetry or third-party
services. Every DSM parameter, including the password, is sent in the HTTPS request body,
never in a URL, and nothing secret is written to the log.

## Installing

Download the latest `.streamDeckPlugin` from
[Releases](https://github.com/jfms7s/opendeck-synology/releases), then either double-click
it (if your file manager associates the extension with OpenDeck) or unzip it into
`~/.config/opendeck/plugins/` and restart OpenDeck.

## Developing

```bash
cargo test                                  # unit tests, no NAS needed
scripts/capture-fixtures.sh nas.lan jf      # record redacted responses from a real NAS
scripts/render-icons.sh                     # regenerate PNG icons (needs ImageMagick 7)
cargo test keyring_round_trip -- --ignored  # check the system keyring works
```

## Manual smoke-test checklist

Run this against a live OpenDeck + Stream Deck (with dials) and a DSM 7 NAS with 2FA,
before cutting a release:

- [ ] Fresh install: keys show `Set up`; saving the connection with a self-signed
      certificate shows its fingerprint; trusting it moves on to *Needs 2FA code*.
- [ ] Entering a wrong 2FA code shows *Wrong 2FA code*; the right one connects, and the
      device appears under DSM › Personal › Security › Trusted devices.
- [ ] Restarting OpenDeck reconnects without asking for a code.
- [ ] A wrong password shows *Wrong account or password* and DSM's log shows exactly one
      failed login, not one per refresh.
- [ ] Each of the ten actions shows a sensible value on a key and on a dial; rotating each
      dial cycles as described above and the subject line shows `‹ … n/m ›`.
- [ ] Setting a CPU warn threshold below the current load turns the key amber.
- [ ] Unplugging the NAS's network cable: keys turn grey with `!` within three refreshes
      and recover by themselves after reconnecting.
- [ ] Rebooting the NAS: keys go stale, then recover without a 2FA prompt.
- [ ] Replacing the DSM certificate (or pinning a wrong one by editing the settings):
      keys show `Cert` and the panel offers to trust the new fingerprint.
- [ ] Switching °C/°F redraws temperature keys immediately.
- [ ] `~/.config/opendeck/` contains no password (grep for it), unless the log warned that
      no keyring was available.
````

- [ ] **Step 5: Commit**

```bash
git add src README.md
git commit -m "feat: wire the plugin together and document setup and smoke tests

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 17: Manual smoke test against the real NAS, then release

This task needs the user at their Stream Deck. The implementer prepares everything, walks the user through the checklist and records the results. Nothing is pushed or published without the user's explicit go-ahead.

**Files:**
- Modify: whatever the smoke test shows is broken (each fix gets its own failing test first, then a commit)

- [ ] **Step 1: Install the build locally**

```bash
cargo build --release --target x86_64-unknown-linux-gnu
node build.mjs x86_64-unknown-linux-gnu
rm -rf ~/.config/opendeck/plugins/com.jfms7s.synology.sdPlugin
cp -r dist/com.jfms7s.synology.sdPlugin ~/.config/opendeck/plugins/
```
Then ask the user to restart OpenDeck (plugins load only at startup).

- [ ] **Step 2: Walk through the README's smoke-test checklist with the user**

Go through it item by item. For anything that fails:
1. Read OpenDeck's plugin log for `com.jfms7s.synology` (check that it contains no secrets while you're there).
2. Reproduce the problem in a unit test.
3. Fix it, and commit with `fix: ...`.
4. Rebuild, reinstall, and re-check that item.

- [ ] **Step 3: Offer to publish**

When every item passes, ask the user whether to:
- create the GitHub repository `jfms7s/opendeck-synology` and push `master`
- tag `v0.1.0` and publish a GitHub release; the release workflow attaches `opendeck-synology.streamDeckPlugin`

Do each only after an explicit yes.
