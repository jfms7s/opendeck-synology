# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A Rust [OpenDeck](https://github.com/nekename/OpenDeck) plugin (Linux x86_64 + aarch64 and Apple Silicon macOS, on the `openaction` crate) showing live, read-only status of one Synology NAS running DSM 7 on Stream Deck keys and dials: ten actions (CPU, RAM, network, temperatures, disks, volumes, pools, uptime, DSM update). It signs in with 2FA (device token), pins self-signed certificates, and keeps secrets in the system keyring (Secret Service on Linux, the login Keychain on macOS). The README is the user-facing spec and holds the manual smoke-test checklist.

## Commands

```bash
cargo fmt --check                                   # CI gate
cargo clippy --all-targets --locked -- -D warnings  # CI gate
cargo test --locked                                 # no NAS, no OpenDeck, no keyring needed
cargo build --release --locked && node build.mjs    # dist/opendeck-synology.streamDeckPlugin + SHA256SUMS
node build.mjs --check-version                      # Cargo.toml and manifest.json versions agree
REQUIRE_REAL_FIXTURES=1 cargo test recorded         # parsers vs. local real NAS captures
```

## Architecture

`actions.rs` (one generic `MetricAction` per metric, from the single `kinds!` list) → `instances.rs` (one render task per visible key/dial; redraws only on change) → `services.rs` (`Services`: settings, the one `dsm::Session`, four `poller::Poller`s, the `ConnStatus` and display watch channels, the connection epoch) → `dsm/` (`endpoint.rs` which API/method/parser per endpoint, `api.rs` discovery, `session.rs` login/re-login/2FA, `transport.rs` HTTP + `tls.rs` pinning verifier, `model.rs` parsing). `metrics.rs` (pure: poll state → `Reading`) → `render/` (pure SVG / dial JSON). `secrets.rs` (`Vault`: keyring, settings-file fallback, migration), `inspector.rs` (settings panel protocol), `metric.rs` (the catalogue, incl. per-metric panel fields). Design and history: the vault, `~/git/obsidian-vault/personal/projects/opendeck-synology/` (`specs/` has the as-built architecture).

## Hard rules

- **Never retry a failed login.** Codes 400-410 (`AuthError`) block the session until the user acts (`Session.blocked`, pollers pause on `needs_user()`); retrying a wrong password or 2FA code trips DSM's auto-block. Only 105/106/107/119 get one silent re-login, shared by all callers via the session `generation`. Never send an empty or malformed 2FA code.
- **One session, one connection epoch.** Every late callback (poll result, device token, firmware lookup) checks `Services::is_current(epoch)`; the poller's `generation` guards its own state. Log the old session out only after the pollers moved off it.
- **No secret in a URL, a log line or `Debug` output.** All DSM parameters go in the POST body; settings-panel payloads are never logged; `Credentials` and `FallbackSecrets` redact `Debug`; error text drops URLs.
- **Secrets are scoped to account + scheme + host + port** (`Connection::secret_scope`). A secret saved for HTTPS is never sent over HTTP; over HTTP no device token is sent or stored. Without a keyring the password may go to the settings file (the panel must say so), the device token never does.
- **Keep `keyring`'s `apple-native` feature.** keyring enables backends per OS; without it a macOS build silently uses an in-memory mock store and loses every secret.
- **Certificates:** trust only the fingerprint the user saw (`trust_certificate(fp)`); never add an "accept any certificate" path. Redirects are never followed.
- **No zero for missing data**: an absent field shows `N/A`/`Missing`, unknown DSM state words count as a warning.
- Version lives in `Cargo.toml`, `Cargo.lock` and `assets/manifest.json`; `build.mjs` refuses a mismatch. Releases: push a `vX.Y.Z` tag → draft release with bundle + `SHA256SUMS` → publish by hand after the smoke checklist.
- `tests/fixtures/real/` holds captures from the author's NAS and stays git-ignored; committed fixtures are hand-written (`tests/fixtures/dsm7/` copies the real response shapes).

## Conventions

- Conventional Commits; PRs squash-merged to `master`; CI actions are pinned to commit SHAs.
- Project docs (specs, plans, reviews, issues) live in the Obsidian vault at `~/git/obsidian-vault/personal/projects/opendeck-synology/`, not in this repo; follow the vault's `CLAUDE.md`.
- Behaviour bugs get a failing test first (fake NAS: `dsm::fake::FakeDsm`, fake keyring: `secrets::MemoryStore`; never the real keyring or a real NAS in tests). The one exception is the `#[ignore]`d `keyring_round_trip`, which CI runs on its throwaway macOS runner to prove secrets really persist.
- User-visible changes go in the README (actions, setup, smoke-test checklist).
