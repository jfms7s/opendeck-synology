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
three failed refreshes in a row; they never drop to a misleading zero. Retries back off
(the wait doubles after each failure, up to 5 minutes), so three failures take about
seven refresh intervals after the last good value - 35 s for a key refreshing every 5 s,
7 minutes for the 60 s storage keys. Adding or removing keys during an outage doesn't
cut the backoff short; pressing a key retries at once. Keys recover by themselves on the
first successful refresh.

## Setting up

1. Add any Synology action and open its settings.
2. Enter the NAS's host or IP address, the port (5001 for HTTPS), your DSM account and
   password, then **Save and connect**. These are shared by every key; the password is
   stored in the system keyring (GNOME Keyring / KWallet via Secret Service), not in
   OpenDeck's settings file. The panel says where it actually is (see
   [Without a keyring](#without-a-keyring-flatpak)).
3. **Self-signed certificate** (the DSM default): the panel shows the certificate's SHA-256
   fingerprint. Compare it with DSM › Control Panel › Security › Certificate, then
   **Trust this certificate**. Only that exact fingerprint is trusted: if the NAS presents
   another one by the time you click, nothing is pinned and the panel shows the new one.
   If the certificate later changes, keys show `Cert` and the panel warns that someone may
   be intercepting the connection; only trust the new fingerprint once you have checked it
   on the NAS. A trusted (pinned) certificate is accepted for any name you reach the NAS
   by, since users often use its IP address. A certificate that is valid for the host name
   against the system's certificate authorities (e.g. Let's Encrypt on a `synology.me`
   name) is accepted too, pinned or not - so a pin adds trust in the NAS's own
   certificate but doesn't restrict publicly valid ones.
4. **2FA**: when the status says *Needs 2FA code*, enter a code from your authenticator app.
   DSM then remembers this computer (it appears under Personal › Security › Trusted devices),
   so you're not asked again - not even after restarting OpenDeck or the NAS. Removing the
   device there makes the plugin ask for a code once more.

The **Disk Temperature**, **Disk Health**, **Volume** and **Storage Pool** actions read
DSM's storage manager API, which DSM usually only allows for members of the
*administrators* group. With a non-admin account those four show `Denied`; the rest work.

A wrong password or 2FA code is never retried automatically, so the plugin can't trip
DSM's auto-block. An empty or malformed 2FA code is never sent at all. If your IP does
get blocked, unblock it in Control Panel › Security › Protection.

### Plain HTTP

Unticking **HTTPS** (port 5000) sends the password unencrypted at every sign-in. Saved
secrets belong to one account, scheme, host and port: a password saved for HTTPS is
never sent over HTTP - switching asks for it again - and over HTTP no 2FA device token is
used or stored, so with 2FA you're asked for a code at every sign-in (a password plus a
device token sniffed off the network would get past 2FA).

### Without a keyring (Flatpak)

If no Secret Service keyring can be used - most often because OpenDeck runs as a
**Flatpak**, which can't reach it unless allowed - the password is kept in OpenDeck's
settings file instead, and the panel says so. The 2FA device token is then only kept in
memory, so a code is asked for again after each OpenDeck restart. To let the Flatpak use
the keyring:

```bash
flatpak override --user --talk-name=org.freedesktop.secrets me.amankhanna.opendeck
```

then restart OpenDeck and save the password again. If the keyring is there but can't be
read yet (e.g. still locked right after logging in), keys show `Keyring` and the plugin
tries again a few times.

## Privacy

The plugin talks only to the NAS you configure. No analytics, telemetry or third-party
services. Every DSM parameter, including the password, is sent in the request body,
never in a URL; redirects are never followed, so the login can't be bounced elsewhere; and
nothing secret is written to the log.

## Installing

Download the latest `.streamDeckPlugin` and `SHA256SUMS` from
[Releases](https://github.com/jfms7s/opendeck-synology/releases) and check the download
with `sha256sum -c SHA256SUMS`. Then either double-click it (if your file manager
associates the extension with OpenDeck) or unzip it into `~/.config/opendeck/plugins/`
and restart OpenDeck. The bundle runs on Linux x86_64 and aarch64.

## Development

```bash
cargo fmt --check                                  # the same checks CI runs
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked                                # unit tests, no NAS needed
cargo build --release --locked && node build.mjs   # dist/opendeck-synology.streamDeckPlugin
cargo test keyring_round_trip -- --ignored         # check the system keyring works
scripts/render-icons.sh                            # regenerate icons (needs ImageMagick 7)

# Record redacted responses from a real NAS into tests/fixtures/real/ (git-ignored).
# PIN_SHA256 is the certificate fingerprint the settings panel shows.
PIN_SHA256=ab12... scripts/capture-fixtures.sh nas.lan jf
REQUIRE_REAL_FIXTURES=1 cargo test recorded        # then check the parsers against them
```

The toolchain is pinned in CI (`rust-version` in `Cargo.toml` is the oldest supported
Rust). Releases: bump the version in `Cargo.toml`, `Cargo.lock` and
`assets/manifest.json`, then push a `vX.Y.Z` tag; the Release workflow checks, builds both
architectures and creates a **draft** release with the bundle and `SHA256SUMS`, which you
publish after a look.

## Manual smoke-test checklist

Run this against a live OpenDeck + Stream Deck (with dials) and a DSM 7 NAS with 2FA,
before publishing a release, and record the result per item (pass / fail / **not run**, with
why - e.g. "NAS has a public certificate") in that release's smoke log. Items that need a
self-signed certificate can't pass against a NAS with a publicly trusted one.

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
- [ ] Unplugging the NAS's network cable: keys turn grey with `!` about seven refresh
      intervals after the last good value (35 s for CPU) and recover by themselves after
      reconnecting.
- [ ] Rebooting the NAS: keys go stale, then recover without a 2FA prompt.
- [ ] Replacing the DSM certificate (or pinning a wrong one by editing the settings):
      keys show `Cert` and the panel warns that the certificate changed before offering
      to trust the new fingerprint.
- [ ] Switching °C/°F redraws temperature keys immediately.
- [ ] `~/.config/opendeck/` contains no password (grep for it), unless the panel says the
      password is in OpenDeck's settings file.
- [ ] Unticking HTTPS and saving with an empty password field asks for the password
      instead of connecting.
- [ ] An out-of-range port (e.g. 70000) shows an error and keeps what was typed.
- [ ] Pressing Verify with an empty 2FA field sends nothing (DSM's log shows no failed
      sign-in).
- [ ] After all of the above, DSM › Control Panel › Security › Account activity (or
      Resource Monitor › Connections) lists at most one `OpenDeck` session for the account.
- [ ] The settings panel shows the DSM version in its status line with only a CPU key on
      the deck.

## License

MIT — see [LICENSE](LICENSE).
