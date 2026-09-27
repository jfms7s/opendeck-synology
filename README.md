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
