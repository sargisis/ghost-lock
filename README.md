# ghost-lock

**iPhone security audit & hardening toolkit that works on top of Lockdown Mode.**
A local Python + Go toolset: crash-log forensics against Pegasus/Predator-class
spyware, automatic audits on USB connect, hardening profiles installed on the
phone, and Telegram alerts.

No jailbreak. No Apple Developer account. No third-party apps on the phone.
Everything runs locally.

---

## How it works

iOS is a closed system: without a jailbreak you cannot install a background
daemon into the phone or bolt anything onto Lockdown Mode. So ghost-lock is
built entirely on legitimate mechanisms and covers **four independent layers**:

| Layer | Where | What it does |
|---|---|---|
| **Lockdown Mode** | Phone | Apple's baseline — ghost-lock doesn't touch it, it complements it |
| **Profiles** (`dns_shield`, `hardened`, `web_filter`) | Phone, always-on | Encrypted DNS, system restrictions, spyware domain blocklist enforced at the WebKit level |
| **Audit** (`audit`) | PC, over cable | Forensics: scans exported crash logs, installed apps, security hygiene; keeps history and diffs between checks |
| **Automation** (`glock-watch`) | PC, always-on | Sees the phone hit USB → runs the audit → sends the verdict to Telegram |

Philosophy: **Lockdown Mode prevents; ghost-lock detects and verifies.**

## Quick start

> **Linux · macOS · Windows:** full per-platform installation guide in
> [docs/INSTALL.md](docs/INSTALL.md) (RU: [docs/INSTALL.ru.md](docs/INSTALL.ru.md)).
> The auto-audit daemon is Linux-only; everything else is cross-platform.

```bash
sudo apt install libimobiledevice-utils   # if not present yet
python3 ghost_lock/ghost_lock.py doctor   # environment check
python3 ghost_lock/ghost_lock.py devices  # list connected iPhones
python3 ghost_lock/ghost_lock.py audit    # full audit + HTML report
```

On first connect, unlock the phone and tap "Trust This Computer".
Reports land in `~/.local/share/ghost-lock/reports/`.

## Commands

```
doctor           environment check
devices          list connected devices
audit            full audit (--udid <UDID>, --deep for forensic mode)
profiles         generate phone profiles (+ --serve to serve over Wi-Fi)
setup-telegram   connect alerts (needs a token from @BotFather)
update-ioc       refresh the indicator database from AmnestyTech STIX feeds
dns-check        test encrypted DNS on the current network (phone presets + this PC)
sysdiagnose      pull a sysdiagnose over the cable and check shutdown.log
```

## Inside the audit

1. **Crash-log export** — the richest evidence source: crash logs retain
   mentions of C2 domains, implant names, jailbreak artifacts.
2. **IOC scan** by a hybrid engine: heavy lifting in Go (worker pool), URL and
   phishing heuristics in Python. An allowlist suppresses false positives
   (e.g. the legit `Pegasus.framework` shipped inside iOS itself).
3. **App inventory scan** against known stalkerware bundle IDs
   (mSpy/FlexiSPY/CocoSpy/uMobix/EyeZy…).
   **Installed configuration profiles** are listed over the cable in seconds
   (needs `pymobiledevice3`, see below): anything not from ghost-lock is
   flagged on every audit, not only in deep mode. Names only — what a foreign
   profile contains (MDM, certificate, VPN) is shown by `audit --deep`.
4. **Security hygiene**: everything readable over cable (activation state,
   passcode status), with honest "unreadable" marks where iOS refuses to talk.
5. **iOS freshness check** via api.ipsw.me — an outdated OS means known
   exploits stay usable.
6. **"What changed" diff**: new/removed apps, never-seen-before crash logs,
   compared against the entire audit history (SQLite).

Scoring: `<3` clean · `3–14` suspicious · `≥15` critical.

### Deep mode

```bash
python3 ghost_lock/ghost_lock.py audit --deep
```

A full device backup via `idevicebackup2` (SMS databases, Safari history,
network usage) followed by a sweep of everything inside. The first run takes
tens of minutes; later ones are incremental and fast. A regular audit sees
hundreds of files — deep mode sees tens of thousands.

**Encrypted backups.** The `hardened` profile turns on `forceEncryptedBackup`,
so after installing it the phone only hands out ciphertext. ghost-lock asks the
phone *before* the backup whether it will be encrypted, takes the backup
password from `GHOST_LOCK_BACKUP_PASSWORD` or a keyboard prompt, decrypts into
a temporary folder (`pip install cryptography`), scans it and deletes the
plaintext copy right away. No password or a wrong one → the audit is marked
**INCOMPLETE** in the console, the report and Telegram — a scan of ciphertext
is never reported as "clean". An unencrypted backup triggers a warning: it sits
on disk in plaintext; enable encryption with
`idevicebackup2 -i -u <UDID> encryption on`.

### Profile & certificate audit (deep mode)

Stalkerware and "corporate" surveillance often arrive as a **configuration
profile**, not an app. While the decrypted backup is still in place, deep mode
inspects:

- **Foreign profiles**, weighted by power: MDM (15), root certificate or global
  proxy (10), VPN (8), third-party DNS or web filter (7), plus the
  `stalkerware_profiles` IOC prefixes. A profile counts as ghost-lock's only if
  its *contents* match too (payload type, DoH server from our presets), since
  the `cc.ghostlock.*` name is trivial to fake.
- **User-trusted certificates** in `TrustStore.sqlite3` (MITM risk).
- **Supervision** (`CloudConfigurationDetails.plist`).
- **Your own coverage**: which ghost-lock profiles are installed, whether the
  Domain Wall list matches the current IOC database, and how many `hardened`
  restrictions iOS actually enforces (`EffectiveUserSettings.plist`).

Needs an encrypted backup: in an unencrypted one the files have hashed names.

### shutdown.log (sysdiagnose)

On every reboot iOS logs the processes that delayed shutdown. Kaspersky's
2024 "iShutdown" research showed Pegasus, Reign and Predator implants
lingering there from unusual places (`/private/var/db/`, `/private/var/tmp/`),
and the log survives implant removal while keeping many reboots of history.
ghost-lock reads only `shutdown.log` from the newest `sysdiagnose_*.tar.gz`,
in memory, and flags such paths plus IOC process names and file paths.

Take a sysdiagnose on the phone (both volume buttons + side button for
1–1.5 s, a short vibration; it takes ~10 minutes to build). The next `audit`
picks it up, or pull and check it right away over the cable:

```bash
python3 ghost_lock/ghost_lock.py sysdiagnose
```

### Per-process network statistics (deep mode)

iOS records every process that went online in `DataUsage.sqlite`; an implant's
name stays there even after its binary is gone. The process name is a
dedicated field, so it is matched **exactly** against the IOC `processes`
section (not as a substring, which is why that section stays off for crash
logs). Names that coincide with real Apple daemons (`roleaccountd`,
`updaterd`) are reported at low weight for manual review; process paths are
also checked against `file_paths`. Traffic rows that point at a deleted
process row — a cleanup trace MVT looks for — are counted and shown as
information until a clean-phone baseline is known.

## Audit history & diff

Every audit is stored in `~/.local/share/ghost-lock/history.db`.
The next check prints the delta:

```
[*] What changed since last time…
  🆕 New apps (1): com.evil.stalker
  📉 New crash logs: 14
```

Stalkerware is easiest to catch by its *delta*, not its absolute footprint.
The top diff lines ride along in every Telegram alert.

## Phone profiles

```bash
python3 ghost_lock/ghost_lock.py profiles --usb     # over the cable (recommended)
python3 ghost_lock/ghost_lock.py profiles --serve   # over Wi-Fi
# or simply send the files from ghost_lock/profiles/ to yourself
```

**Over the cable** (`--usb`) needs no network: serving over Wi-Fi often fails
silently because the PC firewall drops inbound connections or the router
isolates Wi-Fi clients. It uses `pymobiledevice3`, installed into its own
environment (Debian/Ubuntu block system-wide pip, PEP 668):

```bash
python3 -m venv ~/.local/share/ghost-lock/venv
~/.local/share/ghost-lock/venv/bin/pip install pymobiledevice3
```

Profiles are sent one by one; confirm each on the phone (Install → passcode).
`--hardened` adds the restrictions profile. Verified on iOS 27: the phone
rejects `profile store` for a DNS payload ("not permitted", error 4022), while
`profile install` shows the normal install prompt — ghost-lock uses the latter.

On the phone: open the file → Install. Verify under Settings → General →
VPN & Device Management. iOS will warn "Profile is not signed" — expected for
manually installed profiles.

> Installing new profiles requires temporarily disabling Lockdown Mode
> (Settings → Privacy & Security). Re-enable it afterwards.

| File | Payload type | Purpose |
|---|---|---|
| `dns_shield.mobileconfig` | DNS Settings (DoH) | Encrypted DNS with resolver-level filtering. Pins the DoH server's IPs (`ServerAddresses`) and never falls back to plain DNS (`AllowFailover=false`) |
| `web_filter.mobileconfig` | Web Content Filter | **Spyware Domain Wall**: the top-500 C2 domains of Pegasus/Predator/FinFisher blocked at the Safari/WebKit level — a second line of defense that works even off our DNS |
| `hardened.mobileconfig` | Restrictions | System restrictions stacked on top of Lockdown Mode |

DNS presets:

| Preset | Blocks | Example |
|---|---|---|
| `mullvad` *(default)* | malware, ads, trackers (Mullvad Base, no logs) | — |
| `quad9` | malware, phishing (Quad9, no IP logging) | `profiles --preset quad9` |
| `family` | malware, phishing, adult content (CleanBrowsing Family) | — |
| `cf-family` / `security` | Cloudflare variants without content filtering | — |
| `nextdns --nextdns-id <ID>` | whatever you configure at my.nextdns.io | `profiles --preset nextdns --nextdns-id abc123` |

**No plain-DNS fallback, by design.** A network that blocks DoH could
otherwise silently downgrade the phone to unencrypted DNS; instead the phone
loses DNS on such a network. Some ISPs and routers block the well-known
resolvers, so before installing, check every network the phone uses:

```bash
python3 ghost_lock/ghost_lock.py dns-check
```

It sends a real DoH query straight to each preset's pinned IP (via `curl`,
which also speaks HTTP/2) with the certificate verified, exactly as iOS will.
It also checks the PC: `systemd-resolved` only speaks DoT (port 853), so on
such a network it either leaks to the router's plain DNS or stops resolving.
When that happens, `dns-check` prints a ready `dnscrypt-proxy` config that uses
DoH on port 443 instead.

> **Firewalls with DNS bypass prevention** (e.g. Portmaster) block apps —
> including `curl` and `dnscrypt-proxy` — from reaching well-known DNS servers,
> and resolve everything themselves. `dns-check` warns when Portmaster runs:
> its "blocked" results are then the firewall's, not the network's. With
> Portmaster, set the encrypted DNS server in Portmaster itself (Secure DNS →
> DNS Servers), e.g. `dot://base.dns.mullvad.net?ip=194.242.2.4&name=Mullvad`,
> instead of running a second proxy. Use DoT there: Portmaster marked the
> Mullvad DoH entry as failing (Mullvad's DoH endpoint speaks HTTP/2 only).
> Also turn off Portmaster's fallback to the network's plain DNS server.

> Earlier versions wrote a `ServerFallback` key. Apple has no such key, so iOS
> ignored it. The deep audit flags an installed profile of that version;
> reinstall it.

The Domain Wall rebuilds from the current IOC database whenever you run
`profiles` — reinstall the file to refresh the blocklist.

## Automatic audits on USB connect

A Go daemon listens to kernel uevents over netlink, spots the iPhone plugging
in and runs the full audit by itself. Installed as a systemd user service:

```bash
./deploy/install_watch.sh
```

```bash
systemctl --user status glock-watch     # is it alive
journalctl --user -u glock-watch -f     # live audit logs
```

A 90-second cooldown prevents event storms. Only one audit runs at a time (a
lock file), and the daemon calls `audit --if-stale 15`: a deep backup makes the
phone reconnect over USB, which would otherwise start a second audit and a
duplicate Telegram alert. Re-run `./deploy/install_watch.sh` after updating. To start the service before login:
`sudo loginctl enable-linger $USER`.

## Telegram alerts

```bash
python3 ghost_lock/ghost_lock.py setup-telegram --token <TOKEN_FROM_BotFather>
```

The script discovers your chat_id automatically (send the bot any message
during setup) and sends a test notification. Every audit afterwards — including
automatic ones — reports the verdict, score and top findings. The token lives
outside the repo in `~/.config/ghost-lock/telegram.json` with `0600`
permissions. No network or no config? The audit quietly continues anyway.

## The IOC database

```bash
python3 ghost_lock/ghost_lock.py update-ioc
```

A STIX 2.x parser pulls **every AmnestyTech investigation** (Pegasus, Predator,
FinFisher, DoNOT, NovaSpy, Wintego…) via the GitHub API: domains, emails, file
paths. Process names from cross-platform reports are deliberately excluded from
scanning — they cause a flood of false positives in iOS crash logs (verified:
`roleaccountd` and `updaterd` are legit Apple daemons).

Current database size: **~4,300 indicators**. Entry format:
`{"value": "domain", "weight": 1-10, "source": "report"}`.

## Tests

240 Python tests (scanner, allowlist, STIX, history/diff, hygiene, WCF profile,
Telegram, CLI, integration) plus Go tests (scan engine, uevent parser):

```bash
python3 -m unittest discover -s tests
cd go && go test ./...
```

## Project layout

```
ghost_lock/
├── ghost_lock.py            # CLI
├── config.py                # paths, DNS presets, scoring thresholds
├── modules/
│   ├── connect.py           # usbmuxd/lockdownd with human-readable errors
│   ├── diagnostics.py       # fault-tolerant crash-log export
│   ├── spyware_scan.py      # engine: Go binary or Python fallback
│   ├── apps_scan.py         # stalkerware by bundle-id
│   ├── hygiene.py           # over-cable security hygiene check
│   ├── history.py           # SQLite history + diff
│   ├── deep_scan.py         # full backup + forensics sweep
│   ├── backup_crypto.py     # encrypted iOS backup decryption
│   ├── profile_audit.py     # profiles, certificates, supervision
│   ├── netusage.py          # per-process network statistics
│   ├── dns_check.py         # DoH reachability, PC DNS leaks
│   ├── usb_profiles.py      # profiles over the cable (pymobiledevice3)
│   ├── host_check.py        # pairing records, disk encryption, Portmaster
│   ├── shutdown_log.py      # iShutdown: shutdown.log from sysdiagnose
│   ├── profile_gen.py       # generates every .mobileconfig
│   ├── telegram_notify.py   # alerts
│   ├── ioc_update.py        # STIX parser + feed merging
│   ├── os_check.py          # iOS freshness
│   └── report.py            # HTML report
├── ioc/indicators.json      # indicator database
├── profiles/                # ready-to-install .mobileconfig files
go/
├── cmd/glock-scan/          # scanner CLI (JSON output)
├── cmd/glock-watch/         # auto-audit daemon
└── internal/{ioc,scan,watch}/
tests/                       # 240 unit tests
deploy/                      # systemd user unit + installer
```

## License

[MIT](LICENSE)

## Honest limitations

- The legacy `PasswordProtected` key from lockdownd is **unreliable on modern
  iOS** — verified on iOS 27: it reports `false` with a passcode and Face ID
  enabled, regardless of screen state. Hygiene therefore treats it as
  "unknown", never as "off". The true passcode status requires MDM supervision;
  check manually.
- A regular audit sees crash logs and device metadata, not phone contents;
  use `--deep` for full depth.
- The DoH shield can't see traffic that bypasses DNS (hardcoded IPs); the
  WebKit wall doesn't govern native (non-WebKit) traffic. Which is exactly why
  there are several layers.
- Deep traffic inspection inside iOS would require a custom NetworkExtension
  VPN app and an Apple Developer account — out of scope here.
- Some hardened-profile keys only apply to supervised devices (Apple
  Configurator); those are marked as such and honestly ignored by iOS.
- Profile installation cannot be automated remotely: Apple deliberately
  requires manual confirmation — which also protects the profiles from being
  silently removed by malware.

---

README на русском: [README.ru.md](README.ru.md)
