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
```

## Inside the audit

1. **Crash-log export** — the richest evidence source: crash logs retain
   mentions of C2 domains, implant names, jailbreak artifacts.
2. **IOC scan** by a hybrid engine: heavy lifting in Go (worker pool), URL and
   phishing heuristics in Python. An allowlist suppresses false positives
   (e.g. the legit `Pegasus.framework` shipped inside iOS itself).
3. **App inventory scan** against known stalkerware bundle IDs
   (mSpy/FlexiSPY/CocoSpy/uMobix/EyeZy…).
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
python3 ghost_lock/ghost_lock.py profiles --serve   # serve over Wi-Fi
# or simply send the files from ghost_lock/profiles/ to yourself
```

On the phone: open the file → Install. Verify under Settings → General →
VPN & Device Management. iOS will warn "Profile is not signed" — expected for
manually installed profiles.

> Installing new profiles requires temporarily disabling Lockdown Mode
> (Settings → Privacy & Security). Re-enable it afterwards.

| File | Payload type | Purpose |
|---|---|---|
| `dns_shield.mobileconfig` | DNS Settings (DoH) | Encrypted DNS with resolver-level filtering. A `ServerFallback` keeps the internet working if the DoH endpoint hiccups |
| `web_filter.mobileconfig` | Web Content Filter | **Spyware Domain Wall**: the top-500 C2 domains of Pegasus/Predator/FinFisher blocked at the Safari/WebKit level — a second line of defense that works even off our DNS |
| `hardened.mobileconfig` | Restrictions | System restrictions stacked on top of Lockdown Mode |

DNS presets:

| Preset | Blocks | Example |
|---|---|---|
| `family` *(default)* | malware, phishing, adult content (CleanBrowsing Family) | — |
| `cf-family` / `security` | Cloudflare variants without content filtering | — |
| `nextdns --nextdns-id <ID>` | whatever you configure at my.nextdns.io | `profiles --preset nextdns --nextdns-id abc123` |

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

A 90-second cooldown prevents event storms. To start the service before login:
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

190 Python tests (scanner, allowlist, STIX, history/diff, hygiene, WCF profile,
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
tests/                       # 190 unit tests
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
