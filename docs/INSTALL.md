# Platform Installation Guide (Linux · macOS · Windows)

ghost-lock's core — auditing, profile generation, Telegram alerts, audit
history, deep forensics — runs anywhere [libimobiledevice](https://libimobiledevice.org)
and Python 3 run. One component is Linux-specific:

> ⚠️ **`glock-watch` auto-audit daemon is Linux-only.** It listens to kernel
> USB uevents via netlink (`AF_NETLINK`), which does not exist on macOS or
> Windows. This guide provides honest alternatives for those platforms below.

## Feature matrix

| Feature | Linux | macOS | Windows |
|---|---|---|---|
| Full audit (`audit`, `--deep`) | ✅ | ✅ | ✅ * |
| Phone profiles (`profiles`) | ✅ | ✅ | ✅ |
| IOC database updates (STIX) | ✅ | ✅ | ✅ |
| Telegram alerts | ✅ | ✅ | ✅ |
| Audit history & diff | ✅ | ✅ | ✅ |
| Auto-audit daemon | ✅ netlink | ➖ poll script | ➖ PowerShell event |

\* Windows depends on third-party libimobiledevice builds — see notes.

---

## Linux (primary platform)

Everything works out of the box, including the auto-audit daemon:

```bash
sudo apt install libimobiledevice-utils   # Debian/Ubuntu
# Fedora: sudo dnf install libimobiledevice-utils
# Arch:   sudo pacman -S libimobiledevice usbmuxd

python3 ghost_lock/ghost_lock.py doctor   # verify
./deploy/install_watch.sh                 # optional: auto-audit daemon
```

Requires Python 3.10+. Go is only needed if you want to rebuild the scanner
(`cd go && go build ./...`) — otherwise install the prebuilt binary path or
let the hybrid engine fall back to pure Python automatically.

## macOS

libimobiledevice is first-class on macOS via Homebrew:

```bash
brew install libimobiledevice python go

python3 -m venv .venv && source .venv/bin/activate   # optional
python3 ghost_lock/ghost_lock.py doctor
python3 ghost_lock/ghost_lock.py audit
```

Notes:
- The first connection shows the standard "Trust This Computer" dialog on the
  phone — same as Linux.
- The `.mobileconfig` profiles are installed on the iPhone itself, so profile
  workflows are identical on any host OS. `profiles --serve` works fine.
- **Auto-audit daemon:** netlink doesn't exist here. A crude but functional
  substitute is a poll loop — e.g. save as `watch_mac.sh` and run it under
  your favourite process manager:

```bash
#!/bin/bash
# Poor-man's USB watcher for macOS: polls every 15s, cools down 5 min after an audit.
while true; do
  if system_profiler SPUSBDataType 2>/dev/null | grep -q "iPhone"; then
    python3 "$(dirname "$0")/ghost_lock/ghost_lock.py" audit || true
    sleep 300
  fi
  sleep 15
done
```

A production-grade version would use IOKit notifications via PyObjC — pull
requests welcome.

## Windows

Honest picture: libimobiledevice works on Windows, but it is not a one-click
install like on Linux/macOS. Two viable routes:

### Route 1 — MSYS2 (recommended, maintained packages)

```powershell
winget install MSYS2.MSYS2
# in the MSYS2 UCRT64 shell:
pacman -S mingw-w64-ucrt-x86_64-libimobiledevice \
          mingw-w64-ucrt-x86_64-python \
          mingw-w64-ucrt-x86_64-go
```

Add `C:\msys64\ucrt64\bin` to PATH, then verify `ideviceinfo` prints your
device info while the iPhone is connected and trusted.

### Route 2 — stock Python + prebuilt binaries

Install Python 3.10+ from python.org, then obtain prebuilt `idevice*.exe`
tools from a trusted distribution of libimobiledevice for Windows (check the
project's official documentation/wiki for current pointers — builds move
around). Place them in a directory listed in PATH.

### What works and what differs

- All CLI commands behave identically: `audit`, `--deep`, `profiles`,
  `setup-telegram`, `update-ioc`.
- Paths differ: data lands in `%LOCALAPPDATA%\ghost-lock\` equivalents
  (`Path.home() / ".local/share"` resolves to the user profile folder).
- **Auto-audit:** no netlink. Use Task Scheduler or a PowerShell WMI event
  subscription on Apple vendor devices (USB VID `05AC`). Sketch:

```powershell
Register-CimIndicationEvent -QueryName iPhonePlug -Query `
  "SELECT * FROM __InstanceCreationEvent WITHIN 10 WHERE TargetInstance ISA 'Win32_PnPEntity' AND TargetInstance.DeviceID LIKE '%VID_05AC%'" | ForEach-Object {
    & python C:\path\to\ghost_lock\ghost_lock.py audit
  }
```

Test this sketch on your machine before relying on it — WMI timing varies by
Windows build.

---

## Same on every platform

- **Phone-side hardening** (the three `.mobileconfig` profiles) is installed
  on the iPhone itself and has zero dependency on your computer's OS.
- Installing new profiles requires temporarily disabling Lockdown Mode,
  regardless of platform — Apple enforces manual confirmation by design.
- Trust pairing happens once; afterwards audits run without touching the phone.
