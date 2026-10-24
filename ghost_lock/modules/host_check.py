"""Безопасность самого компьютера: он — ключ к телефону.

  • Запись сопряжения (/var/lib/lockdown/<UDID>.plist) содержит закрытый ключ
    хоста и escrow-ключ: с ней можно подключиться к телефону как «доверенный
    компьютер» и читать данные без кода (после первой разблокировки). usbmuxd
    в Debian/Ubuntu пишет её с правами 0644 — читает любой процесс. Программы
    (idevice*, pymobiledevice3) берут ключ через usbmuxd, поэтому 0600 ничего
    не ломает. UMask=0077 в юните usbmuxd закрывает и будущие записи.
  • Шифрование системного диска: без него украденный ноутбук отдаёт и записи
    сопряжения, и бэкапы, и отчёты.
  • Portmaster перехватывает весь DNS компьютера (свой резолвер 127.0.0.17)
    — DNS-сервер тогда настраивается в нём, а не в systemd-resolved.

Security of the computer itself: it is the key to the phone.

  • The pairing record holds the host private key and the escrow key: with it
    one can connect to the phone as a "trusted computer" and read data without
    the passcode (after first unlock). usbmuxd on Debian/Ubuntu writes it as
    0644 — any process can read it. Tools get the key through usbmuxd, so 0600
    breaks nothing; UMask=0077 on the usbmuxd unit covers future records.
  • System disk encryption: without it a stolen laptop yields the pairing
    records, backups and reports.
  • Portmaster intercepts all DNS (its own resolver at 127.0.0.17) — the DNS
    server is then configured in it, not in systemd-resolved.
"""

from __future__ import annotations

import platform
import subprocess
from dataclasses import dataclass
from pathlib import Path

PAIRING_DIRS = (Path("/var/lib/lockdown"), Path("/var/db/lockdown"))
PORTMASTER_DNS = "127.0.0.17"
FIX_PAIRING = ("sudo chmod 600 /var/lib/lockdown/*.plist && "
               "sudo mkdir -p /etc/systemd/system/usbmuxd.service.d && "
               "printf '[Service]\\nUMask=0077\\n' | "
               "sudo tee /etc/systemd/system/usbmuxd.service.d/ghost-lock.conf && "
               "sudo systemctl daemon-reload")


@dataclass
class HostCheck:
    ok: bool | None   # True хорошо / False плохо / None информация или неизвестно
    title: str
    fix: str = ""


def exposed_pairing_records(dirs=PAIRING_DIRS) -> list[Path]:
    """Записи сопряжения, читаемые группой или всеми.

    Pairing records readable by group or others.
    """
    out = []
    for d in dirs:
        try:
            files = sorted(d.glob("*.plist"))
        except OSError:
            continue
        for f in files:
            try:
                if f.stat().st_mode & 0o077:
                    out.append(f)
            except OSError:
                continue
    return out


def _run(cmd: list[str]) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


def root_disk_encrypted() -> bool | None:
    system = platform.system()
    if system == "Linux":
        source = _run(["findmnt", "-no", "SOURCE", "/"]).strip()
        if not source:
            return None
        # -s: цепочка устройств вверх до диска; «crypt» = LUKS/dm-crypt в цепочке
        # -s: the device chain up to the disk; "crypt" = LUKS/dm-crypt in the chain
        types = _run(["lsblk", "-s", "-no", "TYPE", source]).split()
        return "crypt" in types if types else None
    if system == "Darwin":
        out = _run(["fdesetup", "status"])
        return "FileVault is On" in out if out else None
    return None


def portmaster_running(proc_root: Path = Path("/proc")) -> bool:
    try:
        entries = list(proc_root.iterdir())
    except OSError:
        return False
    for p in entries:
        if not p.name.isdigit():
            continue
        try:
            if (p / "comm").read_text().strip().startswith("portmaster-core"):
                return True
        except OSError:
            continue
    return False


def checks() -> list[HostCheck]:
    out: list[HostCheck] = []
    if any(d.exists() for d in PAIRING_DIRS):
        exposed = exposed_pairing_records()
        if exposed:
            out.append(HostCheck(False, f"Записи сопряжения с iPhone читаются всеми ({len(exposed)}): "
                                        "любой процесс получит доступ к телефону", FIX_PAIRING))
        else:
            out.append(HostCheck(True, "Записи сопряжения с iPhone закрыты"))

    enc = root_disk_encrypted()
    if enc is True:
        out.append(HostCheck(True, "Системный диск зашифрован"))
    elif enc is False:
        out.append(HostCheck(False, "Системный диск НЕ зашифрован: украденный компьютер отдаст "
                                    "записи сопряжения, бэкапы и отчёты",
                             "шифрование включается при переустановке (LUKS / FileVault)"))
    else:
        out.append(HostCheck(None, "Шифрование диска: не удалось определить"))

    if portmaster_running():
        out.append(HostCheck(None, "Portmaster перехватывает DNS компьютера: DNS-сервер "
                                   "(напр. dot://base.dns.mullvad.net?ip=194.242.2.4) задаётся в его Secure DNS"))
    return out
