"""Глубокий форензик-режим: полный бэкап через idevicebackup2 + скан всего.

Обычный аудит смотрит только краш-логи (~сотни файлов). Полный бэкап —
это SMS-базы, история Safari, сетевая статистика, снапшоты приложений:
десятки тысяч файлов. Медленно (десятки минут первый раз, дальше
инкрементально быстро), но это уровень настоящего forensics.

Шифрование: если на телефоне включено шифрование бэкапов (его включает
профиль hardened через forceEncryptedBackup), бэкап расшифровывается
паролем во временную папку, сканируется и сразу удаляется. Без пароля
результат помечается НЕПОЛНЫМ — скан шифротекста никогда не выдаётся
за «чисто». Пароль: переменная GHOST_LOCK_BACKUP_PASSWORD или ввод
с клавиатуры.

Deep forensic mode: full backup via idevicebackup2 + scan of everything.

The regular audit only looks at crash logs (~hundreds of files). A full
backup covers SMS databases, Safari history, network stats, app snapshots:
tens of thousands of files. Slow at first (dozens of minutes; fast and
incremental afterwards) but this is real forensics level.

Encryption: if backup encryption is on (the hardened profile enables it via
forceEncryptedBackup), the backup is decrypted with the password into a
temporary folder, scanned and deleted right away. Without a password the
result is marked INCOMPLETE — a scan of ciphertext is never reported as
"clean". Password: GHOST_LOCK_BACKUP_PASSWORD env var or keyboard prompt.
"""

from __future__ import annotations

import getpass
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable

from . import backup_crypto
from .spyware_scan import ScanResult

BACKUP_TIMEOUT = 3600  # час на полный бэкап / one hour for a full backup
INFO_TIMEOUT = 20
BACKUPS_DIR = Path.home() / ".local" / "share" / "ghost-lock" / "backups"
PASSWORD_ENV = "GHOST_LOCK_BACKUP_PASSWORD"


def _run_backup(udid: str, dest_dir: Path) -> tuple[bool, str]:
    dest_dir.mkdir(parents=True, exist_ok=True)
    # Без --full: первый раз idevicebackup2 сам делает полный бэкап, дальше —
    # инкрементальный. --full заставлял каждый раз заново качать всё.
    # No --full: the first run is full on its own, later ones incremental.
    # --full forced re-downloading everything on every audit.
    cmd = ["idevicebackup2", "backup", str(dest_dir)]
    if udid:
        cmd.append(udid)
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=BACKUP_TIMEOUT)
    except subprocess.TimeoutExpired:
        return False, "бэкап не уложился в часовой таймаут"
    except OSError as e:
        return False, f"idevicebackup2 недоступен: {e}"
    if proc.returncode != 0:
        tail = (proc.stderr or proc.stdout).strip().splitlines()
        reason = tail[-1] if tail else f"exit {proc.returncode}"
        return False, reason
    return True, ""


def will_encrypt(udid: str) -> bool | None:
    """Спрашивает телефон, будет ли бэкап зашифрован. None — не удалось узнать.

    Asks the phone whether the backup will be encrypted. None — unknown.
    """
    cmd = ["ideviceinfo", "-q", "com.apple.mobile.backup", "-k", "WillEncrypt"]
    if udid:
        cmd += ["-u", udid]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=INFO_TIMEOUT)
    except (OSError, subprocess.TimeoutExpired):
        return None
    val = proc.stdout.strip().lower()
    if val in ("true", "false"):
        return val == "true"
    return None


def default_password_provider() -> str | None:
    pwd = os.environ.get(PASSWORD_ENV)
    if pwd:
        return pwd
    if not sys.stdin.isatty():
        return None
    try:
        return getpass.getpass("  [?] Пароль шифрования бэкапа (Enter — пропустить): ") or None
    except (EOFError, KeyboardInterrupt):
        return None


def _incomplete(reason: str) -> ScanResult:
    res = ScanResult(findings=[], files_scanned=0)
    res.incomplete = True
    res.stats_note = f"deep: НЕПОЛНЫЙ — {reason}"
    print(f"  [!] {reason}")
    return res


def run(udid: str, info: dict[str, Any],
        password_provider: Callable[[], str | None] = default_password_provider) -> ScanResult:
    """Полный бэкап + IOC-скан. Возвращает отдельный ScanResult.

    Full backup + IOC scan. Returns a separate ScanResult.
    """
    from .spyware_scan import run_scan

    # Пароль спрашиваем ДО часового бэкапа, а не после
    # Ask for the password BEFORE the hour-long backup, not after
    password: str | None = None
    if will_encrypt(udid):
        print("  [~] Шифрование бэкапов на телефоне включено — нужен пароль бэкапа.")
        password = password_provider()
        if not password:
            return _incomplete(
                f"бэкап зашифрован, а пароль не задан ({PASSWORD_ENV} или ввод вручную)")

    started = time.monotonic()
    dest = BACKUPS_DIR / udid
    print("  [~] Глубокий режим: бэкап (первый — до часа, дальше только изменения)…")
    ok, err = _run_backup(udid, dest)
    if not ok:
        res = ScanResult(findings=[], files_scanned=0)
        res.incomplete = True
        res.stats_note = f"deep: бэкап не удался ({err})"
        print(f"  [!] Бэкап не удался: {err}")
        return res
    minutes = (time.monotonic() - started) / 60

    manifest = backup_crypto.find_manifest(dest)
    if manifest is None:
        return _incomplete("в бэкапе нет Manifest.plist — содержимое не распознано")

    if not backup_crypto.is_encrypted(manifest):
        n_files = sum(1 for _ in dest.rglob("*") if _.is_file())
        print(f"  [+] Бэкап готов за {minutes:.1f} мин ({n_files} файлов). Скан…")
        print("  [!] Бэкап НЕ зашифрован: SMS, история и прочее лежат на диске открыто.")
        print(f"      Включи шифрование: idevicebackup2 -i -u {udid} encryption on")
        return _report_noise(_prefix(run_scan(info, dest)))

    if password is None:
        # телефон не сообщил WillEncrypt, но бэкап оказался зашифрованным
        # the phone did not report WillEncrypt, yet the backup came out encrypted
        password = password_provider()
        if not password:
            return _incomplete(
                f"бэкап зашифрован, а пароль не задан ({PASSWORD_ENV} или ввод вручную)")

    print(f"  [+] Зашифрованный бэкап готов за {minutes:.1f} мин. Расшифровка…")
    plain_dir = Path(tempfile.mkdtemp(prefix=".decrypted-", dir=BACKUPS_DIR))
    try:
        try:
            stats = backup_crypto.decrypt_backup(manifest.parent, password, plain_dir)
        except backup_crypto.BackupCryptoError as e:
            return _incomplete(f"расшифровка не удалась: {e}")
        note = f"  [+] Расшифровано {stats.decrypted} файлов"
        if stats.skipped_large:
            note += f", пропущено крупных (медиа): {stats.skipped_large}"
        if stats.failed:
            note += f", ошибок: {stats.failed}"
        print(note + ". Скан…")
        result = _report_noise(_prefix(run_scan(info, plain_dir), plain_dir))
    finally:
        # расшифрованная копия не должна переживать скан
        # the decrypted copy must not outlive the scan
        shutil.rmtree(plain_dir, ignore_errors=True)
    return result


# ── Шум бэкапа: списки блокировки и слова-эвристики ─────────────────────────
# ── Backup noise: blocklists and heuristic words ────────────────────────────
# В бэкапе лежат ЧУЖИЕ списки блокировки (профиль ghost-lock, правила Safari,
# трекер-листы) — в них сотни доменов шпионов, но это защита, а не заражение.
# The backup holds blocklists (the ghost-lock profile, Safari rules, tracker
# lists) — hundreds of spyware domains, yet that is protection, not infection.

# Домены из стольких разных расследований в одном файле = это список
# Domains from this many distinct investigations in one file = it is a list
LIST_MIN_SOURCES = 3

_LIST_FILE_MARKERS = (
    "contentrulelist", "trackerdataset", "scamfilterset", "lastcompiledrules",
    "allowlist", "blocklist", "denylist", "webcontentfilter", "configurationprofiles/",
    "profiletruth.plist", "effectiveusersettings.plist", ".mobileconfig", ".stub",
)

# Слова-эвристики имеют смысл в краш-логах, но в бэкапе — это статьи, песни, JS
# Heuristic words make sense in crash logs, but in a backup they are articles, songs, JS
NOISY_WORDS = {"pegasus", "trident", "frigate", "frida", "cellebrite",
               "spyware", "keylogger", "cell tracker"}


def _source_key(source: str) -> str:
    return source.split(" (строка")[0].strip().lower()


def filter_backup_noise(findings: list) -> tuple[list, list]:
    """Делит находки бэкапа на (оставленные, подавленные как шум).

    Splits backup findings into (kept, suppressed as noise).
    """
    by_file: dict[str, set[str]] = {}
    for f in findings:
        if f.ioc_type == "domains":
            by_file.setdefault(f.location, set()).add(_source_key(f.source))
    list_files = {loc for loc, srcs in by_file.items() if len(srcs) >= LIST_MIN_SOURCES}

    kept, suppressed = [], []
    for f in findings:
        loc = f.location.lower()
        noisy = (
            f.value.strip().lower() in NOISY_WORDS
            or (f.ioc_type == "domains" and f.location in list_files)
            or any(m in loc for m in _LIST_FILE_MARKERS)
        )
        (suppressed if noisy else kept).append(f)
    return kept, suppressed


def _report_noise(result: ScanResult) -> ScanResult:
    result.findings, suppressed = filter_backup_noise(result.findings)
    if suppressed:
        files: dict[str, int] = {}
        for f in suppressed:
            name = Path(f.location.removeprefix("backup:")).name
            files[name] = files.get(name, 0) + 1
        top = ", ".join(n for n, _ in sorted(files.items(), key=lambda kv: -kv[1])[:5])
        print(f"  [~] Отфильтровано как списки блокировки/шум: {len(suppressed)} "
              f"находок в {len(files)} файлах ({top}{'…' if len(files) > 5 else ''})")
    return result


def _prefix(result: ScanResult, strip_root: Path | None = None) -> ScanResult:
    for f in result.findings:
        loc = f.location
        if strip_root is not None and loc.startswith(str(strip_root)):
            loc = loc[len(str(strip_root)):].lstrip("/")
        if not loc.startswith("backup:"):
            f.location = f"backup:{loc}"
    return result
