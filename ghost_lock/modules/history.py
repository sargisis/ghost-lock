"""SQLite-история аудитов + diff «что изменилось с прошлого раза».

База: ~/.local/share/ghost-lock/history.db
Таблицы:
  audits        — по строке на каждый аудит
  app_snapshots — снимок установленных приложений на аудит
  crash_files   — имена выгруженных краш-логов (для поиска новых)

Сталкер/зловред проще всего поймать по дельте, а не по абсолюту:
новое приложение после «обновления», всплеск незнакомых крашей.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path.home() / ".local" / "share" / "ghost-lock" / "history.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audits (
    id INTEGER PRIMARY KEY,
    ts TEXT NOT NULL,
    udid TEXT,
    device TEXT,
    ios_version TEXT,
    verdict TEXT,
    score INTEGER,
    files_scanned INTEGER,
    apps_count INTEGER,
    ioc_version TEXT,
    deep INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS app_snapshots (
    audit_id INTEGER NOT NULL REFERENCES audits(id),
    bundle_id TEXT NOT NULL,
    version TEXT
);
CREATE TABLE IF NOT EXISTS crash_files (
    audit_id INTEGER NOT NULL REFERENCES audits(id),
    filename TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audits_udid ON audits(udid, id DESC);
"""


def _connect(path: Path | None = None) -> sqlite3.Connection:
    p = path or DB_PATH
    p.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(p)
    con.executescript(_SCHEMA)
    return con


@dataclass
class DiffReport:
    prev_ts: str | None = None
    prev_score: int | None = None
    new_apps: list[tuple[str, str]] = field(default_factory=list)      # (bundle, version)
    removed_apps: list[str] = field(default_factory=list)
    new_crashes: int = 0

    @property
    def is_first_audit(self) -> bool:
        return self.prev_ts is None

    def has_changes(self) -> bool:
        return bool(self.new_apps or self.removed_apps or self.new_crashes)


def last_audit(udid: str, path: Path | None = None) -> dict | None:
    con = _connect(path)
    try:
        row = con.execute(
            "SELECT id, ts, verdict, score FROM audits WHERE udid=? ORDER BY id DESC LIMIT 1",
            (udid,),
        ).fetchone()
    finally:
        con.close()
    if not row:
        return None
    return {"id": row[0], "ts": row[1], "verdict": row[2], "score": row[3]}


def save_audit(*, udid: str, device: str, ios_version: str, verdict: str,
               score: int, files_scanned: int, apps: list[tuple[str, str]],
               crash_names: list[str], ioc_version: str, deep: bool = False,
               path: Path | None = None) -> int:
    con = _connect(path)
    try:
        cur = con.execute(
            "INSERT INTO audits (ts, udid, device, ios_version, verdict, score,"
            " files_scanned, apps_count, ioc_version, deep)"
            " VALUES (?,?,?,?,?,?,?,?,?,?)",
            (datetime.now(timezone.utc).isoformat(timespec="seconds"), udid, device,
             ios_version, verdict, score, files_scanned, len(apps), ioc_version,
             int(deep)),
        )
        audit_id = cur.lastrowid
        con.executemany(
            "INSERT INTO app_snapshots (audit_id, bundle_id, version) VALUES (?,?,?)",
            [(audit_id, b, v) for b, v in apps],
        )
        con.executemany(
            "INSERT INTO crash_files (audit_id, filename) VALUES (?,?)",
            [(audit_id, n) for n in crash_names],
        )
        con.commit()
        return audit_id
    finally:
        con.close()


def diff_with_history(*, udid: str, current_apps: list[tuple[str, str]],
                      current_crash_names: list[str],
                      path: Path | None = None) -> DiffReport:
    """Сравнивает текущий аудит со ВСЕЙ прошлой историей устройства."""
    rep = DiffReport()
    con = _connect(path)
    try:
        row = con.execute(
            "SELECT ts, score FROM audits WHERE udid=? ORDER BY id DESC LIMIT 1",
            (udid,),
        ).fetchone()
        if not row:
            return rep
        rep.prev_ts, rep.prev_score = row[0], row[1]

        known_bundles = {r[0] for r in con.execute(
            "SELECT DISTINCT s.bundle_id FROM app_snapshots s"
            " JOIN audits a ON a.id=s.audit_id WHERE a.udid=?", (udid,))}
        cur_bundles = {b for b, _ in current_apps}
        rep.new_apps = sorted(
            (b, v) for b, v in current_apps if b not in known_bundles)
        rep.removed_apps = sorted(known_bundles - cur_bundles)

        known_crashes = {r[0] for r in con.execute(
            "SELECT DISTINCT c.filename FROM crash_files c"
            " JOIN audits a ON a.id=c.audit_id WHERE a.udid=?", (udid,))}
        rep.new_crashes = sum(1 for n in current_crash_names if n not in known_crashes)
        return rep
    finally:
        con.close()


def format_diff(rep: DiffReport) -> list[str]:
    """Строки для CLI/Telegram. Пустой список = первая проверка или без изменений."""
    if rep.is_first_audit:
        return ["Первый аудит этого устройства — история начата."]
    lines = []
    if rep.new_apps:
        lines.append(f"🆕 Новые приложения ({len(rep.new_apps)}): "
                     + ", ".join(b for b, _ in rep.new_apps[:5])
                     + ("…" if len(rep.new_apps) > 5 else ""))
    if rep.removed_apps:
        lines.append(f"🗑 Удалены приложения ({len(rep.removed_apps)}): "
                     + ", ".join(rep.removed_apps[:5]) + ("…" if len(rep.removed_apps) > 5 else ""))
    if rep.new_crashes:
        lines.append(f"📉 Новых краш-логов: {rep.new_crashes}")
    if not lines:
        lines.append("Изменений с прошлого аудита нет.")
    return lines


def history_summary(udid: str, limit: int = 10,
                    path: Path | None = None) -> list[dict]:
    con = _connect(path)
    try:
        rows = con.execute(
            "SELECT ts, verdict, score, files_scanned, apps_count FROM audits"
            " WHERE udid=? ORDER BY id DESC LIMIT ?", (udid, limit)).fetchall()
        keys = ("ts", "verdict", "score", "files", "apps")
        return [dict(zip(keys, r)) for r in rows]
    finally:
        con.close()
