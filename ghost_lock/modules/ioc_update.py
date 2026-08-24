"""Обновление базы IOC: STIX-фиды AmnestyTech + текстовые списки.

Парсит полноценный STIX 2.x: домены, имена процессов, email'ы, пути файлов.
Каждый тип routed в свою секцию indicators.json, чтобы сканер искал
их в краш-логах. IP-адреса и хеши сознательно не тащим: в аудите по
краш-логам они дают либо ноль пользы, либо ложные срабатывания.

Список фидов строится автоматически из GitHub API репозитория
AmnestyTech/investigations: все папки-расследования, все *.stix2 файлы.
"""

from __future__ import annotations

import json
import re
import urllib.request
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any

from .. import config

GITHUB_API = "https://api.github.com/repos/AmnestyTech/investigations/contents/"
GITHUB_RAW = "https://raw.githubusercontent.com/AmnestyTech/investigations/master/"
USER_AGENT = "ghost-lock/1.0"

# Дополнительные текстовые списки (проверенные пути)
TXT_FEEDS = {
    "amnesty_pegasus_domains": "2021-07-18_nso/domains.txt",
    "amnesty_pegasus_v4": "2021-07-18_nso/v4_domains.txt",
    "amnesty_cytrox_domains": "2021-12-16_cytrox/domains.txt",
}

# Типы весов по умолчанию для новых секций
DEFAULT_WEIGHTS = {"domains": 8, "processes": 6, "emails": 7, "file_paths": 6}


@dataclass
class StixIndicator:
    section: str  # domains | processes | emails | file_paths
    value: str
    source: str


@dataclass
class FeedReport:
    name: str
    found: int = 0
    added: int = 0
    errors: list[str] = field(default_factory=list)


def _http_get(url: str, timeout: int = 30) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="replace")


def _http_json(url: str) -> Any:
    return json.loads(_http_get(url))


# ── STIX парсер ──────────────────────────────────────────────────────────────

_STIX_PATTERNS = (
    ("domain-name:value", re.compile(r"domain-name:value\s*=\s*['\"]([^'\"]+)['\"]", re.I)),
    ("process:name", re.compile(r"process:name\s*=\s*['\"]([^'\"]+)['\"]", re.I)),
    ("email-addr:value", re.compile(r"email-addr:value\s*=\s*['\"]([^'\"]+)['\"]", re.I)),
    ("file:path", re.compile(r"file:path\s*=\s*['\"]([^'\"]+)['\"]", re.I)),
)

_SECTION_BY_TYPE = {
    "domain-name:value": "domains",
    "process:name": "processes",
    "email-addr:value": "emails",
    "file:path": "file_paths",
}

# Мусорные значения, которые встречаются в публичных фидах
_NOISE = {
    "", "example.com", "example.org", "localhost",
    "your.domain.com", "attacker.com", "c2.example.com",
}
_DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9\-_]*\.)+[a-z]{2,}$", re.I)


def _clean(value: str) -> str:
    v = value.strip().strip("'\"").lower()
    if v.startswith("hxxp"):
        v = v.replace("hxxp", "http", 1)
        v = v.split("://", 1)[-1]
    v = v.split("/")[0].split(":")[0] if v and not v.startswith(("/", "~")) else v
    return v


def parse_stix(text: str, source: str) -> list[StixIndicator]:
    """Извлекает индикаторы из STIX 2.x bundle (JSON)."""
    try:
        data = json.loads(text)
    except ValueError:
        return []

    out: list[StixIndicator] = []
    objects = data.get("objects", []) if isinstance(data, dict) else []
    if isinstance(data, list):
        objects = data

    for obj in objects:
        if not isinstance(obj, dict):
            continue
        if obj.get("revoked") or not obj.get("is_active", True):
            continue
        pattern = str(obj.get("pattern", ""))
        labels = ",".join(map(str, obj.get("labels", [])[:3]))
        src = f"{source}:{labels}" if labels else source

        for stix_type, rx in _STIX_PATTERNS:
            for match in rx.findall(pattern):
                v = _clean(match)
                if not v or v in _NOISE:
                    continue
                if stix_type == "domain-name:value" and not _DOMAIN_RE.match(v):
                    continue
                out.append(StixIndicator(
                    section=_SECTION_BY_TYPE[stix_type],
                    value=v,
                    source=src,
                ))
    return out


def parse_txt(text: str, source: str, section: str = "domains") -> list[StixIndicator]:
    line_re = re.compile(r"^\s*([^\s#]+)\s*$")
    out: list[StixIndicator] = []
    for line in text.splitlines():
        m = line_re.match(line)
        if not m:
            continue
        v = _clean(m.group(1))
        if not v or v in _NOISE or v.endswith((".png", ".jpg", ".md")):
            continue
        if section == "domains" and not _DOMAIN_RE.match(v):
            continue
        out.append(StixIndicator(section=section, value=v, source=source))
    return out


# ── Сбор фидов ───────────────────────────────────────────────────────────────

def discover_amnesty_stix_files() -> list[tuple[str, str]]:
    """[(имя фида, raw-url)] по всем *.stix2 во всех расследованиях."""
    try:
        entries = _http_json(GITHUB_API)
    except OSError:
        return []
    feeds: list[tuple[str, str]] = []
    for entry in entries:
        if entry.get("type") != "dir":
            continue
        dirname = entry["name"]
        try:
            files = _http_json(GITHUB_API + dirname)
        except OSError:
            continue
        for f in files:
            if f.get("name", "").endswith(".stix2"):
                url = GITHUB_RAW + f"{dirname}/{f['name']}"
                feeds.append((f"stix_{dirname}", url))
    return feeds


def collect_all() -> tuple[list[StixIndicator], list[str]]:
    """Тянет все фиды. Возвращает (индикаторы, список ошибок)."""
    collected: list[StixIndicator] = []
    errors: list[str] = []

    for name, path in TXT_FEEDS.items():
        try:
            collected.extend(parse_txt(_http_get(GITHUB_RAW + path), name))
        except OSError as e:
            errors.append(f"{name}: {e}")

    for name, url in discover_amnesty_stix_files():
        short = name.replace("stix_", "")[:40]
        try:
            collected.extend(parse_stix(_http_get(url), short))
        except OSError as e:
            errors.append(f"{short}: {e}")

    # дедуп на уровне сбора
    seen: set[tuple[str, str]] = set()
    unique: list[StixIndicator] = []
    for ind in collected:
        key = (ind.section, ind.value)
        if key in seen:
            continue
        seen.add(key)
        unique.append(ind)
    return unique, errors


# ── Слияние с базой ──────────────────────────────────────────────────────────

def merge_indicators(items: list[StixIndicator], ioc_path: Path | None = None) -> dict[str, int]:
    """Разливает индикаторы по секциям базы, возвращает {секция: добавлено}."""
    path = ioc_path or config.IOC_PATH
    with open(path, encoding="utf-8") as fh:
        db = json.load(fh)

    added = {s: 0 for s in DEFAULT_WEIGHTS}
    for ind in items:
        value = ind.value.lower()
        if not value:
            continue
        bucket = db.setdefault(ind.section, [])
        existing = {str(x.get("value", "")).lower() for x in bucket if isinstance(x, dict)}
        if value in existing:
            continue
        bucket.append({"value": value, "weight": DEFAULT_WEIGHTS.get(ind.section, 5), "source": ind.source})
        added[ind.section] = added.get(ind.section, 0) + 1

    meta = db.setdefault("_meta", {})
    meta["updated"] = date.today().isoformat()
    meta["version"] = _bump_minor(str(meta.get("version", "1.0.0")))

    with open(path, "w", encoding="utf-8") as fh:
        json.dump(db, fh, ensure_ascii=False, indent=2)
    return added


def _bump_minor(version: str) -> str:
    parts = version.split(".")
    if len(parts) >= 2 and parts[-2].isdigit():
        parts[-2] = str(int(parts[-2]) + 1)
        parts[-1] = "0"
        return ".".join(parts)
    return version + ".1"


def update() -> dict[str, Any]:
    """Полное обновление. Возвращает сводку для CLI."""
    items, errors = collect_all()
    per_section = merge_indicators(items)

    with open(config.IOC_PATH, encoding="utf-8") as fh:
        db = json.load(fh)
    totals = {
        s: len(db.get(s, []))
        for s in ("domains", "jailbreak_artifacts", "spyware_strings",
                  "stalkerware_profiles", "spyware_bundles",
                  "processes", "emails", "file_paths")
    }
    return {"added": per_section, "totals": totals, "errors": errors,
            "feeds_ok": len(TXT_FEEDS), "items": len(items)}
