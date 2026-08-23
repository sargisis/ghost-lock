"""Обновление базы IOC из публичных фидов AmnestyTech.

Источник: https://github.com/AmnestyTech/investigations — STIX-файлы
расследований Pegasus и др. Извлекаем домены из STIX-паттернов вида:
  [domain-name:value = 'example.com']
и сливаем их с локальной базой без дублей (weight=8, source=ссылка на фид).

Сеть не обязательна: при ошибке локальная база остаётся нетронутой.
"""

from __future__ import annotations

import json
import re
import urllib.request
from datetime import date
from pathlib import Path

from .. import config

FEEDS = {
    # NSO Pegasus: доменная инфраструктура из отчёта Amnesty 2021-07-18
    "amnesty_pegasus": (
        "https://raw.githubusercontent.com/AmnestyTech/investigations/master/2021-07-18_nso/domains.txt",
        "txt",
    ),
    # Cytrox/Predator: домены из отчёта Amnesty 2021-12-16
    "amnesty_cytrox": (
        "https://raw.githubusercontent.com/AmnestyTech/investigations/master/2021-12-16_cytrox/domains.txt",
        "txt",
    ),
}

STIX_DOMAIN_RE = re.compile(r"domain-name:value\s*=\s*['\"]([^'\"]+)['\"]")
TXT_LINE_RE = re.compile(r"^\s*([a-z0-9][a-z0-9.\-_]*\.[a-z]{2,})\s*$", re.IGNORECASE)


def fetch_feed(url: str, fmt: str) -> list[str]:
    if fmt == "skip":
        return []
    req = urllib.request.Request(url, headers={"User-Agent": "ghost-lock/1.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        text = resp.read().decode("utf-8", errors="replace")

    domains: set[str] = set()
    if text.lstrip().startswith("{") or '"type": "indicator"' in text[:2000]:
        # STIX JSON
        try:
            data = json.loads(text)
            objects = data.get("objects", [])
        except ValueError:
            return []
        for obj in objects:
            pattern = str(obj.get("pattern", ""))
            domains.update(m.lower() for m in STIX_DOMAIN_RE.findall(pattern))
    else:
        # простой текстовый список
        for line in text.splitlines():
            m = TXT_LINE_RE.match(line.strip())
            if m and not m.group(1).endswith((".png", ".jpg", ".md")):
                domains.add(m.group(1).lower())
    return sorted(domains)


def merge_into_local(new_domains: dict[str, tuple[int, str]],
                     ioc_path: Path | None = None) -> tuple[int, int]:
    """Сливает новые домены в indicators.json.

    new_domains: {домен: (weight, source)}
    Возвращает (добавлено, всего доменов после).
    """
    path = ioc_path or config.IOC_PATH
    with open(path, encoding="utf-8") as fh:
        db = json.load(fh)

    existing = {str(i["value"]).lower() for i in db.get("domains", [])}
    added = 0
    for domain, (weight, source) in new_domains.items():
        domain = domain.lower().strip(".")
        if not domain or domain in existing:
            continue
        db.setdefault("domains", []).append(
            {"value": domain, "weight": weight, "source": source}
        )
        existing.add(domain)
        added += 1

    meta = db.setdefault("_meta", {})
    meta["updated"] = date.today().isoformat()
    meta["version"] = _bump_patch(str(meta.get("version", "1.0.0")))

    with open(path, "w", encoding="utf-8") as fh:
        json.dump(db, fh, ensure_ascii=False, indent=2)
    return added, len(existing)


def _bump_patch(version: str) -> str:
    parts = version.split(".")
    if len(parts) == 3 and parts[-1].isdigit():
        parts[-1] = str(int(parts[-1]) + 1)
        return ".".join(parts)
    return version + ".1"


def update_from_feeds(ioc_path: Path | None = None) -> dict[str, tuple[int, int]]:
    """Тянет все активные фиды, возвращает отчёт {фид: (найдено, добавлено)}."""
    report: dict[str, tuple[int, int]] = {}
    collected: dict[str, tuple[int, str]] = {}

    for name, (url, fmt) in FEEDS.items():
        try:
            found = fetch_feed(url, fmt)
        except OSError as e:
            report[name] = (0, 0)
            print(f"[!] Фид {name}: недоступен ({e})")
            continue
        for d in found:
            collected.setdefault(d, (8, f"{name} feed"))
        report[name] = (len(found), 0)

    if collected:
        _, total_after = merge_into_local(collected, ioc_path)
        # пересчитаем добавленное по факту
        added_total = sum(n for n, _ in report.values() if n)
        report["_total"] = (added_total, total_after)
    else:
        report["_total"] = (0, len(json.load(open(ioc_path or config.IOC_PATH)).get("domains", [])))
    return report


if __name__ == "__main__":
    rep = update_from_feeds()
    for k, (found, after) in rep.items():
        print(f"{k}: найдено {found}, всего доменов в базе теперь {after}")
