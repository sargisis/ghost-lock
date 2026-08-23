"""IOC-сканер: сопоставляет выгруженные логи и инфо устройства с базой индикаторов.

Методика вдохновлена Amnesty International MVT: краш-логи и системные
артефакты ищутся на совпадения с публичными IOC шпионского ПО.
"""

from __future__ import annotations

import json
import re
import subprocess
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .. import config
from .diagnostics import collect_log_files
from .models import Finding
from .phishing_guard import heuristic_url_findings

GO_BIN = config.REPO_ROOT / "go" / "bin" / "glock-scan"
# Файлы, которые Python дочитывает сам для URL-эвристик поверх Go-скана.
HEURISTIC_MAX_BYTES = 2_000_000


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    stats_note: str = ""

    @property
    def score(self) -> int:
        return sum(f.weight for f in self.findings)

    def verdict(self) -> tuple[str, str]:
        t = config.THRESHOLDS
        if self.score >= t["critical"]:
            return config.VERDICTS["critical"]
        if self.score >= t["suspicious"]:
            return config.VERDICTS["suspicious"]
        return config.VERDICTS["clean"]


def load_iocs(path: Path | None = None) -> dict[str, Any]:
    path = path or config.IOC_PATH
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    required = ("domains", "jailbreak_artifacts", "spyware_strings")
    missing = [k for k in required if k not in data]
    if missing:
        raise ValueError(f"В {path} отсутствуют секции: {missing}")
    return data


def _normalize(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    return re.sub(r"\s+", " ", text).strip()


# Строки с word-boundary, чтобы не ловить «pegasus» внутри легитимных имён.
_WORDBOUND_TYPES = {"spyware_strings"}


def _allowlist(iocs: dict[str, Any]) -> list[re.Pattern[str]]:
    compiled = []
    for raw in iocs.get("allowlist", []):
        try:
            compiled.append(re.compile(str(raw), re.IGNORECASE))
        except re.error:
            continue
    return compiled


# Кэш плоского списка игл: сборка один раз на набор IOC.
_NEEDLE_CACHE: dict[tuple, list[tuple[str, dict, str, bool]]] = {}


def _flat_needles(iocs: dict[str, Any]) -> list[tuple[str, dict, str, bool]]:
    """[(needle_lower, ioc_entry, section, word_boundary)] — отсортированы по длине убыв."""
    sections = ("domains", "jailbreak_artifacts", "spyware_strings", "stalkerware_profiles")
    cache_key = tuple(
        tuple(
            str(x.get("value", "")) if isinstance(x, dict) else ""
            for x in iocs.get(section, [])
        )
        for section in sections
    )
    cached = _NEEDLE_CACHE.get(cache_key)
    if cached:
        return cached

    needles: list[tuple[str, dict, str, bool]] = []
    for section in sections:
        for ioc in iocs.get(section, []):
            needle = str(ioc.get("value", "")).lower().strip() if isinstance(ioc, dict) else ""
            if not needle:
                continue
            wb = section in _WORDBOUND_TYPES and len(needle.split()) == 1
            needles.append((needle, ioc, section, wb))
    needles.sort(key=lambda t: -len(t[0]))
    _NEEDLE_CACHE[cache_key] = needles
    return needles


def scan_text(iocs: dict[str, Any], text: str, location: str) -> list[Finding]:
    allow = _allowlist(iocs)
    lowered = text.lower()
    findings: list[Finding] = []

    for needle, ioc, section, wb in _flat_needles(iocs):
        # Ищем все вхождения, пока не найдём то, что не гасится allowlist'ом
        # и проходит границы слова. dedupe схлопнет повторы файла.
        idx = lowered.find(needle)
        hops = 0
        recorded = False
        while idx != -1 and hops < 10_000:
            hops += 1
            end = idx + len(needle)

            if wb:
                before_ok = idx == 0 or not lowered[idx - 1].isalnum()
                after_ok = end >= len(lowered) or not lowered[end].isalnum()
                if not (before_ok and after_ok):
                    idx = lowered.find(needle, end or idx + 1)
                    continue

            ls = text.rfind("\n", 0, idx) + 1
            le = text.find("\n", idx)
            if le == -1:
                le = len(text)
            lineno = text.count("\n", 0, ls) + 1
            line = _normalize(lowered[ls:le])

            # Allowlist: легитимное ПО в той же строке гасит совпадение.
            if any(a.search(line) for a in allow):
                idx = lowered.find(needle, end or idx + 1)
                continue

            pos = max(line.find(needle) - 80, 0)
            context = line[pos : pos + 200]
            findings.append(Finding(
                ioc_type=section,
                value=ioc["value"],
                weight=int(ioc.get("weight", 5)),
                source=f"{ioc.get('source', 'unknown')} (строка {lineno})",
                location=location,
                context=context.replace("\x00", ""),
            ))
            recorded = True
            break

        if recorded:
            continue

    findings.extend(heuristic_url_findings(iocs, text, location))
    return findings


def dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple] = set()
    out: list[Finding] = []
    for f in sorted(findings, key=lambda x: -x.weight):
        key = (f.ioc_type, f.value, f.location)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def scan_device_info(iocs: dict[str, Any], info: dict[str, Any]) -> list[Finding]:
    blob = json.dumps(info, ensure_ascii=False, default=str)
    return scan_text(iocs, blob, "device_info")


def scan_crash_logs(iocs: dict[str, Any], crash_dir: Path) -> tuple[list[Finding], int]:
    files = collect_log_files(crash_dir)
    findings: list[Finding] = []
    for f in files:
        try:
            text = f.read_text(errors="replace")
        except OSError:
            continue
        findings.extend(scan_text(iocs, text, str(f.relative_to(crash_dir.parent))))
    return dedupe(findings), len(files)


def go_available() -> bool:
    return GO_BIN.exists()


def _scan_with_go(crash_dir: Path) -> ScanResult | None:
    """Тяжёлый IOC-скан отдаём Go-бинарнику (в ~7 раз быстрее Python)."""
    if not go_available():
        return None
    try:
        proc = subprocess.run(
            [str(GO_BIN), "-iocs", str(config.IOC_PATH), "-dir", str(crash_dir)],
            capture_output=True,
            text=True,
            timeout=600,
        )
        if proc.returncode != 0:
            return None
        data = json.loads(proc.stdout)
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return None

    result = ScanResult()
    for f in data.get("findings", []):
        result.findings.append(Finding(
            ioc_type=str(f["type"]),
            value=str(f["value"]),
            weight=int(f["weight"]),
            source=str(f["source"]),
            location=str(f["location"]),
            context=str(f["context"]),
        ))
    result.files_scanned = int(data["stats"]["files"])
    return result


def run_scan(info: dict[str, Any], crash_dir: Path | None) -> ScanResult:
    iocs = load_iocs()
    result = ScanResult()
    result.findings.extend(scan_device_info(iocs, info))

    if crash_dir and crash_dir.exists():
        engine_go = False
        go_result = _scan_with_go(crash_dir)
        if go_result is not None:
            result.findings.extend(go_result.findings)
            result.files_scanned = go_result.files_scanned
            engine_go = True
        else:
            log_findings, n = scan_crash_logs(iocs, crash_dir)
            result.files_scanned = n
            result.findings.extend(log_findings)

        # URL-эвристики — Python поверх (малые файлы, недорого)
        for f in collect_log_files(crash_dir):
            try:
                if f.stat().st_size > HEURISTIC_MAX_BYTES:
                    continue
                text = f.read_text(errors="replace")
            except OSError:
                continue
            result.findings.extend(heuristic_url_findings(iocs, text, str(f.relative_to(crash_dir.parent))))

        if engine_go:
            result.stats_note = "engine: Go"
    result.findings = dedupe(result.findings)
    return result


def render_findings_table(findings: list[Finding]) -> str:
    if not findings:
        return '<tr><td colspan="6" class="muted">Совпадений не найдено</td></tr>'
    rows = []
    for f in findings:
        ctx = f.context[:120].replace("<", "&lt;")
        loc = Path(f.location).name
        rows.append(
            f"<tr><td>{f.ioc_type}</td><td><b>{f.value}</b></td>"
            f"<td>{f.weight}</td><td>{loc}</td>"
            f"<td class='ctx'>{ctx}</td><td>{f.source}</td></tr>"
        )
    return "\n".join(rows)
