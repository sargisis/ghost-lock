"""Фишинг-щит: эвристики подозрительных URL/IP + данные для DNS-профиля.

На телефоне постоянную защиту даёт dns_shield.mobileconfig (DoH с
блокировкой малвари на уровне резолвера). Здесь мы дополняем аудит:
ищем в логах следы фишинговых/подозрительных доменов.
"""

from __future__ import annotations

import re
from typing import Any

from .models import Finding

_URL_RE = re.compile(
    r"(?:https?://|www\.)[a-z0-9\-._~%]+(?:/[^\s\"'<>]*)?",
    re.IGNORECASE,
)


def extract_urls(text: str) -> set[str]:
    return {m.group(0).rstrip(".,;)") for m in _URL_RE.finditer(text)}


def _host_of(url: str) -> str:
    host = re.sub(r"^[a-z]+://", "", url, flags=re.IGNORECASE)
    return host.split("/")[0].split(":")[0].lower()


def heuristic_url_findings(
    iocs: dict[str, Any], text: str, location: str
) -> list[Finding]:
    """Ищет хосты, попадающие под фишинг-эвристики."""
    ph = iocs.get("phishing_heuristics", {})
    brands = [b.lower() for b in ph.get("brand_keywords", [])]
    bad_tlds = tuple(t.lower() for t in ph.get("tld_watchlist", []))
    patterns = [
        (re.compile(p["pattern"], re.IGNORECASE), p["desc"])
        for p in ph.get("patterns", [])
    ]

    findings: list[Finding] = []
    seen: set[str] = set()

    for url in extract_urls(text):
        host = _host_of(url)
        if not host or "." not in host or host in seen:
            continue
        seen.add(host)

        reason = None

        # 1. Бренд + watchlist-TLD: apple-id-verify.top
        if any(b in host for b in brands) and host.endswith(bad_tlds):
            reason = "имитация бренда + подозрительный TLD"

        # 2. Фишинговая лексика рядом с брендом: secure-appleid-login.com
        if reason is None and any(b in host for b in brands):
            for rx, desc in patterns:
                if rx.search(host) and "сырой IP" not in desc:
                    reason = f"имитация бренда ({desc})"
                    break

        # 3. Общие паттерны на любом хосте (punycode, сырой IP)
        if reason is None:
            for rx, desc in patterns:
                if rx.search(host):
                    reason = desc
                    break

        if reason:
            findings.append(Finding(
                ioc_type="phishing_heuristic",
                value=host,
                weight=3,
                source=f"Эвристика: {reason}",
                location=location,
                context=url[:160],
            ))
    return findings


def blocklist_for_profile(domains: list[str]) -> str:
    """Формирует человекочитаемый блоклист для описания DNS-профиля."""
    lines = [f"- {d}" for d in sorted(set(d.lower() for d in domains))]
    return "\n".join(lines) if lines else "(пусто)"
