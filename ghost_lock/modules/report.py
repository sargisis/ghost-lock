"""Генерация HTML-отчёта аудита.

HTML report generation for audits.
"""

from __future__ import annotations

import html as html_mod
from datetime import datetime
from pathlib import Path

from .. import config


def _esc(v: str) -> str:
    return html_mod.escape(str(v))


def build_report(
    device_rows: list[tuple[str, str]],
    findings_rows_html: str,
    findings_count: int,
    files_scanned: int,
    ioc_meta: str,
    recommendations: list[str],
    verdict_key: str,
    score: int,
) -> str:
    template = config.TEMPLATE_PATH.read_text(encoding="utf-8")
    verdict_en, verdict_ru = config.VERDICTS.get(verdict_key, ("UNKNOWN", "Неизвестно"))

    rec_items = "\n".join(f"<li>{_esc(r)}</li>" for r in recommendations)
    dev_rows = "\n".join(
        f"<tr><td>{_esc(t)}</td><td><code>{_esc(v)}</code></td></tr>"
        for t, v in device_rows
    )

    return (
        template.replace("{{VERDICT}}", f"{verdict_en} / {verdict_ru}")
        .replace("{{VERDICT_CLASS}}", verdict_en.lower())
        .replace("{{SCORE}}", str(score))
        .replace("{{DEVICE_ROWS}}", dev_rows)
        .replace("{{FINDINGS_ROWS}}", findings_rows_html)
        .replace("{{FINDINGS_COUNT}}", str(findings_count))
        .replace("{{FILES_SCANNED}}", str(files_scanned))
        .replace("{{IOC_META}}", _esc(ioc_meta))
        .replace("{{RECOMMENDATIONS}}", rec_items)
        .replace("{{TIMESTAMP}}", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    )


def write_report(html: str) -> Path:
    config.ensure_dirs()
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = config.REPORTS_DIR / f"report_{stamp}.html"
    path.write_text(html, encoding="utf-8")
    return path


BASE_RECOMMENDATIONS = [
    "Lockdown Mode включён - отлично, держи его всегда для угрожаемых сценариев.",
    "Установи профиль dns_shield.mobileconfig (инструкция: ghost_lock.py profiles) - постоянный DoH-щит от малвари и фишинга.",
    "Обнови iOS до последней версии: эксплойты закрываются патчами Apple быстрее, чем кем-либо ещё.",
    "Проверь Настройки → Основное → VPN и управление устройством: там не должно быть незнакомых профилей.",
    "Для максимального уровня рассмотри режим «Под контролем» (Apple Configurator на Mac) - он открывает жёсткие ограничения.",
]
