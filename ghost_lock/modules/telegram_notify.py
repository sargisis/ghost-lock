"""Telegram-алерты: сообщение после каждого аудита.

Настройка (один раз, без Apple Developer):
  1. В Telegram напиши @BotFather → /newbot → получишь токен.
  2. python3 ghost_lock/ghost_lock.py setup-telegram --token <ТОКЕН>
  3. Перешли боту любое слово — скрипт поймает chat_id и вышлет тест.

Токен лежит в ~/.config/ghost-lock/telegram.json с правами 600,
в репозиторий не попадает. Любая ошибка сети — просто warning в лог,
аудит никогда не падает из-за уведомлений.
"""

from __future__ import annotations

import json
import os
import stat
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

CONFIG_DIR = Path(os.environ.get("HOME", "~")).expanduser() / ".config" / "ghost-lock"
CONFIG_PATH = CONFIG_DIR / "telegram.json"
API = "https://api.telegram.org/bot{token}/{method}"

VERDICT_STYLE = {
    "clean": ("✅", "ЧИСТО"),
    "suspicious": ("⚠️", "ПОДОЗРИТЕЛЬНО"),
    "critical": ("🚨", "КРИТИЧНО!"),
}


class TelegramError(Exception):
    pass


def _load_config(path: Path | None = None) -> dict[str, Any] | None:
    p = path or CONFIG_PATH
    try:
        cfg = json.loads(p.read_text(encoding="utf-8"))
        if cfg.get("bot_token") and cfg.get("chat_id"):
            return cfg
    except (OSError, ValueError):
        pass
    return None


def _save_config(bot_token: str, chat_id: int | str, path: Path | None = None) -> Path:
    p = path or CONFIG_PATH
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(
        json.dumps({"bot_token": bot_token, "chat_id": chat_id}, ensure_ascii=False),
        encoding="utf-8",
    )
    p.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 600
    return p


def _call(token: str, method: str, params: dict[str, Any] | None = None,
          timeout: int = 15) -> dict[str, Any]:
    url = API.format(token=token, method=method)
    data = urllib.parse.urlencode(params or {}).encode()
    req = urllib.request.Request(url, data=data, headers={"User-Agent": "ghost-lock/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        payload = json.loads(resp.read().decode())
    if not payload.get("ok"):
        raise TelegramError(str(payload.get("description", "unknown")))
    return payload.get("result", {})


def get_updates(token: str, timeout: int = 30) -> list[dict[str, Any]]:
    """Последние апдейты бота — из них достаём chat_id."""
    res = _call(token, "getUpdates", {"timeout": timeout - 5}, timeout=timeout + 5)
    return res if isinstance(res, list) else []


def extract_chat_id(updates: list[dict[str, Any]]) -> int | None:
    for upd in reversed(updates):  # свежее сообщение приоритетнее
        msg = upd.get("message") or upd.get("edited_message") or {}
        chat = msg.get("chat") or {}
        cid = chat.get("id")
        if cid is not None:
            return int(cid)
    return None


def send_message(text: str, token: str | None = None, chat_id: int | str | None = None) -> bool:
    cfg = _load_config()
    token = token or (cfg or {}).get("bot_token")
    chat_id = chat_id or (cfg or {}).get("chat_id")
    if not token or not chat_id:
        return False
    _call(token, "sendMessage", {
        "chat_id": chat_id,
        "text": text[:4000],
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    })
    return True


def format_audit(verdict_en: str, verdict_ru: str, score: int,
                 device: str, files_scanned: int, findings_top: list[tuple[int, str, str]],
                 report_name: str, extra_lines: list[str] | None = None) -> str:
    emoji, label = VERDICT_STYLE.get(verdict_en.lower(), ("❓", verdict_en))
    lines = [
        f"{emoji} <b>ghost-lock: {label}</b> (score {score})",
        f"📱 {device}",
        f"🗂 просканировано файлов: {files_scanned}",
    ]
    if extra_lines:
        lines.append("")
        for ln in extra_lines:
            lines.append(_esc(ln))
    if findings_top:
        lines.append("\n<b>Топ находок:</b>")
        for weight, value, location in findings_top[:5]:
            lines.append(f"• [{weight}] <code>{_esc(value)}</code> ← {_esc(location)}")
        if len(findings_top) > 5:
            lines.append(f"...и ещё {len(findings_top) - 5}")
    else:
        lines.append("\nСовпадений с базой IOC нет.")
    lines.append(f"\n📄 {_esc(report_name)}")
    return "\n".join(lines)


def notify_audit(*, verdict_en: str, verdict_ru: str, score: int, device: str,
                 files_scanned: int, findings_top: list[tuple[int, str, str]],
                 report_path: str, extra_lines: list[str] | None = None) -> bool:
    """Шлёт алерт. Тихо возвращает False если не настроено/нет сети."""
    try:
        text = format_audit(
            verdict_en, verdict_ru, score, device, files_scanned,
            findings_top, Path(report_path).name, extra_lines=extra_lines,
        )
        return send_message(text)
    except Exception:
        return False


def _esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
