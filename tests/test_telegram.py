"""Тесты Telegram-алертов: форматирование, конфиг, устойчивость к сбоям."""

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ghost_lock.modules import telegram_notify as tg  # noqa: E402


class TestFormatAudit(unittest.TestCase):
    def test_clean_verdict(self):
        text = tg.format_audit("clean", "Чисто", 0, "iPhone 15", 500,
                               [], "report_x.html")
        self.assertIn("✅", text)
        self.assertIn("ЧИСТО", text)
        self.assertIn("score 0", text)
        self.assertIn("iPhone 15", text)

    def test_critical_with_findings(self):
        text = tg.format_audit(
            "critical", "Критично", 42, "iPhone", 300,
            [(10, "mobilesms.io", "evil.ips"), (8, "frida-server", "log.ips")],
            "report_y.html",
        )
        self.assertIn("🚨", text)
        self.assertIn("mobilesms.io", text)
        self.assertIn("frida-server", text)
        self.assertIn("Топ находок", text)

    def test_html_escaping(self):
        text = tg.format_audit("suspicious", "Сус", 5, "iPhone", 10,
                               [(3, "<script>alert(1)</script>", "a&b.ips")], "r.html")
        self.assertNotIn("<script>", text)
        self.assertIn("&lt;script&gt;", text)
        self.assertIn("a&amp;b.ips", text)

    def test_truncated_findings_list(self):
        findings = [(i, f"d{i}.evil.com", "x.ips") for i in range(1, 9)]
        text = tg.format_audit("critical", "Кр", 99, "iPhone", 1, findings, "r.html")
        self.assertIn("и ещё 3", text)


class TestConfig(unittest.TestCase):
    def test_save_and_load_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "tg.json"
            tg._save_config("123:ABC", 777, path)
            cfg = tg._load_config(path)
            self.assertEqual(cfg["bot_token"], "123:ABC")
            self.assertEqual(cfg["chat_id"], 777)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_missing_or_broken_config_is_none(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "nope.json"
            self.assertIsNone(tg._load_config(p))
            p.write_text("{broken")
            self.assertIsNone(tg._load_config(p))
            p.write_text(json.dumps({"bot_token": "", "chat_id": 1}))
            self.assertIsNone(tg._load_config(p))


class TestExtractChatId(unittest.TestCase):
    def test_from_message(self):
        updates = [{"message": {"chat": {"id": -100123}, "text": "привет"}}]
        self.assertEqual(tg.extract_chat_id(updates), -100123)

    def test_latest_wins(self):
        updates = [
            {"update_id": 1, "message": {"chat": {"id": 111}}},
            {"update_id": 2, "message": {"chat": {"id": 222}}},
        ]
        self.assertEqual(tg.extract_chat_id(updates), 222)

    def test_empty_returns_none(self):
        self.assertIsNone(tg.extract_chat_id([]))


class TestResilience(unittest.TestCase):
    def test_notify_skips_when_not_configured(self):
        with mock.patch.object(tg, "_load_config", return_value=None):
            self.assertFalse(tg.notify_audit(
                verdict_en="clean", verdict_ru="Чисто", score=0,
                device="X", files_scanned=1, findings_top=[], report_path="/tmp/r.html",
            ))

    def test_network_failure_swallowed(self):
        cfg = {"bot_token": "t", "chat_id": 1}
        with mock.patch.object(tg, "_load_config", return_value=cfg), \
             mock.patch.object(tg, "_call", side_effect=OSError("no net")):
            self.assertFalse(tg.notify_audit(
                verdict_en="clean", verdict_ru="Чисто", score=0,
                device="X", files_scanned=1, findings_top=[], report_path="/tmp/r.html",
            ))

    def test_send_message_true_on_success(self):
        cfg = {"bot_token": "t", "chat_id": 1}
        with mock.patch.object(tg, "_load_config", return_value=cfg), \
             mock.patch.object(tg, "_call", return_value={}):
            self.assertTrue(tg.send_message("hi"))


if __name__ == "__main__":
    unittest.main()
