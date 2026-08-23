"""Тесты отчёта: подстановка плейсхолдеров, экранирование, таблицы."""

import sys
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ghost_lock import config  # noqa: E402
from ghost_lock.modules import report as report_mod  # noqa: E402
from ghost_lock.modules.models import Finding  # noqa: E402
from ghost_lock.modules.spyware_scan import render_findings_table  # noqa: E402


def build(**overrides):
    defaults = dict(
        device_rows=[("Имя устройства", "iPhone"), ("Версия iOS", "27.0")],
        findings_rows_html="<tr><td colspan='6'>none</td></tr>",
        findings_count=0,
        files_scanned=10,
        ioc_meta="v1.1.0",
        recommendations=["Шаг один", "Шаг <два>"],
        verdict_key="clean",
        score=0,
    )
    defaults.update(overrides)
    return report_mod.build_report(**defaults)


class TestBuildReport(unittest.TestCase):
    def test_no_unfilled_placeholders(self):
        self.assertNotIn("{{", build())

    def test_verdict_clean_rendered(self):
        html = build(verdict_key="clean", score=0)
        self.assertIn("CLEAN / Чисто", html)
        self.assertIn("badge clean", html)

    def test_verdict_critical_rendered(self):
        html = build(verdict_key="critical", score=42, findings_count=3)
        self.assertIn("CRITICAL / Критично", html)
        self.assertIn("badge critical", html)

    def test_unknown_verdict_fallback(self):
        self.assertIn("UNKNOWN", build(verdict_key="bogus"))

    def test_score_rendered(self):
        self.assertIn("score 1337", build(score=1337))

    def test_device_rows_rendered(self):
        html = build(device_rows=[("UDID", "abc-123")])
        self.assertIn("UDID", html)
        self.assertIn("<code>abc-123</code>", html)

    def test_html_escaped_in_values(self):
        html = build(device_rows=[("XSS", "<script>alert(1)</script>")])
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_recommendations_escaped_and_listed(self):
        html = build(recommendations=["a < b"])
        self.assertIn("<li>a &lt; b</li>", html)

    def test_counters_rendered(self):
        html = build(findings_count=7, files_scanned=463)
        self.assertIn("Находки (7)", html)
        self.assertIn("463", html)


class TestFindingsTable(unittest.TestCase):
    def test_empty_shows_placeholder_row(self):
        self.assertIn("Совпадений не найдено", render_findings_table([]))

    def test_finding_row_contains_fields(self):
        f = Finding(
            ioc_type="domains",
            value="mobilesms.io",
            weight=10,
            source="Citizen Lab",
            location="/logs/evil.ips",
            context="GET http://mobilesms.io/x <b>",
        )
        row = render_findings_table([f])
        self.assertIn("mobilesms.io", row)
        self.assertIn("evil.ips", row)
        self.assertIn("Citizen Lab", row)
        # контекст экранирован: <b> из лога превращён в &lt;b>
        self.assertIn("&lt;b>", row)
        self.assertNotIn("<b>mobilesms.io/x", row)  # сырое значение не утекло


class TestWriteReport(unittest.TestCase):
    def test_written_to_reports_dir_with_stamp(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(config, "REPORTS_DIR", Path(tmp)):
                path = report_mod.write_report("<html>ok</html>")
                self.assertTrue(str(path).startswith(str(tmp)))
                self.assertRegex(path.name, r"report_\d{8}_\d{6}\.html")
                self.assertEqual(path.read_text(), "<html>ok</html>")


if __name__ == "__main__":
    unittest.main()
