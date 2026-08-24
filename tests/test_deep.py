"""Тесты глубокого режима: сбой бэкапа -> мягкий результат без краха.

Deep-mode tests: backup failure -> soft result without a crash.
"""

import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ghost_lock.modules import deep_scan  # noqa: E402
from ghost_lock.modules.spyware_scan import ScanResult, Finding  # noqa: E402


class TestDeepScan(unittest.TestCase):
    def test_backup_failure_is_soft(self):
        with mock.patch.object(deep_scan, "_run_backup", return_value=(False, "нет кабеля")):
            res = deep_scan.run("UDID", {"DeviceName": "X"})
        self.assertEqual(res.findings, [])
        self.assertEqual(res.files_scanned, 0)
        self.assertIn("не удался", res.stats_note)

    def test_success_prefixes_locations(self):
        finding = Finding(ioc_type="domain", value="mobilesms.io", weight=10,
                          source="t", location="/tmp/x/file.ips", context="...")
        fake = ScanResult(findings=[finding], files_scanned=42)
        with mock.patch.object(deep_scan, "_run_backup", return_value=(True, "")), \
             mock.patch("ghost_lock.modules.spyware_scan.run_scan", return_value=fake):
            res = deep_scan.run("UDID", {"DeviceName": "X"})
        self.assertEqual(res.files_scanned, 42)
        self.assertTrue(all(f.location.startswith("backup:") for f in res.findings))
        self.assertIn("file.ips", res.findings[0].location)

    def test_run_backup_timeout_handled(self):
        with mock.patch.object(deep_scan.subprocess, "run",
                               side_effect=deep_scan.subprocess.TimeoutExpired(cmd="b", timeout=1)):
            ok, err = deep_scan._run_backup("U", Path("/tmp/opencode/deep-test"))
        self.assertFalse(ok)
        self.assertIn("таймаут", err)


if __name__ == "__main__":
    unittest.main()
