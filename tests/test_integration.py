"""Интеграционные тесты: полный пайплайн сканера и CLI.

Integration tests: full scanner pipeline and CLI.
"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ghost_lock.modules.spyware_scan import load_iocs, run_scan, scan_text  # noqa: E402

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CLI = PROJECT_ROOT / "ghost_lock" / "ghost_lock.py"

PEGASUS_LOG = """
Process: sync-services.net [99]
0   libfrigate.dylib frigate_init + 12
http://mobilesms.io/api/v1/checkin token=abc123
"""


class TestFullPipeline(unittest.TestCase):
    def _write_crash_logs(self, root: Path) -> Path:
        d = root / "UDID"
        d.mkdir(parents=True)
        (d / "evil.ips").write_text(PEGASUS_LOG)
        (d / "clean.ips").write_text("Process: Safari [5] EXC_BAD_ACCESS\n")
        (d / "binary.ips").write_bytes(b"\x00\xff\x00")
        return d

    def test_pipeline_detects_and_scores_critical(self):
        findings = scan_text(load_iocs(), PEGASUS_LOG, "evil.ips")
        score = sum(f.weight for f in findings)
        values = {f.value for f in findings}
        self.assertIn("mobilesms.io", values)
        self.assertIn("sync-services.net", values)
        self.assertGreaterEqual(score, 15)

    def test_run_scan_on_tmp_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            crash_dir = self._write_crash_logs(Path(tmp))
            result = run_scan({"DeviceName": "iPhone"}, crash_dir)
            # движок может быть Go (считает все читаемые файлы) или Python
            # (пропускает бинарники) — важно, что зловред найден
            self.assertGreaterEqual(result.files_scanned, 2)
            self.assertTrue(any(f.value == "mobilesms.io" for f in result.findings))
            self.assertGreaterEqual(result.score, 15)

    def test_run_scan_without_crash_dir(self):
        result = run_scan({"DeviceName": "iPhone", "x": "pegasus"}, None)
        self.assertEqual(result.files_scanned, 0)
        self.assertEqual(result.verdict()[0], "SUSPICIOUS")

    def test_device_info_json_serializable_for_scan(self):
        blob = json.dumps({"BatteryIsCharging": True, "n": None}, default=str)
        self.assertIn("true", blob)


class TestCli(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run(
            [sys.executable, str(CLI), *args],
            capture_output=True,
            text=True,
            timeout=120,
            cwd=str(PROJECT_ROOT),
        )

    def test_cli_help_exits_zero(self):
        proc = self.run_cli("--help")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("audit", proc.stdout)

    def test_profiles_generates_valid_profile(self):
        proc = self.run_cli("profiles")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        raw = (PROJECT_ROOT / "ghost_lock/profiles/dns_shield.mobileconfig").read_text()
        self.assertIn("ServerFallback", raw)
        self.assertNotIn("{{", raw)

    def test_profiles_unknown_preset_fails_cleanly(self):
        # argparse отсекает неверный choice с кодом 2 до нашей валидации
        proc = self.run_cli("profiles", "--preset", "nope")
        self.assertEqual(proc.returncode, 2)
        self.assertNotIn("Traceback", proc.stdout + proc.stderr)

    def test_profiles_nextdns_requires_id(self):
        proc = self.run_cli("profiles", "--preset", "nextdns")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("--nextdns-id", proc.stdout + proc.stderr)

    def test_audit_without_device_fails_with_hint(self):
        # На машине без айфона аудит должен завершиться понятной ошибкой,
        # а не трейсбеком.
        proc = self.run_cli("audit")
        if proc.returncode != 0:
            combined = proc.stdout + proc.stderr
            self.assertNotIn("Traceback", combined, combined)
            self.assertTrue(any(k in combined for k in ("usbmuxd", "Доверять", "не найдено")))


if __name__ == "__main__":
    unittest.main()
