"""Тесты diagnostics: фильтрация логов, статистика, экспорт с мок-сабпроцессом.

diagnostics tests: log filtering, stats, export with mocked subprocess.
"""

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ghost_lock.modules import diagnostics  # noqa: E402


class TestCollectLogFiles(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _make(self, relpath: str, content: bytes | str):
        p = self.root / relpath
        p.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            p.write_bytes(content)
        else:
            p.write_text(content)
        return p

    def test_text_logs_collected(self):
        self._make("a.ips", "Process: Safari [1]")
        self._make("b.crash", "Crash report")
        self._make("c.panic", "panic")
        files = diagnostics.collect_log_files(self.root)
        names = {f.name for f in files}
        self.assertEqual(names, {"a.ips", "b.crash", "c.panic"})

    def test_binary_file_skipped(self):
        self._make("garbage.ips", b"\x00\x01\x02\xff\xfe\xfd")
        self.assertEqual(diagnostics.collect_log_files(self.root), [])

    def test_extensionless_files_included(self):
        self._make("plainlog", "some text log")
        files = diagnostics.collect_log_files(self.root)
        self.assertEqual([f.name for f in files], ["plainlog"])

    def test_txt_extension_excluded(self):
        self._make("notes.txt", "not a crash log")
        self.assertEqual(diagnostics.collect_log_files(self.root), [])

    def test_recursive_walk(self):
        self._make("Retired/deep/x.ips", "content")
        files = diagnostics.collect_log_files(self.root)
        self.assertEqual(len(files), 1)

    def test_sorted_output_deterministic(self):
        for name in ("z.ips", "a.ips", "m.ips"):
            self._make(name, "t")
        files = [f.name for f in diagnostics.collect_log_files(self.root)]
        self.assertEqual(files, ["a.ips", "m.ips", "z.ips"])


class TestLogStats(unittest.TestCase):
    def test_counts_by_type_and_total(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a.ips").write_text("x")
            (root / "b.ips").write_text("y")
            (root / "sub").mkdir()
            (root / "sub" / "c.crash").write_text("z")
            stats = diagnostics.log_stats(root)
            self.assertEqual(stats["total"], 3)
            self.assertEqual(stats["by_type"][".ips"], 2)
            self.assertEqual(stats["by_type"][".crash"], 1)

    def test_empty_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            stats = diagnostics.log_stats(Path(tmp))
            self.assertEqual(stats, {"total": 0, "by_type": {}})


class TestExportCrashLogs(unittest.TestCase):
    @mock.patch.object(diagnostics.subprocess, "run")
    def test_export_counts_files(self, run):
        run.return_value = mock.Mock(returncode=0, stdout="", stderr="")
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(diagnostics.config, "CRASH_DIR", Path(tmp)):
                dest = Path(tmp) / "UDID"
                dest.mkdir()
                (dest / "one.ips").write_text("x")
                out_dir, count = diagnostics.export_crash_logs("UDID")
            self.assertEqual(out_dir.name, "UDID")
            self.assertGreaterEqual(count, 1)

    @mock.patch.object(diagnostics.subprocess, "run")
    def test_tool_failure_with_existing_data_not_fatal(self, run):
        run.return_value = mock.Mock(returncode=1, stderr="boom")
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(diagnostics.config, "CRASH_DIR", Path(tmp)):
                d = Path(tmp) / "UDID"
                d.mkdir()
                (d / "old.ips").write_text("kept")
                out_dir, count = diagnostics.export_crash_logs("UDID")
                self.assertEqual(count, 1)


if __name__ == "__main__":
    unittest.main()
