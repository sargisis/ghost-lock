"""Тесты: один аудит за раз и --if-stale для демона.

Tests: one audit at a time and --if-stale for the daemon.
"""

import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import ghost_lock.ghost_lock as cli  # noqa: E402


class TestAuditLock(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.patch = mock.patch.object(cli, "AUDIT_LOCK", Path(self.tmp.name) / "audit.lock")
        self.patch.start()

    def tearDown(self):
        self.patch.stop()
        self.tmp.cleanup()

    def test_second_lock_refused_until_released(self):
        first = cli._acquire_audit_lock()
        self.assertTrue(first)
        self.assertIsNone(cli._acquire_audit_lock())
        first.close()
        again = cli._acquire_audit_lock()
        self.assertTrue(again)
        again.close()

    def test_recent_audit_minutes(self):
        ts = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat(timespec="seconds")
        with mock.patch("ghost_lock.modules.history.last_audit", return_value={"ts": ts}):
            age = cli._recent_audit_minutes("U")
        self.assertAlmostEqual(age, 5, delta=0.5)
        with mock.patch("ghost_lock.modules.history.last_audit", return_value=None):
            self.assertIsNone(cli._recent_audit_minutes("U"))


if __name__ == "__main__":
    unittest.main()
