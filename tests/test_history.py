"""Тесты истории аудитов (SQLite) и diff «что изменилось».

Audit-history (SQLite) tests and the "what changed" diff.
"""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ghost_lock.modules import history  # noqa: E402


class HistoryBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "history.db"

    def tearDown(self):
        self.tmp.cleanup()

    def save(self, udid="UDID1", apps=None, crashes=None, score=0):
        return history.save_audit(
            udid=udid, device="iPhone", ios_version="27.0",
            verdict="clean" if score < 3 else "suspicious", score=score,
            files_scanned=100 + score, apps=apps or [],
            crash_names=crashes or [], ioc_version="9.9.9", path=self.db)


class TestSaveAndLast(HistoryBase):
    def test_first_audit_has_no_history(self):
        self.assertIsNone(history.last_audit("UDID1", self.db))

    def test_save_returns_id_and_last_works(self):
        aid = self.save(score=5)
        self.assertEqual(aid, 1)
        last = history.last_audit("UDID1", self.db)
        self.assertEqual(last["score"], 5)
        self.assertEqual(last["verdict"], "suspicious")

    def test_udids_isolated(self):
        self.save(udid="A")
        self.assertIsNone(history.last_audit("B", self.db))


class TestDiff(HistoryBase):
    def test_first_audit_flagged(self):
        rep = history.diff_with_history(
            udid="X", current_apps=[], current_crash_names=[], path=self.db)
        self.assertTrue(rep.is_first_audit)

    def test_new_app_detected(self):
        self.save(apps=[("com.a", "1.0"), ("com.b", "2.0")])
        rep = history.diff_with_history(
            udid="UDID1",
            current_apps=[("com.a", "1.0"), ("com.b", "2.0"), ("com.evil.stalker", "1.0")],
            current_crash_names=[], path=self.db)
        self.assertEqual(rep.new_apps, [("com.evil.stalker", "1.0")])

    def test_removed_app_detected(self):
        self.save(apps=[("com.gone", "1.0")])
        rep = history.diff_with_history(
            udid="UDID1", current_apps=[("com.a", "1.0")],
            current_crash_names=[], path=self.db)
        self.assertEqual(rep.removed_apps, ["com.gone"])

    def test_reinstall_same_app_not_new(self):
        self.save(apps=[("com.a", "1.0"), ("com.b", "1.0")])
        self.save(apps=[("com.a", "1.0")])  # b удалили
        rep = history.diff_with_history(
            udid="UDID1", current_apps=[("com.a", "1.0"), ("com.b", "2.0")],
            current_crash_names=[], path=self.db)
        # com.b был в истории → не новый; com.gone нет в текущих, но и
        # сравнение идёт со ВСЕЙ историей: удалённым считается то, что
        # было когда-либо и пропало сейчас
        self.assertEqual(rep.new_apps, [])
        self.assertEqual(rep.removed_apps, [])

    def test_new_crash_counted_against_full_history(self):
        self.save(crashes=["a.ips"])
        self.save(crashes=["a.ips", "b.ips"])
        rep = history.diff_with_history(
            udid="UDID1", current_apps=[],
            current_crash_names=["a.ips", "b.ips", "c.ips"], path=self.db)
        self.assertEqual(rep.new_crashes, 1)

    def test_prev_score_carried(self):
        self.save(score=7)
        rep = history.diff_with_history(
            udid="UDID1", current_apps=[], current_crash_names=[], path=self.db)
        self.assertEqual(rep.prev_score, 7)


class TestFormat(unittest.TestCase):
    def test_first_audit_message(self):
        lines = history.format_diff(history.DiffReport())
        self.assertIn("Первый", lines[0])

    def test_changes_listed(self):
        rep = history.DiffReport(prev_ts="t", prev_score=0,
                                 new_apps=[("com.x", "1"), ("com.y", "2")],
                                 new_crashes=14)
        text = "\n".join(history.format_diff(rep))
        self.assertIn("Новые приложения (2)", text)
        self.assertIn("com.x", text)
        self.assertIn("14", text)

    def test_no_changes_message(self):
        rep = history.DiffReport(prev_ts="t", prev_score=0)
        self.assertEqual(history.format_diff(rep), ["Изменений с прошлого аудита нет."])


if __name__ == "__main__":
    unittest.main()
