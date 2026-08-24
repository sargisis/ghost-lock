"""Тесты чека гигиены (PasswordProtected и честные «не читается»)."""

import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ghost_lock.modules import hygiene  # noqa: E402


class TestHygiene(unittest.TestCase):
    def test_false_passcode_is_unknown_not_accomplice(self):
        """PasswordProtected=false доказанно врёт на iOS 27 (пароль включён).
        Трактуем как «не читается», НИКОГДА как «выключен»."""
        checks = hygiene.check_hygiene({"PasswordProtected": "false"})
        pc = next(c for c in checks if c.key == "passcode")
        self.assertIsNone(pc.ok)

    def test_xml_boolean_false_same_treatment(self):
        pc = next(c for c in hygiene.check_hygiene({"PasswordProtected": False})
                  if c.key == "passcode")
        self.assertIsNone(pc.ok)

    def test_true_is_informational_ok(self):
        checks = hygiene.check_hygiene({"PasswordProtected": True})
        pc = next(c for c in checks if c.key == "passcode")
        self.assertTrue(pc.ok)

    def test_passcode_ok(self):
        checks = hygiene.check_hygiene({"PasswordProtected": "true"})
        pc = next(c for c in checks if c.key == "passcode")
        self.assertTrue(pc.ok)

    def test_missing_field_is_unknown_not_false_alarm(self):
        checks = hygiene.check_hygiene({})
        pc = next(c for c in checks if c.key == "passcode")
        self.assertIsNone(pc.ok)

    def test_penalty_always_zero_on_unreliable_signal(self):
        self.assertEqual(hygiene.hygiene_score(hygiene.check_hygiene({"PasswordProtected": "false"})), 0)
        self.assertEqual(hygiene.hygiene_score(hygiene.check_hygiene({"PasswordProtected": True})), 0)
        self.assertEqual(hygiene.hygiene_score(hygiene.check_hygiene({})), 0)

    def test_biometry_honestly_unreadable(self):
        checks = hygiene.check_hygiene({"PasswordProtected": "true"})
        bio = next(c for c in checks if c.key == "biometry")
        self.assertIsNone(bio.ok)

    def test_fetch_failure_returns_empty_info(self):
        with mock.patch.object(hygiene.subprocess, "run", side_effect=OSError("no")):
            self.assertEqual(hygiene.fetch_info(), {})


if __name__ == "__main__":
    unittest.main()
