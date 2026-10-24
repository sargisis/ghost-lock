"""Тесты проверок компьютера: записи сопряжения, шифрование диска, Portmaster.

Host checks tests: pairing records, disk encryption, Portmaster.
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ghost_lock.modules import host_check  # noqa: E402


class TestPairing(unittest.TestCase):
    def test_world_readable_flagged_private_not(self):
        with tempfile.TemporaryDirectory() as d:
            open_rec = Path(d, "UDID.plist")
            closed = Path(d, "SystemConfiguration.plist")
            open_rec.write_text("x")
            closed.write_text("x")
            os.chmod(open_rec, 0o644)
            os.chmod(closed, 0o600)
            self.assertEqual(host_check.exposed_pairing_records((Path(d),)), [open_rec])

    def test_group_readable_flagged(self):
        with tempfile.TemporaryDirectory() as d:
            rec = Path(d, "UDID.plist")
            rec.write_text("x")
            os.chmod(rec, 0o640)  # группа plugdev — это все, кто работает с USB
            self.assertEqual(host_check.exposed_pairing_records((Path(d),)), [rec])


class TestDisk(unittest.TestCase):
    def _linux(self, outputs):
        with mock.patch.object(host_check.platform, "system", return_value="Linux"), \
             mock.patch.object(host_check, "_run", side_effect=outputs):
            return host_check.root_disk_encrypted()

    def test_luks_chain(self):
        self.assertTrue(self._linux(["/dev/mapper/ubuntu--vg-ubuntu--lv\n",
                                     "lvm\ncrypt\npart\ndisk\n"]))

    def test_plain(self):
        self.assertFalse(self._linux(["/dev/nvme0n1p2\n", "part\ndisk\n"]))

    def test_unknown(self):
        self.assertIsNone(self._linux(["", ""]))


class TestPortmaster(unittest.TestCase):
    def test_detect(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, "123").mkdir()
            Path(d, "123", "comm").write_text("portmaster-core\n")
            Path(d, "self").mkdir()
            self.assertTrue(host_check.portmaster_running(Path(d)))

    def test_absent(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, "1").mkdir()
            Path(d, "1", "comm").write_text("systemd\n")
            self.assertFalse(host_check.portmaster_running(Path(d)))


if __name__ == "__main__":
    unittest.main()
