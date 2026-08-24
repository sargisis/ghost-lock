"""Тесты проверки версии iOS. Обновление IOC тестируется в test_ioc_stix.py.

iOS version check tests. IOC updates are covered in test_ioc_stix.py.
"""

import json
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ghost_lock.modules import os_check  # noqa: E402


def ipsw_payload(version="18.6"):
    return {
        "firmwares": [
            {"version": version, "signed": True},
            {"version": "16.7.10", "signed": True},
            {"version": "15.8.3", "signed": False},  # неподписанные игнорируем
        ]
    }


class TestOsCheck(unittest.TestCase):
    @mock.patch.object(os_check.urllib.request, "urlopen")
    def test_up_to_date(self, urlopen):
        urlopen.return_value.__enter__.return_value = mock.Mock(
            read=lambda: json.dumps(ipsw_payload("18.6")).encode()
        )
        status = os_check.check_os("iPhone15,2", "18.6")
        self.assertFalse(status.outdated)
        self.assertEqual(status.latest, "18.6")

    @mock.patch.object(os_check.urllib.request, "urlopen")
    def test_outdated_detected(self, urlopen):
        urlopen.return_value.__enter__.return_value = mock.Mock(
            read=lambda: json.dumps(ipsw_payload("18.6")).encode()
        )
        status = os_check.check_os("iPhone15,2", "17.5.1")
        self.assertTrue(status.outdated)
        self.assertIn("Обнови", status.note)

    @mock.patch.object(os_check.urllib.request, "urlopen")
    def test_network_failure_is_soft(self, urlopen):
        urlopen.side_effect = OSError("no net")
        status = os_check.check_os("iPhone15,2", "17.5.1")
        self.assertIsNone(status.outdated)  # не знаем — не пугаем
        self.assertIn("вручную", status.note)

    @mock.patch.object(os_check.urllib.request, "urlopen")
    def test_malformed_json_is_soft(self, urlopen):
        urlopen.return_value.__enter__.return_value = mock.Mock(read=lambda: b"{broken")
        self.assertIsNone(os_check.check_os("iPhoneX", "16.0").latest)

    @mock.patch.object(os_check.urllib.request, "urlopen")
    def test_picks_highest_signed(self, urlopen):
        payload = {
            "firmwares": [
                {"version": "18.6", "signed": True},
                {"version": "19.0", "signed": False},
                {"version": "17.6", "signed": True},
            ]
        }
        urlopen.return_value.__enter__.return_value = mock.Mock(
            read=lambda: json.dumps(payload).encode()
        )
        self.assertEqual(os_check.fetch_latest_ios("iPhone15,2"), "18.6")


class TestRealDatabase(unittest.TestCase):
    def test_real_database_still_valid(self):
        from ghost_lock.modules.spyware_scan import load_iocs
        from ghost_lock import config
        iocs = load_iocs(config.IOC_PATH)
        self.assertTrue(iocs.get("spyware_bundles"))


if __name__ == "__main__":
    unittest.main()
