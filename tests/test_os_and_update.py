"""Тесты проверки версии iOS и обновления IOC."""

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ghost_lock.modules import ioc_update, os_check  # noqa: E402


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


BASE_IOC = {
    "_meta": {"version": "1.0.0"},
    "domains": [
        {"value": "mobilesms.io", "weight": 10, "source": "CL"},
        {"value": "sync-services.net", "weight": 10, "source": "CL"},
    ],
}


class TestIocUpdate(unittest.TestCase):
    def _merge(self, new_domains):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "indicators.json"
            path.write_text(json.dumps(BASE_IOC))
            added, total = ioc_update.merge_into_local(new_domains, path)
            result = json.loads(path.read_text())
            return added, total, result

    def test_new_domain_added(self):
        added, total, db = self._merge({"new-evil.com": (8, "feed")})
        values = {d["value"] for d in db["domains"]}
        self.assertEqual(added, 1)
        self.assertEqual(total, 3)
        self.assertIn("new-evil.com", values)
        self.assertIn("feed", [d["source"] for d in db["domains"]])

    def test_duplicates_not_added(self):
        added, _, db = self._merge({"mobilesms.io": (8, "dup")})
        self.assertEqual(added, 0)
        self.assertEqual(len(db["domains"]), 2)

    def test_case_insensitive_dedupe(self):
        added, _, _db = self._merge({"MOBILESMS.IO": (8, "dup")})
        self.assertEqual(added, 0)

    def test_meta_updated_and_version_bumped(self):
        _, _, db = self._merge({"x.net": (8, "f")})
        self.assertNotEqual(db["_meta"]["version"], "1.0.0")
        self.assertTrue(db["_meta"].get("updated"))

    def test_txt_feed_parsing(self):
        text = "# comment\n\nevil-domain.com\ngood2.org\nnot_a_domain\nimage.png\n"
        with mock.patch.object(ioc_update.urllib.request, "urlopen") as uo:
            uo.return_value.__enter__.return_value = mock.Mock(
                read=lambda: text.encode()
            )
            domains = ioc_update.fetch_feed("http://x/dl.txt", "txt")
        self.assertEqual(domains, ["evil-domain.com", "good2.org"])

    def test_stix_pattern_parsing(self):
        stix = json.dumps({"objects": [
            {"type": "indicator", "pattern": "[domain-name:value = 'C2.EVIL.org']"},
            {"type": "indicator", "pattern": "[domain-name:value = 'second.example']"},
        ]})
        with mock.patch.object(ioc_update.urllib.request, "urlopen") as uo:
            uo.return_value.__enter__.return_value = mock.Mock(read=lambda: stix.encode())
            domains = ioc_update.fetch_feed("http://x/stix.json", "stix")
        self.assertEqual(sorted(domains), ["c2.evil.org", "second.example"])

    def test_skip_format_returns_empty(self):
        self.assertEqual(ioc_update.fetch_feed("http://x", "skip"), [])

    def test_real_database_still_valid_after_logic(self):
        from ghost_lock.modules.spyware_scan import load_iocs
        from ghost_lock import config
        iocs = load_iocs(config.IOC_PATH)  # не тронута тестами выше
        self.assertTrue(iocs.get("spyware_bundles"))


if __name__ == "__main__":
    unittest.main()
