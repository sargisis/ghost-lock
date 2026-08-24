"""Тесты Web Content Filter профиля (Spyware Domain Wall)."""

import plistlib
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ghost_lock.modules import profile_gen  # noqa: E402


class TestSelectWcfDomains(unittest.TestCase):
    def test_ranked_by_weight_desc(self):
        iocs = {"domains": [
            {"value": "low.org", "weight": 5},
            {"value": "top.org", "weight": 10},
            {"value": "mid.org", "weight": 8},
        ]}
        self.assertEqual(profile_gen.select_wcf_domains(iocs), ["top.org", "mid.org", "low.org"])

    def test_dedupe_keeps_max_weight(self):
        iocs = {"domains": [
            {"value": "dup.org", "weight": 6},
            {"value": "dup.org", "weight": 9},
        ]}
        self.assertEqual(profile_gen.select_wcf_domains(iocs), ["dup.org"])

    def test_allowlist_excluded(self):
        iocs = {
            "allowlist": ["apple\\.com$"],
            "domains": [{"value": "pegasus.apple.com", "weight": 10},
                        {"value": "evil-c2.org", "weight": 9}],
        }
        self.assertEqual(profile_gen.select_wcf_domains(iocs), ["evil-c2.org"])

    def test_cap_respected(self):
        iocs = {"domains": [{"value": f"d{i}.org", "weight": i} for i in range(100)]}
        self.assertEqual(len(profile_gen.select_wcf_domains(iocs, cap=10)), 10)

    def test_garbage_skipped(self):
        iocs = {"domains": [
            "not-a-dict",
            {"value": "", "weight": 9},
            {"value": "nodot", "weight": 9},
            {"value": "ok.example", "weight": 9},
        ]}
        self.assertEqual(profile_gen.select_wcf_domains(iocs), ["ok.example"])


class TestWcfProfile(unittest.TestCase):
    def setUp(self):
        self.xml = profile_gen.render_wcf_profile(["evil-c2.org", "second.evil.net"])
        self.pl = plistlib.loads(self.xml.encode())

    def test_valid_plist_with_builtin_filter(self):
        payload = self.pl["PayloadContent"][0]
        self.assertEqual(payload["PayloadType"], "com.apple.webcontent-filter")
        self.assertEqual(payload["FilterType"], "BuiltIn")
        # несупервизируемые устройства требуют ContentFilterUUID
        self.assertTrue(payload.get("ContentFilterUUID"))
        self.assertEqual(payload["DenyListURLs"], ["evil-c2.org", "second.evil.net"])

    def test_count_in_display_name(self):
        self.assertIn("(2)", self.pl["PayloadDisplayName"])

    def test_stable_uuids(self):
        pl2 = plistlib.loads(profile_gen.render_wcf_profile(["x.org"]).encode())
        self.assertEqual(self.pl["PayloadUUID"], pl2["PayloadUUID"])
        self.assertEqual(
            self.pl["PayloadContent"][0]["PayloadUUID"],
            pl2["PayloadContent"][0]["PayloadUUID"],
        )

    def test_real_database_generates_full_profile(self):
        from ghost_lock import config
        path = profile_gen.generate_wcf(dest=config.PROFILES_DIR / "_test_wcf.mobileconfig")
        try:
            data = plistlib.load(open(path, "rb"))
            domains = data["PayloadContent"][0]["DenyListURLs"]
            self.assertGreater(len(domains), 100)
            self.assertLessEqual(len(domains), profile_gen.WCF_MAX_DOMAINS)
            # allowlist не протёк
            self.assertNotIn("pegasus.apple.com", domains)
            self.assertEqual(len(domains), len(set(domains)))
        finally:
            path.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
