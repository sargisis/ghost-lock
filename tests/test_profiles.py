"""Тесты генератора DNS-профиля и валидность обоих .mobileconfig.

DNS profile generator tests; validity of both .mobileconfig files.
"""

import plistlib
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ghost_lock import config  # noqa: E402
from ghost_lock.modules import profile_gen  # noqa: E402


class TestPresets(unittest.TestCase):
    def test_default_preset_exists(self):
        self.assertIn(config.DEFAULT_RESOLVER_PRESET, config.RESOLVER_PRESETS)

    def test_every_preset_has_fallback_ips(self):
        for name, preset in config.RESOLVER_PRESETS.items():
            fallback = preset.get("fallback", [])
            self.assertTrue(fallback, f"{name}: нет ServerFallback — интернет может сломаться")
            for ip in fallback:
                parts = ip.split(".")
                self.assertEqual(len(parts), 4, f"{name}: битый IP {ip}")
                self.assertTrue(all(p.isdigit() and 0 <= int(p) <= 255 for p in parts))

    def test_unknown_preset_raises(self):
        with self.assertRaises(profile_gen.PresetError):
            profile_gen.resolve_doh_url("no-such-preset")

    def test_nextdns_requires_id(self):
        with self.assertRaises(profile_gen.PresetError):
            profile_gen.resolve_doh_url("nextdns")

    def test_nextdns_id_rejected_short(self):
        with self.assertRaises(profile_gen.PresetError):
            profile_gen.resolve_doh_url("nextdns", "ab;!")

    def test_nextdns_url_formatted(self):
        url = profile_gen.resolve_doh_url("nextdns", "abc123def")
        self.assertEqual(url, "https://dns.nextdns.io/abc123def")


class TestRenderedProfile(unittest.TestCase):
    def render(self, preset="family", nid=None):
        return plistlib.loads(profile_gen.render_profile(preset, nid).encode())

    def _dns_payload(self, data):
        payloads = data["PayloadContent"]
        self.assertEqual(len(payloads), 1)
        self.assertEqual(payloads[0]["PayloadType"], "com.apple.dnsSettings.managed")
        return payloads[0]["DNSSettings"]

    def test_family_preset_urls(self):
        dns = self._dns_payload(self.render())
        self.assertEqual(dns["ServerURL"], "https://doh.cleanbrowsing.org/doh/family-filter/")
        self.assertEqual(dns["ServerFallback"], ["185.228.168.168", "185.228.169.168"])
        self.assertEqual(dns["DNSProtocol"], "HTTPS")

    def test_cf_family_preset(self):
        dns = self._dns_payload(self.render("cf-family"))
        self.assertEqual(dns["ServerURL"], "https://family.cloudflare-dns.com/dns-query")

    def test_nextdns_preset_embeds_id(self):
        dns = self._dns_payload(self.render("nextdns", "abc123"))
        self.assertEqual(dns["ServerURL"], "https://dns.nextdns.io/abc123")

    def test_disablement_not_prohibited(self):
        payload = self.render()["PayloadContent"][0]
        self.assertFalse(payload["ProhibitDisablement"], "профиль должен быть снимаемым")

    def test_uuids_stable_across_presets(self):
        a, b = self.render("family"), self.render("security")
        self.assertEqual(a["PayloadUUID"], b["PayloadUUID"])
        self.assertEqual(
            a["PayloadContent"][0]["PayloadUUID"],
            b["PayloadContent"][0]["PayloadUUID"],
        )

    def test_no_unfilled_placeholders(self):
        for preset in ("family", "cf-family", "security"):
            raw = profile_gen.render_profile(preset)
            self.assertNotIn("{{", raw, f"пресет {preset}: остались плейсхолдеры")


class TestShippedProfilesValid(unittest.TestCase):
    """Реальные файлы profiles/*.mobileconfig из репозитория.

    The real profiles/*.mobileconfig files from the repository.
    """

    def test_dns_shield_is_valid_plist(self):
        data = plistlib.load(open(config.DNS_SHIELD_PROFILE, "rb"))
        self.assertEqual(data["PayloadType"], "Configuration")
        self.assertTrue(data["PayloadContent"])

    def test_dns_shield_has_fallback(self):
        data = plistlib.load(open(config.DNS_SHIELD_PROFILE, "rb"))
        dns = data["PayloadContent"][0]["DNSSettings"]
        self.assertTrue(dns.get("ServerFallback"), "нет фолбэка — риск сломать интернет")

    def test_hardened_is_valid_plist(self):
        data = plistlib.load(open(config.HARDENED_PROFILE, "rb"))
        types = [p["PayloadType"] for p in data["PayloadContent"]]
        self.assertIn("com.apple.applicationaccess", types)

    def test_hardened_restrictions_are_booleans(self):
        data = plistlib.load(open(config.HARDENED_PROFILE, "rb"))
        restrictions = data["PayloadContent"][0]
        bool_keys = [
            k for k in restrictions if k.startswith(("allow", "force")) and isinstance(restrictions[k], bool)
        ]
        self.assertTrue(bool_keys)


class TestGenerateToFile(unittest.TestCase):
    def test_generate_writes_valid_plist(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "out.mobileconfig"
            path = profile_gen.generate("cf-family", dest=dest)
            self.assertEqual(path, dest)
            data = plistlib.load(open(dest, "rb"))
            self.assertEqual(data["PayloadDisplayName"], "ghost-lock DNS Shield (cf-family)")


if __name__ == "__main__":
    unittest.main()
