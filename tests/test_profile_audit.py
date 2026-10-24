"""Тесты аудита профилей: чужие профили, подделка «своих», сертификаты, покрытие.

Profile audit tests: foreign profiles, faked "own" ones, certificates, coverage.
"""

import datetime
import plistlib
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ghost_lock import config  # noqa: E402
from ghost_lock.modules import profile_audit  # noqa: E402

CP = "SysSharedContainerDomain-systemgroup.com.apple.configurationprofiles/Library/ConfigurationProfiles"
UCP = "HomeDomain/Library/UserConfigurationProfiles"
IOCS = {"stalkerware_profiles": [{"value": "com.mspy.", "weight": 9, "source": "mSpy"}]}


def stub(ident, payloads, name="", org=""):
    return {"PayloadIdentifier": ident, "PayloadDisplayName": name, "PayloadOrganization": org,
            "InstallDate": datetime.datetime(2026, 10, 1), "PayloadContent": payloads,
            "InstallOptions": {"installedBy": "com.apple.Preferences"}}


OWN_DNS = stub("cc.ghostlock.dnsshield.profile.family", [{
    "PayloadType": "com.apple.dnsSettings.managed",
    "DNSSettings": {"ServerURL": config.RESOLVER_PRESETS["family"]["doh"],
                    "ServerAddresses": config.RESOLVER_PRESETS["family"]["addresses"],
                    "AllowFailover": False}}])
OWN_WALL = stub("cc.ghostlock.wcf.profile", [{
    "PayloadType": "com.apple.webcontent-filter", "DenyListURLs": ["a.net", "b.net"]}])


class TestProfileAudit(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / CP).mkdir(parents=True)
        (self.root / UCP).mkdir(parents=True)
        self.n = 0

    def tearDown(self):
        self.tmp.cleanup()

    def add(self, data, name=None):
        self.n += 1
        with open(self.root / CP / (name or f"profile-{self.n}.stub"), "wb") as fh:
            plistlib.dump(data, fh, fmt=plistlib.FMT_BINARY)

    def run_audit(self, **kw):
        return profile_audit.audit(self.root, IOCS, **kw)

    def test_only_own_profiles_is_clean(self):
        self.add(OWN_DNS)
        self.add(OWN_WALL)
        self.add({"IsSupervised": False}, "CloudConfigurationDetails.plist")
        rep = self.run_audit(current_wcf_domains=["a.net", "b.net"])
        self.assertEqual(rep.findings, [])
        text = "\n".join(l for _, l in rep.lines)
        self.assertIn("Чужих профилей нет", text)
        self.assertIn("Domain Wall актуален", text)
        self.assertIn("Hardened: НЕ установлен", text)

    def test_old_dns_shield_version_flagged(self):
        old = stub("cc.ghostlock.dnsshield.profile.family", [{
            "PayloadType": "com.apple.dnsSettings.managed",
            "DNSSettings": {"ServerURL": config.RESOLVER_PRESETS["family"]["doh"],
                            "ServerFallback": ["185.228.168.168"]}}])
        self.add(old)
        rep = self.run_audit()
        self.assertTrue(any("старой версии" in l for _, l in rep.lines))
        self.assertTrue(any("dns-check" in r for r in rep.recommendations))

    def test_mdm_profile_is_critical(self):
        self.add(stub("com.corp.mdm", [{"PayloadType": "com.apple.mdm"},
                                       {"PayloadType": "com.apple.security.root"}], "Corp", "ACME"))
        rep = self.run_audit()
        weights = sorted(f.weight for f in rep.findings)
        self.assertEqual(weights, [10, 15])
        self.assertTrue(rep.recommendations)

    def test_stalkerware_prefix_matched(self):
        self.add(stub("com.mspy.profile", [{"PayloadType": "com.apple.vpn.managed"}]))
        rep = self.run_audit()
        self.assertIn("stalkerware_profiles", {f.ioc_type for f in rep.findings})

    def test_fake_own_name_not_trusted(self):
        # чужой DNS под именем ghost-lock / a foreign DNS posing as ghost-lock
        fake = stub("cc.ghostlock.dnsshield.profile.family", [{
            "PayloadType": "com.apple.dnsSettings.managed",
            "DNSSettings": {"ServerURL": "https://evil.example/dns-query"}}])
        self.add(fake)
        rep = self.run_audit()
        self.assertEqual([f.weight for f in rep.findings], [7])

    def test_fake_own_with_extra_payload_not_trusted(self):
        bad = stub("cc.ghostlock.wcf.profile", [
            {"PayloadType": "com.apple.webcontent-filter"},
            {"PayloadType": "com.apple.proxy.http.global"}])
        self.add(bad)
        rep = self.run_audit()
        self.assertIn(10, [f.weight for f in rep.findings])

    def test_outdated_wall(self):
        self.add(OWN_WALL)
        rep = self.run_audit(current_wcf_domains=["a.net", "b.net", "c.net"])
        self.assertTrue(any("устарел" in l for _, l in rep.lines))

    def test_user_trusted_certs(self):
        td = self.root / "ProtectedDomain/trustd/private"
        td.mkdir(parents=True)
        con = sqlite3.connect(td / "TrustStore.sqlite3")
        con.execute("CREATE TABLE tsettings(sha256 BLOB, subj BLOB, tset BLOB, data BLOB, uuid BLOB)")
        con.execute("INSERT INTO tsettings VALUES (x'01', x'02', NULL, NULL, x'03')")
        con.commit()
        con.close()
        rep = self.run_audit()
        self.assertEqual([f.ioc_type for f in rep.findings], ["certificate"])
        self.assertEqual(list(td.glob("*-shm")), [])

    def test_hardened_applied_count(self):
        hardened = self.root / "hardened.mobileconfig"
        with open(hardened, "wb") as fh:
            plistlib.dump({"PayloadContent": [{"PayloadType": "com.apple.applicationaccess",
                                               "allowAutoFill": False, "forceEncryptedBackup": True}]}, fh)
        with open(self.root / UCP / "EffectiveUserSettings.plist", "wb") as fh:
            plistlib.dump({"restrictedBool": {"allowAutoFill": {"value": False},
                                              "forceEncryptedBackup": {"value": False}}}, fh)
        rep = self.run_audit(hardened_profile=hardened)
        self.assertTrue(any("1 из 2" in l for _, l in rep.lines))

    def test_no_data(self):
        rep = profile_audit.audit(Path(self.tmp.name) / "empty", IOCS)
        self.assertFalse(rep.found_data)


if __name__ == "__main__":
    unittest.main()
