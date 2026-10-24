"""Тесты профилей по кабелю: разбор списка, быстрый аудит, ошибки установки.

USB profile tests: list parsing, quick audit, install errors.
"""

import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ghost_lock.modules import usb_profiles  # noqa: E402

LIST = json.dumps({
    "OrderedIdentifiers": ["cc.ghostlock.dnsshield.profile", "com.corp.mdm", "com.mspy.profile"],
    "ProfileMetadata": {
        "cc.ghostlock.dnsshield.profile": {"PayloadDisplayName": "ghost-lock DNS Shield (mullvad)",
                                           "PayloadOrganization": "ghost-lock"},
        "com.corp.mdm": {"PayloadDisplayName": "Corp", "PayloadOrganization": "ACME"},
        "com.mspy.profile": {"PayloadDisplayName": "Update"},
    },
    "Status": "Acknowledged",
})
IOCS = {"stalkerware_profiles": [{"value": "com.mspy.", "weight": 9}]}


def proc(rc=0, out="", err=""):
    return subprocess.CompletedProcess([], rc, out, err)


class TestParse(unittest.TestCase):
    def test_parse_with_log_prefix(self):
        profiles = usb_profiles.parse_profile_list("2026 INFO something\n" + LIST)
        self.assertEqual([p.identifier for p in profiles],
                         ["cc.ghostlock.dnsshield.profile", "com.corp.mdm", "com.mspy.profile"])
        self.assertEqual(profiles[1].organization, "ACME")

    def test_bad_status(self):
        with self.assertRaises(usb_profiles.UsbProfileError):
            usb_profiles.parse_profile_list(json.dumps({"Status": "Error"}))

    def test_garbage(self):
        with self.assertRaises(usb_profiles.UsbProfileError):
            usb_profiles.parse_profile_list("ERROR: Unable to retrieve device list!")


class TestQuickAudit(unittest.TestCase):
    def test_foreign_and_stalkerware(self):
        rep = usb_profiles.quick_audit(usb_profiles.parse_profile_list(LIST), IOCS)
        by_id = {f.value: f for f in rep.findings}
        self.assertEqual(set(by_id), {"com.corp.mdm", "com.mspy.profile"})
        self.assertEqual(by_id["com.mspy.profile"].ioc_type, "stalkerware_profiles")
        self.assertEqual(by_id["com.corp.mdm"].weight, usb_profiles.FOREIGN_WEIGHT)
        self.assertFalse(rep.lines[0][0])

    def test_only_own(self):
        own = [usb_profiles.UsbProfile("cc.ghostlock.wcf.profile", "Wall")]
        rep = usb_profiles.quick_audit(own, IOCS)
        self.assertEqual(rep.findings, [])
        self.assertTrue(rep.lines[0][0])


class TestRun(unittest.TestCase):
    def setUp(self):
        self.p = mock.patch.object(usb_profiles, "pmd3", return_value="/x/pymobiledevice3")
        self.p.start()

    def tearDown(self):
        self.p.stop()

    def test_list_passes_udid(self):
        with mock.patch.object(usb_profiles.subprocess, "run", return_value=proc(out=LIST)) as run:
            usb_profiles.list_profiles("UDID1")
        self.assertEqual(run.call_args.args[0][-2:], ["--udid", "UDID1"])

    def test_install_rejected_explains_lockdown(self):
        out = ("ERROR The device rejected the profile request: {'ErrorChain': [{'ErrorCode': 4022, "
               "'LocalizedDescription': 'The payload type “com.apple.dnsSettings.managed” is not permitted.'}]}")
        with mock.patch.object(usb_profiles.subprocess, "run", return_value=proc(rc=1, err=out)):
            with self.assertRaises(usb_profiles.UsbProfileError) as ctx:
                usb_profiles.install_profile(Path("p.mobileconfig"))
        self.assertIn("not permitted", str(ctx.exception))
        self.assertIn("Lockdown Mode", str(ctx.exception))

    def test_lockdown_mode_detected(self):
        out = ("ERROR The device rejected the profile request: {'ErrorChain': [{'ErrorCode': 4000, "
               "'LocalizedDescription': 'Profiles cannot be installed because Lockdown Mode is enabled'}]}")
        with mock.patch.object(usb_profiles.subprocess, "run", return_value=proc(rc=1, err=out)):
            with self.assertRaises(usb_profiles.LockdownModeError):
                usb_profiles.install_profile(Path("p.mobileconfig"))

    def test_install_uses_install_not_store(self):
        with mock.patch.object(usb_profiles.subprocess, "run", return_value=proc()) as run:
            usb_profiles.install_profile(Path("p.mobileconfig"))
        self.assertEqual(run.call_args.args[0][1:3], ["profile", "install"])

    def test_timeout(self):
        with mock.patch.object(usb_profiles.subprocess, "run",
                               side_effect=subprocess.TimeoutExpired("x", 1)):
            with self.assertRaises(usb_profiles.UsbProfileError):
                usb_profiles.list_profiles()


class TestMissing(unittest.TestCase):
    def test_no_pmd3(self):
        with mock.patch.object(usb_profiles, "pmd3", return_value=None):
            with self.assertRaises(usb_profiles.UsbProfileError) as ctx:
                usb_profiles.list_profiles()
        self.assertIn("pip install pymobiledevice3", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
