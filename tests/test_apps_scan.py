"""Тесты скана приложений: парсинг ideviceinstaller и сверка со шпионскими bundle-id.

App-scan tests: ideviceinstaller parsing and matching against spyware bundle IDs.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ghost_lock.modules import apps_scan  # noqa: E402

SAMPLE_OUTPUT = """cc.ghostlock.app - GhostLock 1.0
com.apple.mobilesafari - Mobile Safari (27.0)
ru.yandex.searchplugin - Яндекс 23.10.1
com.spotify.client - Spotify (8.9.4)
"""


def make_iocs():
    return {
        "spyware_bundles": [
            {"value": "com.mspy.", "weight": 10, "source": "mSpy"},
            {"value": "keylogger", "weight": 8, "source": "generic"},
        ]
    }


class TestParse(unittest.TestCase):
    def test_parses_bundle_name_version(self):
        apps = apps_scan.parse_app_list(SAMPLE_OUTPUT)
        self.assertEqual(len(apps), 4)
        safari = next(a for a in apps if a.bundle_id == "com.apple.mobilesafari")
        self.assertEqual(safari.name, "Mobile Safari")
        self.assertEqual(safari.version, "27.0")

    def test_version_optional(self):
        apps = apps_scan.parse_app_list("cc.x.app - SomeApp\n")
        self.assertEqual(apps[0].version, "")
        self.assertEqual(apps[0].name, "SomeApp")

    def test_en_dash_supported(self):
        apps = apps_scan.parse_app_list("a.b.c – Name App v2\n")
        self.assertEqual(len(apps), 1)
        self.assertEqual(apps[0].bundle_id, "a.b.c")

    def test_garbage_lines_ignored(self):
        apps = apps_scan.parse_app_list("garbage line\n\nanother\n")
        self.assertEqual(apps, [])

    def test_empty_output(self):
        self.assertEqual(apps_scan.parse_app_list(""), [])


class TestScanApps(unittest.TestCase):
    def test_mspy_detected(self):
        apps = apps_scan.parse_app_list("com.mspy.agent - mSpy Agent 5.1\n")
        f = apps_scan.scan_apps(make_iocs(), apps)
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].weight, 10)
        self.assertIn("com.mspy.agent", f[0].location)

    def test_keylogger_in_appname_detected(self):
        apps = apps_scan.parse_app_list("com.shady.app - Super KeyLogger Pro\n")
        f = apps_scan.scan_apps(make_iocs(), apps)
        self.assertEqual([x.value for x in f], ["keylogger"])

    def test_clean_apps_no_findings(self):
        apps = apps_scan.parse_app_list(SAMPLE_OUTPUT)
        self.assertEqual(apps_scan.scan_apps(make_iocs(), apps), [])

    def test_one_finding_per_ioc_even_if_multiple_apps(self):
        output = "com.mspy.one - A\ncom.mspy.two - B\n"
        f = apps_scan.scan_apps(make_iocs(), apps_scan.parse_app_list(output))
        self.assertEqual(len(f), 1)

    def test_missing_weight_defaults(self):
        iocs = {"spyware_bundles": [{"value": "evil"}]}
        apps = apps_scan.parse_app_list("com.evil.bundle - Evil\n")
        f = apps_scan.scan_apps(iocs, apps)
        self.assertEqual(f[0].weight, 5)

    def test_empty_ioc_section_safe(self):
        self.assertEqual(apps_scan.scan_apps({}, []), [])


if __name__ == "__main__":
    unittest.main()
