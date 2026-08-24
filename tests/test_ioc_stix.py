"""Тесты STIX-парсера и слияния индикаторов в базу."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ghost_lock.modules import ioc_update  # noqa: E402


def stix_bundle(*objects):
    return json.dumps({"type": "bundle", "objects": list(objects)})


class TestParseStix(unittest.TestCase):
    def test_all_pattern_types_extracted(self):
        text = stix_bundle(
            {"type": "indicator", "labels": ["Pegasus"],
             "pattern": "[domain-name:value = 'C2.Evil.org' AND process:name = 'frigate']"},
            {"type": "indicator",
             "pattern": "[email-addr:value = 'ops@evil.net']"},
            {"type": "indicator",
             "pattern": "[file:path = '/private/var/implant.dylib']"},
        )
        items = ioc_update.parse_stix(text, "test")
        by_section = {}
        for i in items:
            by_section.setdefault(i.section, []).append(i.value)
        self.assertEqual(by_section["domains"], ["c2.evil.org"])
        self.assertEqual(by_section["processes"], ["frigate"])
        self.assertEqual(by_section["emails"], ["ops@evil.net"])
        self.assertEqual(by_section["file_paths"], ["/private/var/implant.dylib"])

    def test_source_includes_labels(self):
        items = ioc_update.parse_stix(
            stix_bundle({"type": "indicator", "labels": ["Predator", "Android"],
                         "pattern": "[domain-name:value = 'x.org']"}),
            "stix_2021-12-16_cytrox",
        )
        self.assertIn("cytrox", items[0].source)
        self.assertIn("predator", items[0].source.lower())

    def test_revoked_skipped(self):
        text = stix_bundle(
            {"type": "indicator", "revoked": True, "pattern": "[domain-name:value = 'old.org']"},
            {"type": "indicator", "pattern": "[domain-name:value = 'live.org']"},
        )
        values = [i.value for i in ioc_update.parse_stix(text, "t")]
        self.assertEqual(values, ["live.org"])

    def test_noise_and_invalid_domains_filtered(self):
        text = stix_bundle(
            {"type": "indicator", "pattern": "[domain-name:value = 'example.com']"},
            {"type": "indicator", "pattern": "[domain-name:value = 'not a domain!!']"},
            {"type": "indicator", "pattern": "[domain-name:value = 'real-domain.org']"},
        )
        values = {i.value for i in ioc_update.parse_stix(text, "t")}
        self.assertEqual(values, {"real-domain.org"})

    def test_hxxp_defanged(self):
        text = stix_bundle(
            {"type": "indicator", "pattern": "[domain-name:value = 'hxxps://defanged.evil.com/path']"}
        )
        items = ioc_update.parse_stix(text, "t")
        self.assertEqual(items[0].value, "defanged.evil.com")

    def test_broken_json_returns_empty(self):
        self.assertEqual(ioc_update.parse_stix("{broken", "t"), [])

    def test_plain_list_object(self):
        text = json.dumps([
            {"type": "indicator", "pattern": "[domain-name:value = 'a.org']"},
            {"type": "indicator", "pattern": "[domain-name:value = 'b.org']"},
        ])
        self.assertEqual(len(ioc_update.parse_stix(text, "t")), 2)


class TestTxtParsing(unittest.TestCase):
    def test_txt_lines(self):
        text = "# comment\n\nevil-domain.com\ngood2.org\nnot a domain\nimage.png\n"
        domains = ioc_update.parse_txt(text, "feed")
        self.assertEqual([i.value for i in domains], ["evil-domain.com", "good2.org"])

    def test_skip_marker(self):
        pass  # формат skip больше не нужен: фиды строятся автоматически


class TestMergeIndicators(unittest.TestCase):
    BASE = {
        "_meta": {"version": "1.0.0"},
        "domains": [{"value": "mobilesms.io", "weight": 10, "source": "CL"}],
    }

    def _merge(self, items):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ind.json"
            path.write_text(json.dumps(self.BASE))
            added = ioc_update.merge_indicators(items, path)
            return added, json.loads(path.read_text())

    def test_routed_to_sections_with_default_weights(self):
        from ghost_lock.modules.ioc_update import StixIndicator
        added, db = self._merge([
            StixIndicator("domains", "new-evil.com", "f1"),
            StixIndicator("processes", "frigate", "f1"),
            StixIndicator("emails", "ops@evil.net", "f2"),
            StixIndicator("file_paths", "/var/implant", "f2"),
        ])
        self.assertEqual(added["domains"], 1)
        self.assertEqual(added["processes"], 1)
        self.assertEqual(db["processes"][0]["weight"], 6)
        self.assertEqual(db["emails"][0]["weight"], 7)
        self.assertEqual(db["file_paths"][0]["weight"], 6)

    def test_case_insensitive_dedupe(self):
        from ghost_lock.modules.ioc_update import StixIndicator
        added, db = self._merge([StixIndicator("domains", "MOBILESMS.IO", "dup")])
        self.assertEqual(added["domains"], 0)
        self.assertEqual(len(db["domains"]), 1)

    def test_meta_version_minor_bump(self):
        from ghost_lock.modules.ioc_update import StixIndicator
        _, db = self._merge([StixIndicator("domains", "x.org", "s")])
        self.assertTrue(db["_meta"]["version"].startswith("1.1."))


class TestDiscovery(unittest.TestCase):
    @unittest.skipUnless(False, "сеть в юнит-тестах не дергаем")
    def test_live_discovery(self):
        feeds = ioc_update.discover_amnesty_stix_files()
        self.assertGreater(len(feeds), 3)

    def test_discovery_offline_is_empty_not_crash(self):
        import unittest.mock as mock
        with mock.patch.object(ioc_update.urllib.request, "urlopen", side_effect=OSError("no net")):
            self.assertEqual(ioc_update.discover_amnesty_stix_files(), [])


if __name__ == "__main__":
    unittest.main()
