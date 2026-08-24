"""Тесты IOC-сканера: сопоставление, allowlist, скоринг, дедупликация.

IOC-scanner tests: matching, allowlist, scoring, deduplication.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ghost_lock.modules.spyware_scan import (  # noqa: E402
    ScanResult,
    dedupe,
    load_iocs,
    scan_text,
)


def make_iocs(**overrides):
    base = {
        "domains": [
            {"value": "mobilesms.io", "weight": 10, "source": "test"},
            {"value": "sync-services.net", "weight": 10, "source": "test"},
        ],
        "jailbreak_artifacts": [
            {"value": "/Applications/Cydia.app", "weight": 8, "source": "test"},
        ],
        "spyware_strings": [
            {"value": "pegasus", "weight": 4, "source": "test"},
        ],
        "stalkerware_profiles": [
            {"value": "com.mspy.", "weight": 9, "source": "test"},
        ],
        "phishing_heuristics": {
            "brand_keywords": ["apple", "icloud"],
            "tld_watchlist": [".top"],
            "patterns": [{"pattern": "xn--", "desc": "punycode"}],
        },
    }
    base.update(overrides)
    return base


class TestIocMatching(unittest.TestCase):
    def setUp(self):
        self.iocs = make_iocs()

    def test_clean_log_no_findings(self):
        text = "Process: MobileSafari [123]\nException Type: EXC_BAD_ACCESS\n"
        self.assertEqual(scan_text(self.iocs, text, "x.ips"), [])

    def test_domain_hit(self):
        f = scan_text(self.iocs, "GET http://mobilesms.io/api HTTP/1.1", "a.log")
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].ioc_type, "domains")
        self.assertEqual(f[0].weight, 10)

    def test_case_insensitive(self):
        f = scan_text(self.iocs, "http://MOBILESMS.IO/checkin", "a.log")
        self.assertEqual(len(f), 1)

    def test_jailbreak_artifact(self):
        f = scan_text(self.iocs, "dyld loaded /Applications/Cydia.app", "b.log")
        self.assertEqual(f[0].value, "/Applications/Cydia.app")

    def test_stalkerware_profile_prefix(self):
        f = scan_text(self.iocs, "profile com.mspy.payload installed", "c.log")
        self.assertEqual(f[0].value, "com.mspy.")

    def test_multiple_hits_deduped_by_location(self):
        text = ("http://mobilesms.io/x\n" * 3) + "http://sync-services.net/y\n"
        f = dedupe(scan_text(self.iocs, text, "d.log"))
        values = sorted(x.value for x in f)
        self.assertEqual(values, ["mobilesms.io", "sync-services.net"])

    def test_same_ioc_different_locations_both_kept(self):
        f = dedupe(
            scan_text(self.iocs, "mobilesms.io", "one.log")
            + scan_text(self.iocs, "mobilesms.io", "two.log")
        )
        self.assertEqual(len(f), 2)

    def test_line_number_recorded(self):
        f = scan_text(self.iocs, "line1\nline2\nsync-services.net here", "e.log")
        self.assertIn("строка 3", f[0].source)

    def test_context_captured_around_match(self):
        f = scan_text(self.iocs, "A" * 100 + " mobilesms.io " + "B" * 100, "f.log")
        self.assertIn("mobilesms.io", f[0].context)

    def test_missing_weight_defaults_to_five(self):
        iocs = make_iocs(domains=[{"value": "mobilesms.io", "source": "t"}])
        f = scan_text(iocs, "mobilesms.io", "g.log")
        self.assertEqual(f[0].weight, 5)

    def test_malformed_ioc_entry_does_not_crash(self):
        iocs = make_iocs(domains=[{"nope": True}])
        f = scan_text(iocs, "anything mobilesms.io", "h.log")  # type: ignore[arg-type]
        self.assertTrue(all(x.value != "" for x in f))


class TestAllowlist(unittest.TestCase):
    def setUp(self):
        self.iocs = make_iocs(allowlist=[
            r"/system/library/privateframeworks/pegasus\.framework",
            r"\(pegasus \+ \d+\)",
        ])

    def test_apple_framework_path_suppressed(self):
        line = "/System/Library/PrivateFrameworks/Pegasus.framework/Pegasus pegasus"
        self.assertEqual(scan_text(self.iocs, line, "fw.ips"), [])

    def test_stack_frame_suppressed(self):
        self.assertEqual(
            scan_text(self.iocs, "1 ??? (Pegasus + 225680) [0x1caf13190]", "fr.ips"), []
        )

    def test_real_spyware_string_still_flags(self):
        f = scan_text(self.iocs, "pegasus implant beacon detected", "bad.ips")
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].value, "pegasus")

    def test_invalid_allowlist_regex_ignored(self):
        iocs = make_iocs(allowlist=["[unclosed"])
        f = scan_text(iocs, "pegasus found", "i.ips")
        self.assertEqual(len(f), 1)

    def test_allowlist_only_gates_same_line(self):
        iocs = make_iocs(allowlist=[r"pegasus\.framework"])
        text = "/System/.../Pegasus.framework ok\npegasus alone"
        f = scan_text(iocs, text, "j.ips")
        self.assertEqual(len(f), 1)  # только вторая строка


class TestWordBoundary(unittest.TestCase):
    def test_substring_not_matched_for_single_word_strings(self):
        iocs = make_iocs()
        f = scan_text(iocs, "pegasusair flight crashed", "k.ips")
        self.assertEqual([x for x in f if x.value == "pegasus"], [])

    def test_exact_word_matched(self):
        iocs = make_iocs()
        f = scan_text(iocs, "process named pegasus exited", "l.ips")
        self.assertEqual(len(f), 1)

    def test_multiword_needle_skips_wordboundary_rule(self):
        iocs = make_iocs(spyware_strings=[
            {"value": "predator implant", "weight": 9, "source": "t"},
        ])
        f = scan_text(iocs, "found predator implants here", "m.ips")
        self.assertEqual(len(f), 1)


class TestScoring(unittest.TestCase):
    def _result(self, weights):
        from ghost_lock.modules.models import Finding
        r = ScanResult()
        r.findings = [
            Finding("domains", f"d{i}", w, "src", "loc") for i, w in enumerate(weights)
        ]
        return r

    def test_clean_below_threshold(self):
        self.assertEqual(self._result([2]).verdict()[0], "CLEAN")

    def test_suspicious_at_lower_boundary(self):
        self.assertEqual(self._result([3]).verdict()[0], "SUSPICIOUS")

    def test_suspicious_below_critical(self):
        self.assertEqual(self._result([7, 7]).verdict()[0], "SUSPICIOUS")

    def test_critical_at_boundary(self):
        self.assertEqual(self._result([15]).verdict()[0], "CRITICAL")

    def test_score_is_sum_of_weights(self):
        self.assertEqual(self._result([10, 8, 2]).score, 20)

    def test_verdict_has_russian_pair(self):
        en, ru = self._result([]).verdict()
        self.assertEqual((en, ru), ("CLEAN", "Чисто"))


class TestDedupe(unittest.TestCase):
    def test_keeps_highest_weight_first(self):
        from ghost_lock.modules.models import Finding
        a = Finding("t", "v", 3, "s", "l")
        b = Finding("t", "v", 9, "s", "l")
        out = dedupe([a, b])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].weight, 9)

    def test_empty_input(self):
        self.assertEqual(dedupe([]), [])


class TestLoadRealDatabase(unittest.TestCase):
    """Тесты реальной базы indicators.json из репозитория.

    Tests against the real indicators.json database from the repository.
    """

    @classmethod
    def setUpClass(cls):
        cls.iocs = load_iocs()

    def test_required_sections_present(self):
        for key in ("domains", "jailbreak_artifacts", "spyware_strings"):
            self.assertIn(key, self.iocs)

    def test_weights_in_valid_range(self):
        for section in ("domains", "jailbreak_artifacts", "spyware_strings", "stalkerware_profiles"):
            for ioc in self.iocs.get(section, []):
                self.assertGreaterEqual(int(ioc["weight"]), 1, f"{section}: {ioc}")
                self.assertLessEqual(int(ioc["weight"]), 10, f"{section}: {ioc}")

    def test_every_ioc_has_source(self):
        for section in ("domains", "jailbreak_artifacts", "spyware_strings"):
            for ioc in self.iocs[section]:
                self.assertTrue(str(ioc.get("source", "")).strip(), ioc)

    def test_allowlist_entries_are_valid_regex(self):
        import re
        for pattern in self.iocs.get("allowlist", []):
            try:
                re.compile(pattern)
            except re.error as e:
                self.fail(f"битый регэксп allowlist {pattern!r}: {e}")

    def test_documented_pegasus_domains_present(self):
        domains = {str(d["value"]).lower() for d in self.iocs["domains"]}
        self.assertIn("mobilesms.io", domains)
        self.assertIn("sync-services.net", domains)

    def test_meta_scoring_matches_thresholds(self):
        from ghost_lock import config
        meta = self.iocs["_meta"]["scoring"]
        self.assertIn(str(config.THRESHOLDS["suspicious"]), meta["suspicious"])
        self.assertIn(str(config.THRESHOLDS["critical"]), meta["critical"])


class TestStixSections(unittest.TestCase):
    """Секции из STIX-фидов: processes исключена из скана, emails/file_paths работают.

    STIX-feed sections: "processes" excluded from scanning,
    emails/file_paths do work.
    """

    def test_processes_section_is_not_scanned(self):
        """STIX принёс общие имена демонов Apple (roleaccountd и др.) —
        секция processes исключена, иначе шквал ложных срабатываний.

        STIX brought generic Apple daemon names (roleaccountd etc.) —
        the processes section is excluded, otherwise a flood of false positives.
        """
        from ghost_lock.modules import spyware_scan
        iocs = {
            "processes": [{"value": "roleaccountd", "weight": 6, "source": "stix"}],
            "domains": [],
        }
        res = spyware_scan.scan_text(iocs, "roleaccountd exited due to JetsamEvent", "t.txt")
        self.assertEqual(res, [])

    def test_emails_and_file_paths_are_scanned(self):
        from ghost_lock.modules import spyware_scan
        iocs = {
            "emails": [{"value": "ops@evil.net", "weight": 7, "source": "stix"}],
            "file_paths": [{"value": "/private/var/implant.dylib", "weight": 6, "source": "stix"}],
            "domains": [],
        }
        text = 'contact "ops@evil.net" then load /private/var/implant.dylib'
        findings = spyware_scan.scan_text(iocs, text, "t.txt")
        values = {f.value for f in findings}
        self.assertEqual(values, {"ops@evil.net", "/private/var/implant.dylib"})


if __name__ == "__main__":
    unittest.main()
