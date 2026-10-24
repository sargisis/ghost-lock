"""Тесты сетевой статистики: точное совпадение имён, пути, двойники Apple, сироты.

Network statistics tests: exact name match, paths, Apple lookalikes, orphans.
"""

import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ghost_lock.modules import netusage  # noqa: E402

IOCS = {
    "processes": [{"value": "bh", "weight": 9, "source": "nso"},
                  {"value": "roleaccountd", "weight": 9, "source": "nso"}],
    "file_paths": [{"value": "/private/var/tmp/takephoto", "weight": 6, "source": "cytrox"}],
}


class TestNetUsage(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def make_db(self, procs, live=()):
        d = self.root / "WirelessDomain/Library/Databases"
        d.mkdir(parents=True, exist_ok=True)
        con = sqlite3.connect(d / "DataUsage.sqlite")
        con.execute("CREATE TABLE ZPROCESS (Z_PK INTEGER PRIMARY KEY, ZFIRSTTIMESTAMP REAL,"
                    " ZTIMESTAMP REAL, ZBUNDLENAME TEXT, ZEXTENSIONNAME TEXT, ZPROCNAME TEXT)")
        con.execute("CREATE TABLE ZLIVEUSAGE (Z_PK INTEGER PRIMARY KEY, ZHASPROCESS INTEGER)")
        for pk, name, bundle in procs:
            con.execute("INSERT INTO ZPROCESS VALUES (?, 7.5e8, 7.6e8, ?, NULL, ?)", (pk, bundle, name))
        for pk, ref in live:
            con.execute("INSERT INTO ZLIVEUSAGE VALUES (?, ?)", (pk, ref))
        con.commit()
        con.close()

    def test_clean(self):
        self.make_db([(1, "mDNSResponder", "com.apple.mDNSResponder"), (2, "bhfoo", None)])
        rep = netusage.audit(self.root, IOCS)
        self.assertEqual(rep.findings, [])
        self.assertEqual(rep.processes, 2)
        self.assertTrue(rep.lines[0][0])

    def test_exact_match_only(self):
        self.make_db([(1, "bh", None), (2, "abhx", None)])
        rep = netusage.audit(self.root, IOCS)
        self.assertEqual([(f.value, f.weight) for f in rep.findings], [("bh", 9)])
        self.assertIn("2024-10-07 … 2025-01-31", rep.findings[0].context)

    def test_path_basename_and_file_paths(self):
        self.make_db([(1, "/private/var/tmp/takephoto", None)])
        rep = netusage.audit(self.root, IOCS)
        self.assertEqual({f.ioc_type for f in rep.findings}, {"file_paths"})

    def test_apple_lookalike_low_weight(self):
        self.make_db([(1, "roleaccountd", None)])
        rep = netusage.audit(self.root, IOCS)
        self.assertEqual(rep.findings[0].weight, netusage.LOOKALIKE_WEIGHT)
        self.assertIn("проверь вручную", rep.findings[0].source)

    def test_orphans_counted_not_scored(self):
        self.make_db([(1, "safari", None)], live=[(1, 1), (2, 5), (3, None)])
        rep = netusage.audit(self.root, IOCS)
        self.assertEqual(rep.orphans, 1)
        self.assertEqual(rep.findings, [])

    def test_no_database(self):
        rep = netusage.audit(self.root, IOCS)
        self.assertEqual(rep.databases, 0)


if __name__ == "__main__":
    unittest.main()
