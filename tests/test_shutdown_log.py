"""Тесты анализа shutdown.log: разбор, подозрительные пути, IOC, архив.

shutdown.log analysis tests: parsing, suspicious paths, IOCs, archive.
"""

import io
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ghost_lock.modules import shutdown_log  # noqa: E402

CLEAN = """SIGTERM: [1729000000]
remaining client pid: 41 (/usr/libexec/backboardd)
After 0.21s, these clients are still here:
\tremaining client pid: 88 (/System/Library/PrivateFrameworks/X.framework/Support/xd)
SIGTERM: [1729500000]
remaining client pid: 41 (/usr/libexec/backboardd)
"""
INFECTED = CLEAN + """SIGTERM: [1729900000]
remaining client pid: 913 (/private/var/db/com.apple.xpc.roleaccountd.staging/rolexd)
remaining client pid: 914 (/private/var/tmp/takephoto)
"""
IOCS = {"processes": [{"value": "rolexd", "weight": 9, "source": "2021-07-18_nso"}],
        "file_paths": [{"value": "/private/var/tmp/takephoto", "weight": 6, "source": "cytrox"}]}


def make_archive(dirpath: Path, log: str | None, name="sysdiagnose_2026.10.24_18-30-00+0400_iPhone-OS_iPhone_24B115.tar.gz"):
    path = dirpath / name
    with tarfile.open(path, "w:gz") as tar:
        if log is not None:
            data = log.encode()
            info = tarfile.TarInfo(name.replace(".tar.gz", "") + "/system_logs.logarchive/Extra/shutdown.log")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        other = b"noise"
        info = tarfile.TarInfo("x/other.txt")
        info.size = len(other)
        tar.addfile(info, io.BytesIO(other))
    return path


class TestParse(unittest.TestCase):
    def test_reboots_and_clients(self):
        reboots = shutdown_log.parse(CLEAN)
        self.assertEqual(len(reboots), 2)
        self.assertEqual(reboots[0].timestamp, 1729000000)
        self.assertIn((88, "/System/Library/PrivateFrameworks/X.framework/Support/xd"), reboots[0].clients)


class TestAnalyze(unittest.TestCase):
    def test_clean(self):
        rep = shutdown_log.analyze(shutdown_log.parse(CLEAN), IOCS)
        self.assertEqual(rep.findings, [])
        self.assertTrue(rep.lines[0][0])
        self.assertEqual(rep.reboots, 2)

    def test_pegasus_like(self):
        rep = shutdown_log.analyze(shutdown_log.parse(INFECTED), IOCS)
        kinds = {(f.ioc_type, f.value) for f in rep.findings}
        self.assertIn(("shutdown_path", "/private/var/db/com.apple.xpc.roleaccountd.staging/rolexd"), kinds)
        self.assertIn(("process", "/private/var/db/com.apple.xpc.roleaccountd.staging/rolexd"), kinds)
        self.assertIn(("file_paths", "/private/var/tmp/takephoto"), kinds)
        self.assertGreaterEqual(sum(f.weight for f in rep.findings), 15)  # critical
        self.assertFalse(rep.lines[0][0])

    def test_one_finding_per_path_across_reboots(self):
        log = INFECTED + "SIGTERM: [1730000000]\nremaining client pid: 5 (/private/var/tmp/takephoto)\n"
        rep = shutdown_log.analyze(shutdown_log.parse(log), IOCS)
        hits = [f for f in rep.findings if f.ioc_type == "shutdown_path" and f.value.endswith("takephoto")]
        self.assertEqual(len(hits), 1)
        self.assertIn("2 раз", hits[0].context)


class TestArchive(unittest.TestCase):
    def test_reads_only_shutdown_log_in_memory(self):
        with tempfile.TemporaryDirectory() as d:
            make_archive(Path(d), INFECTED)
            rep = shutdown_log.audit_dir(Path(d), IOCS)
            self.assertTrue(rep.findings)
            self.assertEqual(sorted(p.name for p in Path(d).iterdir())[0][:11], "sysdiagnose")
            self.assertEqual(len(list(Path(d).iterdir())), 1)  # ничего не распаковано

    def test_no_archive(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertIsNone(shutdown_log.audit_dir(Path(d), IOCS))

    def test_archive_without_log(self):
        with tempfile.TemporaryDirectory() as d:
            make_archive(Path(d), None)
            rep = shutdown_log.audit_dir(Path(d), IOCS)
            self.assertIn("не найден", rep.lines[0][1])

    def test_corrupt_archive(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, "sysdiagnose_bad.tar.gz").write_bytes(b"not a tar")
            rep = shutdown_log.audit_dir(Path(d), IOCS)
            self.assertIsNotNone(rep)


if __name__ == "__main__":
    unittest.main()
