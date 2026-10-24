"""Тесты глубокого режима: бэкап, шифрование, расшифровка, неполный результат.

Deep-mode tests: backup, encryption, decryption, incomplete result.
"""

import hashlib
import os
import plistlib
import sqlite3
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # noqa: E402
from cryptography.hazmat.primitives.keywrap import aes_key_wrap  # noqa: E402

from ghost_lock.modules import backup_crypto, deep_scan  # noqa: E402
from ghost_lock.modules.spyware_scan import ScanResult, Finding  # noqa: E402

PASSWORD = "correct horse battery"
C2 = "mobilesms.io"


def _tlv(tag: bytes, value) -> bytes:
    raw = value.to_bytes(4, "big") if isinstance(value, int) else value
    return tag + struct.pack(">I", len(raw)) + raw


def _encrypt(key: bytes, data: bytes) -> bytes:
    pad = 16 - len(data) % 16
    data += bytes([pad]) * pad
    enc = Cipher(algorithms.AES(key), modes.CBC(b"\x00" * 16)).encryptor()
    return enc.update(data) + enc.finalize()


def _mbfile(wrapped_key: bytes, size: int) -> bytes:
    archive = {
        "$version": 100000, "$archiver": "NSKeyedArchiver",
        "$top": {"root": plistlib.UID(1)},
        "$objects": ["$null",
                     {"Size": size, "ProtectionClass": 3,
                      "EncryptionKey": plistlib.UID(2), "$class": plistlib.UID(3)},
                     {"NS.data": wrapped_key, "$class": plistlib.UID(4)},
                     {"$classname": "MBFile"}, {"$classname": "NSMutableData"}],
    }
    return plistlib.dumps(archive, fmt=plistlib.FMT_BINARY)


def build_encrypted_backup(root: Path, files: dict[tuple[str, str], bytes]) -> Path:
    """Мини-бэкап в формате iOS 10.2+ с малым числом итераций PBKDF2.

    A tiny iOS 10.2+ format backup with low PBKDF2 iteration counts.
    """
    bdir = root / "UDID"
    bdir.mkdir(parents=True)
    dpsl, salt, dpic, iters = os.urandom(20), os.urandom(20), 10, 10
    pre = hashlib.pbkdf2_hmac("sha256", PASSWORD.encode(), dpsl, dpic, 32)
    pass_key = hashlib.pbkdf2_hmac("sha1", pre, salt, iters, 32)
    class_key = os.urandom(32)

    keybag = (_tlv(b"VERS", 4) + _tlv(b"TYPE", 1) + _tlv(b"UUID", os.urandom(16))
              + _tlv(b"HMCK", os.urandom(40)) + _tlv(b"WRAP", 1) + _tlv(b"SALT", salt)
              + _tlv(b"ITER", iters) + _tlv(b"DPWT", 1) + _tlv(b"DPIC", dpic)
              + _tlv(b"DPSL", dpsl)
              + _tlv(b"UUID", os.urandom(16)) + _tlv(b"CLAS", 3) + _tlv(b"WRAP", 3)
              + _tlv(b"KTYP", 0) + _tlv(b"WPKY", aes_key_wrap(pass_key, class_key)))

    manifest_key = os.urandom(32)
    db_path = root / "plain_manifest.db"
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE Files (fileID TEXT, domain TEXT, relativePath TEXT, flags INT, file BLOB)")
    for i, ((domain, rel), content) in enumerate(files.items()):
        file_id = hashlib.sha1(f"{domain}-{rel}-{i}".encode()).hexdigest()
        fkey = os.urandom(32)
        wrapped = struct.pack("<I", 3) + aes_key_wrap(class_key, fkey)
        (bdir / file_id[:2]).mkdir(exist_ok=True)
        (bdir / file_id[:2] / file_id).write_bytes(_encrypt(fkey, content))
        conn.execute("INSERT INTO Files VALUES (?,?,?,1,?)",
                     (file_id, domain, rel, _mbfile(wrapped, len(content))))
    conn.commit()
    conn.close()
    (bdir / "Manifest.db").write_bytes(_encrypt(manifest_key, db_path.read_bytes()))
    db_path.unlink()

    with open(bdir / "Manifest.plist", "wb") as fh:
        plistlib.dump({"IsEncrypted": True, "BackupKeyBag": keybag,
                       "ManifestKey": struct.pack("<I", 3) + aes_key_wrap(class_key, manifest_key)},
                      fh, fmt=plistlib.FMT_BINARY)
    return bdir


SMS = ("HomeDomain", "Library/SMS/sms.db")
FILES = {SMS: f"hello https://{C2}/x link".encode(),
         ("HomeDomain", "../../escape.txt"): b"nope"}


class TestBackupCrypto(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.bdir = build_encrypted_backup(self.root / "backups", FILES)

    def tearDown(self):
        self.tmp.cleanup()

    def test_find_and_detect_encryption(self):
        manifest = backup_crypto.find_manifest(self.root / "backups")
        self.assertEqual(manifest, self.bdir / "Manifest.plist")
        self.assertTrue(backup_crypto.is_encrypted(manifest))

    def test_decrypt_roundtrip(self):
        out = self.root / "out"
        stats = backup_crypto.decrypt_backup(self.bdir, PASSWORD, out)
        self.assertEqual(stats.failed, 0)
        self.assertEqual((out / "HomeDomain/Library/SMS/sms.db").read_bytes(), FILES[SMS])

    def test_path_traversal_contained(self):
        out = self.root / "out"
        backup_crypto.decrypt_backup(self.bdir, PASSWORD, out)
        self.assertFalse((self.root / "escape.txt").exists())
        self.assertTrue((out / "HomeDomain/escape.txt").exists())

    def test_wrong_password(self):
        with self.assertRaises(backup_crypto.WrongPasswordError):
            backup_crypto.decrypt_backup(self.bdir, "wrong", self.root / "out")


class TestDeepScan(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.backups = Path(self.tmp.name)
        self.patches = [mock.patch.object(deep_scan, "BACKUPS_DIR", self.backups)]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        self.tmp.cleanup()

    def _fake_backup(self, encrypted: bool):
        def _run(udid, dest):
            if encrypted:
                build_encrypted_backup(dest, FILES)
            else:
                (dest / "UDID").mkdir(parents=True)
                with open(dest / "UDID/Manifest.plist", "wb") as fh:
                    plistlib.dump({"IsEncrypted": False}, fh)
                (dest / "UDID/ab").mkdir()
                (dest / "UDID/ab/abcdef").write_text(f"https://{C2}/")
            return True, ""
        return mock.patch.object(deep_scan, "_run_backup", side_effect=_run)

    def test_backup_failure_is_incomplete(self):
        with mock.patch.object(deep_scan, "will_encrypt", return_value=False), \
             mock.patch.object(deep_scan, "_run_backup", return_value=(False, "нет кабеля")):
            res = deep_scan.run("UDID", {"DeviceName": "X"})
        self.assertEqual(res.findings, [])
        self.assertTrue(res.incomplete)
        self.assertIn("не удался", res.stats_note)

    def test_encrypted_without_password_never_clean(self):
        with mock.patch.object(deep_scan, "will_encrypt", return_value=True), \
             mock.patch.object(deep_scan, "_run_backup") as backup:
            res = deep_scan.run("UDID", {}, password_provider=lambda: None)
        backup.assert_not_called()  # не тратим час на бэкап без пароля
        self.assertTrue(res.incomplete)
        self.assertIn("НЕПОЛНЫЙ", res.stats_note)

    def test_encrypted_unknown_upfront_asks_after_backup(self):
        with mock.patch.object(deep_scan, "will_encrypt", return_value=None), \
             self._fake_backup(encrypted=True):
            res = deep_scan.run("UDID", {}, password_provider=lambda: None)
        self.assertTrue(res.incomplete)

    def test_wrong_password_is_incomplete(self):
        with mock.patch.object(deep_scan, "will_encrypt", return_value=True), \
             self._fake_backup(encrypted=True):
            res = deep_scan.run("UDID", {}, password_provider=lambda: "wrong")
        self.assertTrue(res.incomplete)
        self.assertIn("неверный пароль", res.stats_note)

    def test_encrypted_with_password_finds_ioc_and_cleans_up(self):
        with mock.patch.object(deep_scan, "will_encrypt", return_value=True), \
             self._fake_backup(encrypted=True):
            res = deep_scan.run("UDID", {}, password_provider=lambda: PASSWORD)
        self.assertFalse(res.incomplete)
        hits = [f for f in res.findings if f.value == C2]
        self.assertTrue(hits, res.findings)
        self.assertEqual(hits[0].location, "backup:HomeDomain/Library/SMS/sms.db")
        self.assertEqual(list(self.backups.glob(".decrypted-*")), [])

    def test_unencrypted_scanned_directly(self):
        with mock.patch.object(deep_scan, "will_encrypt", return_value=False), \
             self._fake_backup(encrypted=False):
            res = deep_scan.run("UDID", {})
        self.assertFalse(res.incomplete)
        self.assertTrue(any(f.value == C2 for f in res.findings))
        self.assertTrue(all(f.location.startswith("backup:") for f in res.findings))

    def test_success_prefixes_locations(self):
        finding = Finding(ioc_type="domain", value=C2, weight=10,
                          source="t", location="/tmp/x/file.ips", context="...")
        fake = ScanResult(findings=[finding], files_scanned=42)
        with mock.patch.object(deep_scan, "will_encrypt", return_value=False), \
             self._fake_backup(encrypted=False), \
             mock.patch("ghost_lock.modules.spyware_scan.run_scan", return_value=fake):
            res = deep_scan.run("UDID", {})
        self.assertEqual(res.files_scanned, 42)
        self.assertEqual(res.findings[0].location, "backup:/tmp/x/file.ips")

    def test_will_encrypt_parses_output(self):
        proc = mock.Mock(stdout="true\n")
        with mock.patch.object(deep_scan.subprocess, "run", return_value=proc):
            self.assertTrue(deep_scan.will_encrypt("U"))
        proc.stdout = ""
        with mock.patch.object(deep_scan.subprocess, "run", return_value=proc):
            self.assertIsNone(deep_scan.will_encrypt("U"))

    def test_run_backup_is_incremental(self):
        proc = mock.Mock(returncode=0, stdout="", stderr="")
        with mock.patch.object(deep_scan.subprocess, "run", return_value=proc) as run:
            deep_scan._run_backup("U", self.backups / "t")
        self.assertNotIn("--full", run.call_args.args[0])

    def test_run_backup_timeout_handled(self):
        with mock.patch.object(deep_scan.subprocess, "run",
                               side_effect=deep_scan.subprocess.TimeoutExpired(cmd="b", timeout=1)):
            ok, err = deep_scan._run_backup("U", self.backups / "t")
        self.assertFalse(ok)
        self.assertIn("таймаут", err)


def _f(value, loc, source="src", t="domains", w=10):
    return Finding(ioc_type=t, value=value, weight=w, source=f"{source} (строка 1)",
                   location=loc, context="")


class TestBackupNoise(unittest.TestCase):
    def test_own_profile_and_list_files_suppressed(self):
        findings = [
            _f("mobilesms.io", "backup:x/Downloads/web_filter.mobileconfig"),
            _f("mobilesms.io", "backup:x/ConfigurationProfiles/EffectiveUserSettings.plist"),
            _f("nnews.co", "backup:x/WebKit/ContentRuleList-com.apple.WebPrivacy"),
        ]
        kept, sup = deep_scan.filter_backup_noise(findings)
        self.assertEqual(kept, [])
        self.assertEqual(len(sup), 3)

    def test_many_investigations_in_one_file_is_a_list(self):
        loc = "backup:HomeDomain/Library/Safari/Sites.db"
        findings = [_f(d, loc, source=s) for d, s in
                    [("a.net", "Citizen Lab"), ("b.net", "Amnesty"), ("c.net", "Talos")]]
        kept, sup = deep_scan.filter_backup_noise(findings)
        self.assertEqual(kept, [])

    def test_real_infection_trace_kept(self):
        # одна кампания, два домена в sms.db — это как раз след заражения
        # one campaign, two domains in sms.db — exactly an infection trace
        loc = "backup:HomeDomain/Library/SMS/sms.db"
        findings = [_f("mobilesms.io", loc, source="Citizen Lab 2016"),
                    _f("smsx.io", loc, source="Citizen Lab 2016")]
        kept, sup = deep_scan.filter_backup_noise(findings)
        self.assertEqual(len(kept), 2)
        self.assertEqual(sup, [])

    def test_heuristic_words_suppressed_in_backup(self):
        findings = [_f("pegasus", "backup:AppDomain-nytimes/most-read.json", t="spyware_strings", w=4),
                    _f("frida", "backup:x/user-preferences", t="jailbreak_artifacts", w=5),
                    _f("/Applications/Cydia.app", "backup:x/y.plist", t="jailbreak_artifacts", w=8)]
        kept, sup = deep_scan.filter_backup_noise(findings)
        self.assertEqual([f.value for f in kept], ["/Applications/Cydia.app"])


if __name__ == "__main__":
    unittest.main()
