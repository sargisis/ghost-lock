"""Расшифровка зашифрованного бэкапа iOS (формат iOS 10.2+).

Зачем: профиль hardened включает forceEncryptedBackup, и после этого
idevicebackup2 пишет только шифротекст. Скан шифротекста ничего не найдёт —
и выдаст ложное «чисто». Здесь мы честно расшифровываем бэкап паролем
пользователя во временную папку, чтобы сканер видел реальные данные.

Схема (та же, что в MVT / iphone_backup_decrypt):
  1. Manifest.plist → BackupKeyBag (TLV) и ManifestKey.
  2. Ключ пароля: PBKDF2-SHA256(пароль, DPSL, DPIC) → PBKDF2-SHA1(…, SALT, ITER).
  3. Ключом пароля разворачиваем (AES Key Wrap, RFC 3394) ключи классов защиты.
  4. Ключом класса разворачиваем ManifestKey → расшифровываем Manifest.db.
  5. Для каждого файла из Manifest.db: свой ключ (EncryptionKey), AES-256-CBC.

Decrypting an encrypted iOS backup (iOS 10.2+ format).

Why: the hardened profile turns on forceEncryptedBackup, after which
idevicebackup2 writes ciphertext only. Scanning ciphertext finds nothing —
and yields a false "clean". Here we decrypt the backup with the user's
password into a temporary folder so the scanner sees the real data.

Scheme (same as MVT / iphone_backup_decrypt):
  1. Manifest.plist → BackupKeyBag (TLV) and ManifestKey.
  2. Password key: PBKDF2-SHA256(password, DPSL, DPIC) → PBKDF2-SHA1(…, SALT, ITER).
  3. The password key unwraps (AES Key Wrap, RFC 3394) the protection-class keys.
  4. A class key unwraps ManifestKey → decrypts Manifest.db.
  5. Every file in Manifest.db has its own key (EncryptionKey), AES-256-CBC.
"""

from __future__ import annotations

import hashlib
import plistlib
import sqlite3
import struct
import tempfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

# Сканер всё равно пропускает файлы крупнее — нет смысла их расшифровывать
# The scanner skips larger files anyway — no point decrypting them
DECRYPT_MAX_BYTES = 8 << 20

WRAP_PASSCODE = 2
_KEYBAG_TOP_TAGS = {b"VERS", b"TYPE", b"UUID", b"HMCK", b"WRAP",
                    b"SALT", b"ITER", b"DPWT", b"DPIC", b"DPSL"}


class BackupCryptoError(RuntimeError):
    pass


class WrongPasswordError(BackupCryptoError):
    pass


def _crypto():
    """Ленивый импорт: cryptography нужна только для зашифрованных бэкапов.

    Lazy import: cryptography is only needed for encrypted backups.
    """
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.keywrap import InvalidUnwrap, aes_key_unwrap
    except ImportError:
        raise BackupCryptoError(
            "для зашифрованного бэкапа нужен пакет cryptography: pip install cryptography"
        ) from None
    return Cipher, algorithms, modes, aes_key_unwrap, InvalidUnwrap


def find_manifest(backup_root: Path) -> Path | None:
    """idevicebackup2 кладёт бэкап в <dest>/<UDID>/ — ищем Manifest.plist.

    idevicebackup2 puts the backup in <dest>/<UDID>/ — locate Manifest.plist.
    """
    direct = backup_root / "Manifest.plist"
    if direct.is_file():
        return direct
    found = sorted(backup_root.glob("*/Manifest.plist"))
    return found[0] if found else None


def is_encrypted(manifest_plist: Path) -> bool:
    with open(manifest_plist, "rb") as fh:
        return bool(plistlib.load(fh).get("IsEncrypted", False))


@dataclass
class Keybag:
    attrs: dict[bytes, bytes | int] = field(default_factory=dict)
    class_keys: dict[int, dict[bytes, bytes | int]] = field(default_factory=dict)

    @classmethod
    def parse(cls, blob: bytes) -> "Keybag":
        kb = cls()
        current: dict[bytes, bytes | int] = {}
        pos = 0
        while pos + 8 <= len(blob):
            tag = blob[pos:pos + 4]
            length = struct.unpack(">I", blob[pos + 4:pos + 8])[0]
            raw = blob[pos + 8:pos + 8 + length]
            pos += 8 + length
            value: bytes | int = int.from_bytes(raw, "big") if length == 4 else raw
            if tag == b"UUID" and b"UUID" in kb.attrs:
                # каждый следующий UUID открывает новый ключ класса
                # every subsequent UUID starts a new class key
                if b"CLAS" in current:
                    kb.class_keys[int(current[b"CLAS"])] = current
                current = {b"UUID": value}
            elif tag in _KEYBAG_TOP_TAGS and not current:
                kb.attrs[tag] = value
            else:
                current[tag] = value
        if b"CLAS" in current:
            kb.class_keys[int(current[b"CLAS"])] = current
        return kb

    def unlock(self, password: str) -> dict[int, bytes]:
        _, _, _, unwrap, invalid = _crypto()
        try:
            dpsl, dpic = self.attrs[b"DPSL"], self.attrs[b"DPIC"]
            salt, iters = self.attrs[b"SALT"], self.attrs[b"ITER"]
        except KeyError as e:
            raise BackupCryptoError(f"keybag без поля {e.args[0]!r} (бэкап старше iOS 10.2?)") from None
        pre = hashlib.pbkdf2_hmac("sha256", password.encode(), dpsl, int(dpic), 32)
        pass_key = hashlib.pbkdf2_hmac("sha1", pre, salt, int(iters), 32)

        keys: dict[int, bytes] = {}
        for clas, ck in self.class_keys.items():
            if not int(ck.get(b"WRAP", 0)) & WRAP_PASSCODE or b"WPKY" not in ck:
                continue
            try:
                keys[clas] = unwrap(pass_key, ck[b"WPKY"])
            except invalid:
                raise WrongPasswordError("неверный пароль бэкапа") from None
        if not keys:
            raise BackupCryptoError("в keybag нет ключей, защищённых паролем")
        return keys


def _aes_cbc_decrypt(key: bytes, data: bytes) -> bytes:
    cipher_cls, algorithms, modes, _, _ = _crypto()
    usable = len(data) - len(data) % 16
    dec = cipher_cls(algorithms.AES(key), modes.CBC(b"\x00" * 16)).decryptor()
    return dec.update(data[:usable]) + dec.finalize()


def _unpad(data: bytes) -> bytes:
    """Снимает PKCS7, только если паддинг корректен. / Strips PKCS7 only if valid."""
    if not data:
        return data
    n = data[-1]
    if 1 <= n <= 16 and data[-n:] == bytes([n]) * n:
        return data[:-n]
    return data


def _unwrap_with_class(class_keys: dict[int, bytes], blob: bytes) -> bytes:
    _, _, _, unwrap, invalid = _crypto()
    clas = struct.unpack("<I", blob[:4])[0]
    if clas not in class_keys:
        raise BackupCryptoError(f"нет ключа для класса защиты {clas}")
    try:
        return unwrap(class_keys[clas], blob[4:])
    except invalid:
        raise BackupCryptoError(f"не удалось развернуть ключ класса {clas}") from None


def _file_meta(blob: bytes) -> tuple[bytes | None, int | None]:
    """Из NSKeyedArchiver-плиста MBFile достаёт (EncryptionKey, Size).

    Extracts (EncryptionKey, Size) from the MBFile NSKeyedArchiver plist.
    """
    try:
        archive = plistlib.loads(blob)
        objects = archive["$objects"]
        root = objects[archive["$top"]["root"].data]
    except (plistlib.InvalidFileException, KeyError, IndexError, AttributeError, TypeError, ValueError):
        return None, None
    size = root.get("Size")
    ref = root.get("EncryptionKey")
    if not isinstance(ref, plistlib.UID):
        return None, size
    key_obj = objects[ref.data]
    data = key_obj.get("NS.data") if isinstance(key_obj, dict) else key_obj
    return (data if isinstance(data, bytes) else None), size


def _safe_rel(domain: str, rel: str) -> Path | None:
    """Путь вида <domain>/<relativePath> без выхода за пределы папки.

    A <domain>/<relativePath> path that cannot escape the output folder.
    """
    parts = [p for p in PurePosixPath(domain or "unknown", rel or "").parts
             if p not in ("", ".", "..", "/")]
    return Path(*parts) if parts else None


@dataclass
class DecryptStats:
    decrypted: int = 0
    skipped_large: int = 0
    failed: int = 0


def decrypt_backup(backup_dir: Path, password: str, out_dir: Path) -> DecryptStats:
    """Расшифровывает бэкап в out_dir с настоящими путями <domain>/<path>.

    Decrypts the backup into out_dir using real <domain>/<path> paths.
    """
    with open(backup_dir / "Manifest.plist", "rb") as fh:
        manifest = plistlib.load(fh)
    if not manifest.get("IsEncrypted"):
        raise BackupCryptoError("бэкап не зашифрован")
    keybag = Keybag.parse(manifest["BackupKeyBag"])
    class_keys = keybag.unlock(password)

    manifest_key = _unwrap_with_class(class_keys, manifest["ManifestKey"])
    db_plain = _unpad(_aes_cbc_decrypt(manifest_key, (backup_dir / "Manifest.db").read_bytes()))
    if not db_plain.startswith(b"SQLite format 3"):
        raise BackupCryptoError("Manifest.db не расшифровался (повреждён бэкап?)")

    stats = DecryptStats()
    out_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=out_dir, suffix=".db") as tmp_db:
        tmp_db.write(db_plain)
        tmp_db.flush()
        conn = sqlite3.connect(f"file:{tmp_db.name}?mode=ro", uri=True)
        try:
            rows = conn.execute(
                "SELECT fileID, domain, relativePath, file FROM Files WHERE flags = 1"
            ).fetchall()
        finally:
            conn.close()

    for file_id, domain, rel, meta in rows:
        src = backup_dir / file_id[:2] / file_id
        dest_rel = _safe_rel(domain, rel)
        if dest_rel is None or not src.is_file():
            continue
        enc_key, size = _file_meta(meta or b"")
        if src.stat().st_size > DECRYPT_MAX_BYTES:
            stats.skipped_large += 1
            continue
        try:
            data = src.read_bytes()
            if enc_key:
                key = _unwrap_with_class(class_keys, enc_key)
                data = _unpad(_aes_cbc_decrypt(key, data))
                if isinstance(size, int) and 0 <= size <= len(data):
                    data = data[:size]
            dest = out_dir / dest_rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
            stats.decrypted += 1
        except (BackupCryptoError, OSError):
            stats.failed += 1
    return stats
