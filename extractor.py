"""
WeChat Message Extractor - Core extraction logic.

Handles WeChat detection, database decryption, contact loading,
chat listing, and message export to TXT format.

Supports both classic WeChat.exe (3.x) and newer Weixin.exe (4.x+).
WeChat 3.x uses SQLCipher 3 (HMAC-SHA1, 64k iters, reserve=48).
WeChat 4.x uses SQLCipher 4 (HMAC-SHA512, 256k iters, reserve=80, per-DB keys).
"""

import os
import sys
import glob
import sqlite3
import shutil
import struct
import tempfile
import ctypes
import ctypes.wintypes as wintypes
import atexit
import re
import subprocess
import hashlib
import hmac as hmac_mod
import zlib
import winreg
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Callable

try:
    import zstandard as zstd
except ImportError:
    zstd = None

try:
    from Cryptodome.Cipher import AES
except ImportError:
    from Crypto.Cipher import AES


def is_admin() -> bool:
    """Check if the current process has administrator privileges."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


# Message type constants
MSG_TYPE_TEXT = 1
MSG_TYPE_IMAGE = 3
MSG_TYPE_VOICE = 34
MSG_TYPE_CONTACT_CARD = 42
MSG_TYPE_VIDEO = 43
MSG_TYPE_STICKER = 47
MSG_TYPE_LOCATION = 48
MSG_TYPE_APP = 49
MSG_TYPE_VOIP = 50
MSG_TYPE_SYSTEM = 10000
MSG_TYPE_RECALLED = 10002

MSG_TYPE_LABELS = {
    MSG_TYPE_IMAGE: "[Image]",
    MSG_TYPE_VOICE: "[Voice Message]",
    MSG_TYPE_CONTACT_CARD: "[Contact Card]",
    MSG_TYPE_VIDEO: "[Video]",
    MSG_TYPE_STICKER: "[Sticker]",
    MSG_TYPE_LOCATION: "[Location]",
    MSG_TYPE_VOIP: "[Voice/Video Call]",
    MSG_TYPE_SYSTEM: "[System Message]",
    MSG_TYPE_RECALLED: "[Message Recalled]",
}

# Types excluded from text export (non-text content)
EXCLUDE_TYPES = {
    MSG_TYPE_IMAGE, MSG_TYPE_VOICE, MSG_TYPE_CONTACT_CARD,
    MSG_TYPE_VIDEO, MSG_TYPE_STICKER, MSG_TYPE_LOCATION,
    MSG_TYPE_VOIP, MSG_TYPE_SYSTEM, MSG_TYPE_RECALLED,
}

# Formatted content prefixes to skip (app messages that aren't plain text replies)
_SKIP_PREFIXES = ("[App Message]", "[Link] ", "[Sticker]", "[Type ")

# System accounts to exclude from chat list
SYSTEM_ACCOUNTS = {
    "weixin", "fmessage", "medianote", "floatbottle",
    "newsapp", "blogapp", "qqmail", "tmessage",
    "qmessage", "qqsynchronous", "qqsafe", "pluginmessage",
    "officialaccounts", "notification_messages", "mphelper",
}

# SQLCipher constants
SQLITE_FILE_HEADER = b"SQLite format 3\x00"
KEY_SIZE = 32
SALT_SIZE = 16
PAGE_SIZE = 4096

# SQLCipher 3 (WeChat 3.x): HMAC-SHA1, 64k iters, reserve=48
SC3_ITERATIONS = 64000
SC3_RESERVE = 48  # IV(16) + HMAC_SHA1(20) + pad(12)

# SQLCipher 4 (WeChat 4.x): HMAC-SHA512, 256k iters, reserve=80
SC4_ITERATIONS = 256000
SC4_RESERVE = 80  # IV(16) + HMAC_SHA512(64)
SC4_IV_SIZE = 16
SC4_HMAC_SIZE = 64


# ── SQLCipher 4 crypto (WeChat 4.0) ────────────────────────────────────────

def _sc4_verify_key(enc_key: bytes, db_page1: bytes) -> bool:
    """Verify a 32-byte enc_key against page 1 of a SQLCipher 4 database."""
    if len(db_page1) < PAGE_SIZE:
        return False
    salt = db_page1[:SALT_SIZE]
    mac_salt = bytes(b ^ 0x3a for b in salt)
    mac_key = hashlib.pbkdf2_hmac("sha512", enc_key, mac_salt, 2, dklen=KEY_SIZE)
    hmac_data = db_page1[SALT_SIZE:PAGE_SIZE - SC4_RESERVE + SC4_IV_SIZE]
    stored_hmac = db_page1[PAGE_SIZE - SC4_HMAC_SIZE:PAGE_SIZE]
    h = hmac_mod.new(mac_key, hmac_data, hashlib.sha512)
    h.update(struct.pack('<I', 1))
    return h.digest() == stored_hmac


def _sc4_decrypt_page(enc_key: bytes, page_data: bytes, pgno: int) -> bytes:
    """Decrypt a single SQLCipher 4 page."""
    iv = page_data[PAGE_SIZE - SC4_RESERVE:PAGE_SIZE - SC4_RESERVE + SC4_IV_SIZE]
    if pgno == 1:
        encrypted = page_data[SALT_SIZE:PAGE_SIZE - SC4_RESERVE]
        cipher = AES.new(enc_key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted)
        return bytes(SQLITE_FILE_HEADER + decrypted + b'\x00' * SC4_RESERVE)
    else:
        encrypted = page_data[:PAGE_SIZE - SC4_RESERVE]
        cipher = AES.new(enc_key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted)
        return decrypted + b'\x00' * SC4_RESERVE


def _sc4_decrypt_file(enc_key: bytes, db_path: str, out_path: str) -> bool:
    """Decrypt a SQLCipher 4 database file. Returns True on success."""
    try:
        file_size = os.path.getsize(db_path)
        if file_size < PAGE_SIZE:
            return False
        with open(db_path, "rb") as f:
            page1 = f.read(PAGE_SIZE)
        if not _sc4_verify_key(enc_key, page1):
            return False
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        total_pages = (file_size + PAGE_SIZE - 1) // PAGE_SIZE
        with open(db_path, "rb") as fin, open(out_path, "wb") as fout:
            for pgno in range(1, total_pages + 1):
                page = fin.read(PAGE_SIZE)
                if len(page) < PAGE_SIZE:
                    if page:
                        page += b'\x00' * (PAGE_SIZE - len(page))
                    else:
                        break
                fout.write(_sc4_decrypt_page(enc_key, page, pgno))
        return True
    except Exception:
        return False


# ── SQLCipher 3 crypto (WeChat 3.x) ────────────────────────────────────────

def _sc3_verify_key(key_bytes: bytes, db_path: str) -> bool:
    """Verify a 32-byte key against a SQLCipher 3 encrypted database."""
    if not os.path.isfile(db_path):
        return False
    try:
        with open(db_path, "rb") as f:
            header = f.read(PAGE_SIZE)
        if len(header) < PAGE_SIZE:
            return False
        salt = header[:SALT_SIZE]
        mac_salt = bytes([(b ^ 58) for b in salt])
        byteHmac = hashlib.pbkdf2_hmac("sha1", key_bytes, salt, SC3_ITERATIONS, KEY_SIZE)
        mac_key = hashlib.pbkdf2_hmac("sha1", byteHmac, mac_salt, 2, KEY_SIZE)
        hash_mac = hmac_mod.new(mac_key, header[16:4064], hashlib.sha1)
        hash_mac.update(b'\x01\x00\x00\x00')
        return hash_mac.digest() == header[4064:4084]
    except Exception:
        return False


def _sc3_decrypt_file(key_hex: str, db_path: str, out_path: str) -> bool:
    """Decrypt a SQLCipher 3 database file. Returns True on success."""
    password = bytes.fromhex(key_hex)
    try:
        with open(db_path, "rb") as f:
            blist = f.read()
    except Exception:
        return False
    if len(blist) < PAGE_SIZE:
        return False
    salt = blist[:16]
    mac_salt = bytes([(b ^ 58) for b in salt])
    byteHmac = hashlib.pbkdf2_hmac("sha1", password, salt, SC3_ITERATIONS, KEY_SIZE)
    mac_key = hashlib.pbkdf2_hmac("sha1", byteHmac, mac_salt, 2, KEY_SIZE)
    hash_mac = hmac_mod.new(mac_key, blist[16:4064], hashlib.sha1)
    hash_mac.update(b'\x01\x00\x00\x00')
    if hash_mac.digest() != blist[4064:4084]:
        return False
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    try:
        with open(out_path, "wb") as f:
            f.write(SQLITE_FILE_HEADER)
            for i in range(0, len(blist), PAGE_SIZE):
                page = blist[i:i + PAGE_SIZE] if i > 0 else blist[16:i + PAGE_SIZE]
                if len(page) < SC3_RESERVE:
                    break
                f.write(AES.new(byteHmac, AES.MODE_CBC, page[-48:-32]).decrypt(page[:-48]))
                f.write(page[-48:])
    except Exception:
        return False
    return True


# ── Windows process memory helpers ──────────────────────────────────────────

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

_kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_uint64),
        ("AllocationBase", ctypes.c_uint64),
        ("AllocationProtect", wintypes.DWORD),
        ("_pad1", wintypes.DWORD),
        ("RegionSize", ctypes.c_uint64),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
        ("_pad2", wintypes.DWORD),
    ]


def _open_process(pid: int):
    handle = _kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not handle:
        return None
    return handle


def _close_handle(handle):
    _kernel32.CloseHandle(handle)


def _read_process_memory(handle, address: int, size: int) -> Optional[bytes]:
    buf = ctypes.create_string_buffer(size)
    bytes_read = ctypes.c_size_t(0)
    ok = _kernel32.ReadProcessMemory(handle, ctypes.c_uint64(address), buf, size, ctypes.byref(bytes_read))
    if not ok or bytes_read.value == 0:
        return None
    return bytes(buf)[:bytes_read.value]


def _enum_regions(handle):
    """Return list of (base, size) for readable committed memory regions."""
    MEM_COMMIT = 0x1000
    READABLE = {0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80}
    regions = []
    addr = 0
    mbi = MEMORY_BASIC_INFORMATION()
    mbi_size = ctypes.sizeof(mbi)
    while addr < 0x7FFFFFFFFFFF:
        ret = _kernel32.VirtualQueryEx(handle, ctypes.c_uint64(addr), ctypes.byref(mbi), mbi_size)
        if ret == 0:
            break
        if mbi.State == MEM_COMMIT and mbi.Protect in READABLE and 0 < mbi.RegionSize < 500 * 1024 * 1024:
            regions.append((mbi.BaseAddress, mbi.RegionSize))
        nxt = mbi.BaseAddress + mbi.RegionSize
        if nxt <= addr:
            break
        addr = nxt
    return regions


# ── Data directory discovery ────────────────────────────────────────────────

def _find_wechat_data_dir() -> Optional[str]:
    """Find the WeChat/xwechat data directory from config and well-known paths.

    For WeChat 4.x (xwechat), the data is typically at:
        Documents\\xwechat_files\\<wxid>\\db_storage
    """
    user_profile = os.environ.get("USERPROFILE", "")

    # Try xwechat config files first (WeChat 4.x)
    appdata = os.environ.get("APPDATA", "")
    for config_dir_name in ["xwechat", "Weixin"]:
        config_dir = os.path.join(appdata, "Tencent", config_dir_name, "config")
        if os.path.isdir(config_dir):
            for ini_file in glob.glob(os.path.join(config_dir, "*.ini")):
                try:
                    content = None
                    for enc in ("utf-8", "gbk"):
                        try:
                            with open(ini_file, "r", encoding=enc) as f:
                                content = f.read(1024).strip()
                            break
                        except UnicodeDecodeError:
                            continue
                    if not content or any(c in content for c in "\n\r\x00"):
                        continue
                    if content == "MyDocument:":
                        content = os.path.join(
                            user_profile, "Documents"
                        )
                    if os.path.isdir(content):
                        # Search for xwechat_files under this path
                        for subdir in ["xwechat_files", "WeChat Files", "Weixin Files"]:
                            candidate = os.path.join(content, subdir)
                            if os.path.isdir(candidate):
                                return candidate
                        # Maybe the ini points directly
                        return content
                except OSError:
                    continue

    # Try classic WeChat registry key
    for reg_path in [r"Software\Tencent\WeChat", r"Software\Tencent\Weixin"]:
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path, 0, winreg.KEY_READ)
            value, _ = winreg.QueryValueEx(key, "FileSavePath")
            winreg.CloseKey(key)
            if value and os.path.isdir(value):
                return value
        except Exception:
            pass

    # Classic WeChat config
    for config_name in ["3ebffe94.ini"]:
        config_path = os.path.join(
            appdata, "Tencent", "WeChat", "All Users", "config", config_name
        )
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                w_dir = f.read().strip()
            if w_dir and w_dir != "MyDocument:" and os.path.isdir(w_dir):
                return w_dir
        except Exception:
            pass

    # Default: check Documents for known directory names
    docs_path = os.path.join(user_profile, "Documents")
    try:
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
        )
        raw_docs = winreg.QueryValueEx(key, "Personal")[0]
        winreg.CloseKey(key)
        parts = os.path.split(raw_docs)
        if "%" in parts[0]:
            docs_path = os.path.join(
                os.environ.get(parts[0].replace("%", ""), ""),
                *parts[1:]
            )
        else:
            docs_path = raw_docs
    except Exception:
        pass

    for subdir in ["xwechat_files", "WeChat Files", "Weixin Files"]:
        candidate = os.path.join(docs_path, subdir)
        if os.path.isdir(candidate):
            return candidate

    return None


def _find_wxid_dirs(base_dir: str) -> List[Tuple[str, str]]:
    """Return list of (wxid, full_path) for wxid sub-directories."""
    if not base_dir or not os.path.isdir(base_dir):
        return []
    skip = {"All Users", "Applet", "WMPF", "all_users", "Backup"}
    results = []
    for name in os.listdir(base_dir):
        if name in skip:
            continue
        full = os.path.join(base_dir, name)
        if os.path.isdir(full):
            results.append((name, full))
    return results


def _find_db_storage(wxid_path: str) -> Optional[str]:
    """Find the db_storage directory for a wxid path (WeChat 4.x)."""
    ds = os.path.join(wxid_path, "db_storage")
    if os.path.isdir(ds):
        return ds
    return None


def _collect_encrypted_dbs(db_dir: str) -> List[Tuple[str, str, bytes]]:
    """Collect all encrypted .db files under db_dir.

    Returns list of (rel_path, full_path, page1_bytes).
    """
    results = []
    for root, _dirs, files in os.walk(db_dir):
        for f in files:
            if f.endswith(".db") and not f.endswith(("-wal", "-shm")):
                full = os.path.join(root, f)
                try:
                    sz = os.path.getsize(full)
                    if sz < PAGE_SIZE:
                        continue
                    with open(full, "rb") as fh:
                        page1 = fh.read(PAGE_SIZE)
                    if page1[:16] == SQLITE_FILE_HEADER:
                        continue  # Already decrypted
                    rel = os.path.relpath(full, db_dir)
                    results.append((rel, full, page1))
                except Exception:
                    continue
    return results


def _extract_v4_keys_from_process(
    pid: int,
    db_files: List[Tuple[str, str, bytes]],
    progress_callback: Optional[Callable[[str], None]] = None,
) -> Dict[str, str]:
    """Extract per-database SQLCipher 4 keys from Weixin.exe process memory.

    Scans for the WCDB cached key pattern: x'<64hex_enc_key><32hex_salt>'
    then matches against each database's salt and verifies via HMAC.

    Returns dict of {salt_hex: enc_key_hex} for matched databases.
    """
    handle = _open_process(pid)
    if not handle:
        return {}

    # Build salt -> db_files mapping
    salt_to_dbs: Dict[str, List[Tuple[str, str, bytes]]] = {}
    for rel, path, page1 in db_files:
        salt_hex = page1[:SALT_SIZE].hex()
        salt_to_dbs.setdefault(salt_hex, []).append((rel, path, page1))

    remaining_salts = set(salt_to_dbs.keys())
    key_map: Dict[str, str] = {}  # salt_hex -> enc_key_hex
    hex_re = re.compile(b"x'([0-9a-fA-F]{64,192})'")

    if progress_callback:
        progress_callback(f"Scanning PID {pid} for {len(remaining_salts)} database keys...")

    try:
        regions = _enum_regions(handle)
        total_regions = len(regions)

        for reg_idx, (base, size) in enumerate(regions):
            if not remaining_salts:
                break
            data = _read_process_memory(handle, base, size)
            if not data:
                continue

            for m in hex_re.finditer(data):
                hex_str = m.group(1).decode()
                hex_len = len(hex_str)

                # Pattern: x'<64hex_enc_key><32hex_salt>'  (96 chars)
                if hex_len == 96:
                    enc_key_hex = hex_str[:64]
                    salt_hex = hex_str[64:]
                    if salt_hex in remaining_salts:
                        enc_key = bytes.fromhex(enc_key_hex)
                        for rel, path, page1 in salt_to_dbs[salt_hex]:
                            if _sc4_verify_key(enc_key, page1):
                                key_map[salt_hex] = enc_key_hex
                                remaining_salts.discard(salt_hex)
                                break

                # Pattern: x'<64hex_enc_key>'  (standalone key)
                elif hex_len == 64:
                    if not remaining_salts:
                        continue
                    enc_key_hex = hex_str
                    enc_key = bytes.fromhex(enc_key_hex)
                    for salt_hex in list(remaining_salts):
                        for rel, path, page1 in salt_to_dbs[salt_hex]:
                            if _sc4_verify_key(enc_key, page1):
                                key_map[salt_hex] = enc_key_hex
                                remaining_salts.discard(salt_hex)
                                break
                        if salt_hex not in remaining_salts:
                            break

                # Pattern: x'<64hex_enc_key><middle_stuff><32hex_salt>'  (>96 chars)
                elif hex_len > 96 and hex_len % 2 == 0:
                    enc_key_hex = hex_str[:64]
                    salt_hex = hex_str[-32:]
                    if salt_hex in remaining_salts:
                        enc_key = bytes.fromhex(enc_key_hex)
                        for rel, path, page1 in salt_to_dbs[salt_hex]:
                            if _sc4_verify_key(enc_key, page1):
                                key_map[salt_hex] = enc_key_hex
                                remaining_salts.discard(salt_hex)
                                break

            if progress_callback and (reg_idx + 1) % 200 == 0:
                progress_callback(
                    f"Scanning memory: {reg_idx + 1}/{total_regions} regions, "
                    f"{len(key_map)}/{len(salt_to_dbs)} keys found..."
                )
    finally:
        _close_handle(handle)

    # Cross-validate: try known keys against remaining databases
    if remaining_salts and key_map:
        for salt_hex in list(remaining_salts):
            for rel, path, page1 in salt_to_dbs.get(salt_hex, []):
                for known_salt, known_key_hex in key_map.items():
                    enc_key = bytes.fromhex(known_key_hex)
                    if _sc4_verify_key(enc_key, page1):
                        key_map[salt_hex] = known_key_hex
                        remaining_salts.discard(salt_hex)
                        break

    return key_map


def _extract_v3_key_from_process(
    pid: int, db_path: str,
    progress_callback: Optional[Callable[[str], None]] = None,
) -> Optional[str]:
    """Extract SQLCipher 3 key from WeChat.exe process memory (classic WeChat 3.x).

    Searches near phone-type marker strings, then falls back to brute scan.
    """
    handle = _open_process(pid)
    if not handle:
        return None

    phone_markers = [b"iphone\x00", b"android\x00", b"ipad\x00"]
    marker_addrs = []
    addr_len = 8

    if progress_callback:
        progress_callback("Scanning WeChat.exe memory for v3 key...")

    regions = _enum_regions(handle)

    # Find phone type markers
    for base, size in regions:
        data = _read_process_memory(handle, base, min(size, 10 * 1024 * 1024))
        if not data:
            continue
        for marker in phone_markers:
            idx = 0
            while True:
                idx = data.find(marker, idx)
                if idx < 0:
                    break
                marker_addrs.append(base + idx)
                idx += 1

    # Try keys near marker addresses
    if marker_addrs:
        marker_addrs.sort(reverse=True)
        for m_addr in marker_addrs:
            for offset in range(0, 2000, addr_len):
                candidate_addr = m_addr - offset
                ptr_data = _read_process_memory(handle, candidate_addr, addr_len)
                if not ptr_data:
                    continue
                key_addr = int.from_bytes(ptr_data, byteorder='little')
                if key_addr < 0x10000 or key_addr > 0x7FFFFFFFFFFF:
                    continue
                key_bytes = _read_process_memory(handle, key_addr, 32)
                if not key_bytes or len(key_bytes) != 32 or key_bytes == b'\x00' * 32:
                    continue
                if _sc3_verify_key(key_bytes, db_path):
                    _close_handle(handle)
                    return key_bytes.hex()

    _close_handle(handle)
    return None


class WeChatInfo:
    """Holds WeChat account information."""

    def __init__(self, pid, version, name, account, wxid, key, wx_dir,
                 mobile="", wechat_version=3, key_map=None, db_dir=None):
        self.pid = pid
        self.version = version       # WeChat software version string
        self.name = name
        self.account = account
        self.wxid = wxid
        self.key = key               # single hex key (v3) or first key (v4 compat)
        self.wx_dir = wx_dir          # wxid directory
        self.mobile = mobile
        self.wechat_version = wechat_version  # 3 or 4
        self.key_map = key_map or {}  # {salt_hex: enc_key_hex} for v4 per-DB keys
        self.db_dir = db_dir          # path to db_storage (v4) or Msg dir (v3)

    def __str__(self):
        return f"{self.name} ({self.wxid})"


class ChatInfo:
    """Holds chat information."""

    def __init__(self, username, display_name, msg_count, is_group=False):
        self.username = username
        self.display_name = display_name
        self.msg_count = msg_count
        self.is_group = is_group

    def __str__(self):
        prefix = "[Group] " if self.is_group else ""
        return f"{prefix}{self.display_name} ({self.msg_count} messages)"


def _read_varint(data, pos):
    """Read a protobuf varint at pos. Returns (value, new_pos) or (None, pos)."""
    result = 0
    shift = 0
    while pos < len(data):
        b = data[pos]
        result |= (b & 0x7F) << shift
        pos += 1
        if not (b & 0x80):
            return result, pos
        shift += 7
        if shift > 63:
            break
    return None, pos


def _extract_strings_from_protobuf(data, _depth=0):
    """Extract length-delimited string fields from protobuf wire format."""
    if not data or not isinstance(data, (bytes, bytearray)) or _depth > 5:
        return []
    data = bytes(data)
    strings = []
    pos = 0
    while pos < len(data):
        tag, pos = _read_varint(data, pos)
        if tag is None:
            break
        wire_type = tag & 0x07
        if wire_type == 0:  # varint
            _, pos = _read_varint(data, pos)
            if _ is None:
                break
        elif wire_type == 2:  # length-delimited (string/bytes/embedded message)
            length, pos = _read_varint(data, pos)
            if length is None or pos + length > len(data) or length < 0:
                break
            field_data = data[pos:pos + length]
            pos += length
            # Try zlib decompression on the field data
            for wbits in (-zlib.MAX_WBITS, zlib.MAX_WBITS, zlib.MAX_WBITS | 16):
                try:
                    decompressed = zlib.decompress(field_data, wbits).decode("utf-8", errors="replace")
                    if decompressed and len(decompressed) > 5:
                        strings.append(decompressed)
                        break
                except Exception:
                    continue
            # Try to decode as UTF-8 text
            try:
                text = field_data.decode("utf-8")
                if text and (text.isprintable() or '\n' in text or '<' in text):
                    strings.append(text)
            except (UnicodeDecodeError, ValueError):
                pass
            # Recursively try to parse as embedded protobuf message
            nested = _extract_strings_from_protobuf(field_data, _depth + 1)
            strings.extend(nested)
        elif wire_type == 1:  # 64-bit
            pos += 8
        elif wire_type == 5:  # 32-bit
            pos += 4
        else:
            break
    return strings


def _try_decompress(data):
    """Try to extract usable text from binary data. Handles zstd, zlib, protobuf, raw XML."""
    if not data or not isinstance(data, (bytes, bytearray)):
        return None
    data = bytes(data)

    # Zstandard: magic bytes 28 b5 2f fd
    if data[:4] == b'\x28\xb5\x2f\xfd' and zstd:
        try:
            dctx = zstd.ZstdDecompressor()
            result = dctx.decompress(data)
            return result.decode("utf-8", errors="replace")
        except Exception:
            pass

    # Check if it's actually uncompressed XML with a binary prefix
    for marker in (b'<msg', b'<appmsg', b'<?xml'):
        pos = data.find(marker)
        if pos != -1:
            try:
                return data[pos:].decode("utf-8", errors="replace")
            except Exception:
                pass

    # Try zlib decompression on the raw data and at various offsets
    offsets = [0]
    for i in range(min(len(data), 256)):
        if data[i] == 0x78 and i not in offsets:  # zlib magic byte
            offsets.append(i)
    for offset in offsets:
        chunk = data[offset:]
        for wbits in (-zlib.MAX_WBITS, zlib.MAX_WBITS, zlib.MAX_WBITS | 16):
            try:
                result = zlib.decompress(chunk, wbits).decode("utf-8", errors="replace")
                if result and ('<' in result or len(result) > 10):
                    return result
            except Exception:
                continue

    # Try protobuf extraction — find embedded XML or longest text
    strings = _extract_strings_from_protobuf(data)
    if strings:
        # Prefer XML content (app message XML)
        for s in strings:
            if '<msg' in s or '<appmsg' in s:
                return s
        # Try zlib decompression on any binary-looking extracted field
        for s in strings:
            if isinstance(s, str) and len(s) > 5:
                # Check if any extracted string is itself compressible/interesting
                pass
        # Fall back to longest meaningful string
        best = max(strings, key=len)
        if len(best) > 2:
            return best

    return None


def _parse_app_message(content: str) -> str:
    """Parse type 49 (app message) XML content."""
    if not content:
        return "[App Message]"
    try:
        root = ET.fromstring(content)
        # Check if this is a reply message (appmsg type 57)
        type_el = root.find(".//appmsg/type")
        if type_el is not None and type_el.text == "57":
            title_el = root.find(".//title")
            if title_el is not None and title_el.text:
                return title_el.text
            return "[Reply]"
        title_el = root.find(".//title")
        des_el = root.find(".//des")
        url_el = root.find(".//url")
        parts = []
        if title_el is not None and title_el.text:
            parts.append(title_el.text)
        if des_el is not None and des_el.text:
            parts.append(des_el.text)
        if url_el is not None and url_el.text:
            parts.append(url_el.text)
        if parts:
            return "[Link] " + " | ".join(parts)
        return "[App Message]"
    except ET.ParseError:
        if len(content) < 200:
            return content
        return "[App Message]"


def format_message_content(msg_type: int, content: str) -> str:
    """Format message content based on its type."""
    if msg_type == MSG_TYPE_TEXT:
        return content or ""
    label = MSG_TYPE_LABELS.get(msg_type)
    if label:
        return label
    if msg_type == MSG_TYPE_APP:
        return _parse_app_message(content)
    # Fallback: content may be app message XML even with a non-49 type code
    if content and "<appmsg" in content:
        return _parse_app_message(content)
    return content or f"[Type {msg_type}]"


def _is_valid_sqlite(path: str) -> bool:
    """Check if a file is a valid SQLite database."""
    try:
        conn = sqlite3.connect(path)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master LIMIT 1")
        conn.close()
        return True
    except Exception:
        return False


class WeChatExtractor:
    """Main class for extracting WeChat messages."""

    def __init__(self):
        self.wx_info: Optional[WeChatInfo] = None
        self.decrypted_dir: Optional[str] = None
        self.contacts: Dict[str, str] = {}  # username -> display name
        self.chats: List[ChatInfo] = []
        self._temp_dirs: List[str] = []
        atexit.register(self.cleanup)

    @staticmethod
    def _running_process_names() -> List[str]:
        """Return lowercase process names from tasklist output."""
        try:
            output = subprocess.check_output(
                ["tasklist"],
                text=True,
                encoding="utf-8",
                errors="ignore",
            )
        except Exception:
            return []

        names = set()
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            if ".exe" not in line.lower():
                continue
            first = line.split()[0].strip().lower()
            if first.endswith(".exe"):
                names.add(first)
        return sorted(names)

    def detect_wechat(
        self, progress_callback: Optional[Callable[[str], None]] = None,
    ) -> Tuple[Optional[WeChatInfo], Optional[str]]:
        """Detect running WeChat and extract account info + decryption key.

        Strategy:
        1. Try pywxdump (supports classic WeChat.exe 3.x with known offsets).
        2. If pywxdump fails or key is missing, fall back to native memory
           scanning which works with both WeChat.exe and Weixin.exe.
        """
        if not is_admin():
            return None, (
                "Administrator privileges required.\n"
                "Please right-click run.bat and select 'Run as administrator',\n"
                "or re-run this script from an elevated command prompt."
            )

        running = set(self._running_process_names())
        has_classic = "wechat.exe" in running
        has_new = "weixin.exe" in running

        if not has_classic and not has_new:
            return None, (
                "No WeChat instance detected.\n"
                "Make sure WeChat is running and you are logged in."
            )

        # ── Step 1: Try pywxdump for classic WeChat.exe ──
        pywxdump_error = None
        if has_classic:
            result, err = self._try_pywxdump(progress_callback)
            if result and result.key:
                self.wx_info = result
                return self.wx_info, None
            pywxdump_error = err

        # ── Step 2: Native extraction (works for both classic and new) ──
        native_result, native_err = self._try_native_detection(progress_callback)
        if native_result and native_result.key:
            self.wx_info = native_result
            return self.wx_info, None

        # Both methods failed — compose a helpful error message
        if pywxdump_error and native_err:
            return None, (
                f"pywxdump: {pywxdump_error}\n\n"
                f"Native detection: {native_err}\n\n"
                "You can try entering the key and data directory manually."
            )
        return None, (pywxdump_error or native_err or "Detection failed.")

    def _try_pywxdump(
        self, progress_callback: Optional[Callable[[str], None]] = None,
    ) -> Tuple[Optional[WeChatInfo], Optional[str]]:
        """Attempt WeChat detection using pywxdump."""
        info_fn = None
        wx_offs = None
        try:
            import pywxdump
            if hasattr(pywxdump, "read_info"):
                info_fn = pywxdump.read_info
                wx_offs = getattr(pywxdump, "VERSION_LIST", None)
            elif hasattr(pywxdump, "get_wx_info"):
                info_fn = pywxdump.get_wx_info
                wx_offs = getattr(pywxdump, "WX_OFFS", None)
        except Exception:
            return None, "pywxdump is not installed."

        if info_fn is None:
            return None, "Unsupported pywxdump API."

        if progress_callback:
            progress_callback("Trying pywxdump detection...")

        try:
            result = None
            if wx_offs is not None:
                try:
                    result = info_fn(wx_offs)
                except TypeError:
                    result = info_fn()
            else:
                result = info_fn()

            if isinstance(result, dict):
                result = [result]
            elif not isinstance(result, (list, tuple)):
                result = [result] if result is not None else []

            if not result:
                return None, "pywxdump found no WeChat instance."

            info = result[0]

            def _get(obj, *keys, default=""):
                for k in keys:
                    if isinstance(obj, dict):
                        val = obj.get(k)
                    else:
                        val = getattr(obj, k, None)
                    if val:
                        return val
                return default

            wx_dir = _get(info, "filePath", "wx_dir", "wxdir")
            key = _get(info, "key")

            wx_info = WeChatInfo(
                pid=_get(info, "pid", default=0),
                version=_get(info, "version", default="Unknown"),
                name=_get(info, "name", "nick_name", "nickName", "nickname", default="Unknown"),
                account=_get(info, "account"),
                wxid=_get(info, "wxid"),
                key=key,
                wx_dir=wx_dir,
                mobile=_get(info, "mobile"),
            )

            if not wx_info.key:
                return wx_info, (
                    f"pywxdump could not extract decryption key "
                    f"(version {wx_info.version} may not be supported)."
                )

            return wx_info, None

        except Exception as e:
            return None, f"pywxdump error: {e}"

    def _try_native_detection(
        self, progress_callback: Optional[Callable[[str], None]] = None,
    ) -> Tuple[Optional[WeChatInfo], Optional[str]]:
        """Detect WeChat info and key by directly scanning process memory.

        For WeChat 4.x (Weixin.exe): scans for x'key+salt' patterns,
        salt-matches to DB files, and builds per-DB key map.
        For WeChat 3.x (WeChat.exe): scans near phone-type markers
        for pointer-chained 32-byte keys.
        """
        if progress_callback:
            progress_callback("Trying native detection (scanning process memory)...")

        # Find WeChat/Weixin process PIDs
        pids_by_name: Dict[str, List[int]] = {}
        try:
            import psutil
            for proc in psutil.process_iter(["pid", "name"]):
                name = (proc.info["name"] or "").lower()
                if name in ("wechat.exe", "weixin.exe"):
                    pids_by_name.setdefault(name, []).append(proc.info["pid"])
        except ImportError:
            try:
                output = subprocess.check_output(
                    ["tasklist", "/FO", "CSV", "/NH"],
                    text=True, encoding="utf-8", errors="ignore",
                )
                for line in output.strip().splitlines():
                    parts = line.strip().strip('"').split('","')
                    if len(parts) >= 2:
                        name = parts[0].lower()
                        if name in ("wechat.exe", "weixin.exe"):
                            try:
                                pids_by_name.setdefault(name, []).append(int(parts[1]))
                            except ValueError:
                                pass
            except Exception:
                pass

        if not pids_by_name:
            return None, "No WeChat/Weixin process found."

        # Find data directory
        base_dir = _find_wechat_data_dir()
        if not base_dir:
            return None, (
                "Could not find WeChat data directory.\n"
                "You can enter the path manually."
            )

        wxid_dirs = _find_wxid_dirs(base_dir)
        if not wxid_dirs:
            return None, f"No wxid directories found in {base_dir}"

        # ── WeChat 4.x (Weixin.exe): per-DB key extraction ──
        for pid in pids_by_name.get("weixin.exe", []):
            for wxid, wxid_path in wxid_dirs:
                db_storage = _find_db_storage(wxid_path)
                if not db_storage:
                    continue
                db_files = _collect_encrypted_dbs(db_storage)
                if not db_files:
                    continue

                if progress_callback:
                    progress_callback(
                        f"Scanning Weixin.exe (PID {pid}) for {len(db_files)} database keys "
                        f"({wxid})..."
                    )

                key_map = _extract_v4_keys_from_process(pid, db_files, progress_callback)
                if key_map:
                    first_key = next(iter(key_map.values()))
                    if progress_callback:
                        progress_callback(
                            f"Found {len(key_map)}/{len(db_files)} database keys for {wxid}!"
                        )
                    return WeChatInfo(
                        pid=pid,
                        version="4.x",
                        name=wxid,
                        account="",
                        wxid=wxid,
                        key=first_key,
                        wx_dir=wxid_path,
                        wechat_version=4,
                        key_map=key_map,
                        db_dir=db_storage,
                    ), None

        # ── WeChat 3.x (WeChat.exe): single-key extraction ──
        for pid in pids_by_name.get("wechat.exe", []):
            for wxid, wxid_path in wxid_dirs:
                # Find Msg dir and a reference encrypted DB
                msg_dir = os.path.join(wxid_path, "Msg")
                if not os.path.isdir(msg_dir):
                    msg_dir = wxid_path
                ref_db = None
                for candidate in [
                    os.path.join(wxid_path, "Msg", "MicroMsg.db"),
                    os.path.join(wxid_path, "MSG", "MicroMsg.db"),
                ]:
                    if os.path.isfile(candidate):
                        ref_db = candidate
                        break
                if not ref_db:
                    # Walk for any encrypted .db
                    for root, _dirs, files in os.walk(wxid_path):
                        for f in files:
                            if f.endswith(".db"):
                                full = os.path.join(root, f)
                                try:
                                    with open(full, "rb") as fh:
                                        hdr = fh.read(16)
                                    if len(hdr) >= 16 and not hdr.startswith(SQLITE_FILE_HEADER):
                                        ref_db = full
                                        break
                                except Exception:
                                    pass
                        if ref_db:
                            break
                if not ref_db:
                    continue

                if progress_callback:
                    progress_callback(
                        f"Scanning WeChat.exe (PID {pid}) for key ({wxid})..."
                    )

                key = _extract_v3_key_from_process(pid, ref_db, progress_callback)
                if key:
                    if progress_callback:
                        progress_callback(f"Key found for {wxid}!")
                    return WeChatInfo(
                        pid=pid,
                        version="3.x",
                        name=wxid,
                        account="",
                        wxid=wxid,
                        key=key,
                        wx_dir=wxid_path,
                        wechat_version=3,
                        db_dir=msg_dir,
                    ), None

        return None, (
            "Native key extraction failed.\n"
            "The key could not be found in process memory.\n"
            "You can try entering the key manually."
        )

    def set_manual_info(self, key: str, wx_dir: str) -> Tuple[bool, Optional[str]]:
        """Set WeChat info manually (key + data directory).

        For WeChat 4.x: key is a 64-char hex enc_key, wx_dir points to
        the wxid directory containing db_storage/.
        For WeChat 3.x: key is a 64-char hex key, wx_dir points to the
        wxid directory containing Msg/.
        """
        key = key.strip()
        wx_dir = wx_dir.strip()

        if not key or len(key) != 64:
            return False, "Key must be a 64-character hex string."
        try:
            key_bytes = bytes.fromhex(key)
        except ValueError:
            return False, "Key must be a valid hex string."

        if not os.path.isdir(wx_dir):
            return False, f"Directory not found: {wx_dir}"

        # Detect version based on directory structure
        db_storage = _find_db_storage(wx_dir)
        if db_storage:
            # WeChat 4.x: verify key against encrypted DBs using SQLCipher 4
            db_files = _collect_encrypted_dbs(db_storage)
            if not db_files:
                return False, f"No encrypted databases found in {db_storage}"

            # Build key_map: try the key against each DB's salt
            key_map: Dict[str, str] = {}
            verified = False
            for rel, path, page1 in db_files:
                if _sc4_verify_key(key_bytes, page1):
                    salt_hex = page1[:SALT_SIZE].hex()
                    key_map[salt_hex] = key
                    verified = True

            if not verified:
                return False, (
                    "Key verification failed — the key does not match any "
                    f"database in {db_storage}.\n"
                    "For WeChat 4.x, each database may have a different key."
                )

            wxid = os.path.basename(wx_dir)
            self.wx_info = WeChatInfo(
                pid=0, version="Manual (4.x)", name=wxid, account="",
                wxid=wxid, key=key, wx_dir=wx_dir,
                wechat_version=4, key_map=key_map, db_dir=db_storage,
            )
        else:
            # WeChat 3.x: single key for all DBs
            ref_db = None
            for candidate in [
                os.path.join(wx_dir, "Msg", "MicroMsg.db"),
                os.path.join(wx_dir, "MSG", "MicroMsg.db"),
            ]:
                if os.path.isfile(candidate):
                    ref_db = candidate
                    break
            if not ref_db:
                for root, _dirs, files in os.walk(wx_dir):
                    for f in files:
                        if f.endswith(".db"):
                            full = os.path.join(root, f)
                            try:
                                with open(full, "rb") as fh:
                                    hdr = fh.read(16)
                                if len(hdr) >= 16 and not hdr.startswith(SQLITE_FILE_HEADER):
                                    ref_db = full
                                    break
                            except Exception:
                                pass
                    if ref_db:
                        break

            if ref_db and not _sc3_verify_key(key_bytes, ref_db):
                return False, (
                    "Key verification failed — the key does not match the databases "
                    f"in {wx_dir}."
                )

            wxid = os.path.basename(wx_dir)
            msg_dir = os.path.join(wx_dir, "Msg")
            if not os.path.isdir(msg_dir):
                msg_dir = wx_dir
            self.wx_info = WeChatInfo(
                pid=0, version="Manual (3.x)", name=wxid, account="",
                wxid=wxid, key=key, wx_dir=wx_dir,
                wechat_version=3, db_dir=msg_dir,
            )

        return True, None

    def decrypt_databases(
        self, progress_callback: Optional[Callable[[str], None]] = None
    ) -> Tuple[bool, Optional[str]]:
        """Decrypt WeChat databases to a temporary directory.

        For WeChat 4.x: uses per-DB SQLCipher 4 decryption with key_map.
        For WeChat 3.x: tries pywxdump first, falls back to native SQLCipher 3.
        """
        if not self.wx_info:
            return False, "WeChat not detected. Call detect_wechat() first."

        # Create temp directory for decrypted output
        self.decrypted_dir = tempfile.mkdtemp(prefix="wx_extract_")
        self._temp_dirs.append(self.decrypted_dir)

        if self.wx_info.wechat_version == 4:
            return self._decrypt_v4(progress_callback)
        else:
            return self._decrypt_v3(progress_callback)

    def _decrypt_v4(
        self, progress_callback: Optional[Callable[[str], None]] = None
    ) -> Tuple[bool, Optional[str]]:
        """Decrypt WeChat 4.x databases using SQLCipher 4 with per-DB keys."""
        db_dir = self.wx_info.db_dir
        if not db_dir or not os.path.isdir(db_dir):
            return False, f"Database directory not found: {db_dir}"

        db_files = _collect_encrypted_dbs(db_dir)
        if not db_files:
            return False, f"No encrypted databases found in {db_dir}"

        key_map = self.wx_info.key_map
        if not key_map:
            return False, "No decryption keys available."

        if progress_callback:
            progress_callback(f"Decrypting {len(db_files)} databases (SQLCipher 4)...")

        success_count = 0
        for i, (rel, full_path, page1) in enumerate(db_files):
            salt_hex = page1[:SALT_SIZE].hex()
            enc_key_hex = key_map.get(salt_hex)
            if not enc_key_hex:
                # Try all known keys as fallback
                for known_key_hex in key_map.values():
                    if _sc4_verify_key(bytes.fromhex(known_key_hex), page1):
                        enc_key_hex = known_key_hex
                        break
            if not enc_key_hex:
                continue

            out_path = os.path.join(self.decrypted_dir, "de_" + rel.replace(os.sep, "_"))
            if progress_callback:
                progress_callback(
                    f"Decrypting {rel}... ({i + 1}/{len(db_files)})"
                )

            enc_key = bytes.fromhex(enc_key_hex)
            if _sc4_decrypt_file(enc_key, full_path, out_path):
                success_count += 1

        if success_count == 0:
            return False, (
                "Decryption produced no valid database files.\n"
                "The decryption keys may be incorrect."
            )

        if progress_callback:
            progress_callback(f"Successfully decrypted {success_count}/{len(db_files)} databases.")
        return True, None

    def _decrypt_v3(
        self, progress_callback: Optional[Callable[[str], None]] = None
    ) -> Tuple[bool, Optional[str]]:
        """Decrypt WeChat 3.x databases using SQLCipher 3."""
        wx_dir = self.wx_info.wx_dir
        if not wx_dir or not os.path.isdir(wx_dir):
            return False, f"WeChat data directory not found: {wx_dir}"

        msg_dir = self.wx_info.db_dir or os.path.join(wx_dir, "Msg")
        if not os.path.isdir(msg_dir):
            msg_dir = wx_dir

        db_files = []
        for root, _dirs, files in os.walk(msg_dir):
            for f in files:
                if f.endswith(".db"):
                    db_files.append(os.path.join(root, f))

        if not db_files:
            return False, f"No database files found in {msg_dir}"

        if progress_callback:
            progress_callback(f"Found {len(db_files)} database files. Decrypting...")

        key = self.wx_info.key

        # Try pywxdump batch_decrypt first
        try:
            from pywxdump import batch_decrypt
            try:
                batch_decrypt(key, msg_dir, self.decrypted_dir)
            except Exception:
                for db_file in db_files:
                    try:
                        batch_decrypt(key, db_file, self.decrypted_dir)
                    except Exception:
                        continue
        except ImportError:
            pass

        decrypted_files = self._count_valid_sqlite(self.decrypted_dir)
        if not decrypted_files:
            if progress_callback:
                progress_callback("pywxdump decryption failed, using native decryption...")
            for i, db_file in enumerate(db_files):
                if progress_callback:
                    progress_callback(
                        f"Decrypting {os.path.basename(db_file)}... ({i + 1}/{len(db_files)})"
                    )
                rel = os.path.relpath(os.path.dirname(db_file), msg_dir)
                out_name = "de_" + os.path.basename(db_file)
                out_path = os.path.join(self.decrypted_dir, rel, out_name)
                _sc3_decrypt_file(key, db_file, out_path)

            decrypted_files = self._count_valid_sqlite(self.decrypted_dir)

        if not decrypted_files:
            return False, (
                "Decryption produced no valid database files.\n"
                "The decryption key may be incorrect or the WeChat version is unsupported."
            )

        if progress_callback:
            progress_callback(f"Successfully decrypted {len(decrypted_files)} databases.")
        return True, None

    @staticmethod
    def _count_valid_sqlite(directory: str) -> List[str]:
        """Return list of valid SQLite files under directory."""
        result = []
        for root, _dirs, files in os.walk(directory):
            for f in files:
                full = os.path.join(root, f)
                if _is_valid_sqlite(full):
                    result.append(full)
        return result

    def load_contacts(
        self, progress_callback: Optional[Callable[[str], None]] = None
    ) -> Tuple[bool, Optional[str]]:
        """Load contacts from decrypted databases.

        WeChat 3.x: MicroMsg.db -> Contact table (UserName, NickName, Remark)
        WeChat 4.x: contact.db -> contact table (username, nick_name, remark, alias)
                    or Friend table (userName, dbContactRemark)
        """
        if not self.decrypted_dir:
            return False, "Databases not decrypted yet."

        if progress_callback:
            progress_callback("Loading contacts...")

        all_dbs = self._count_valid_sqlite(self.decrypted_dir)

        # Queries to try, in order of preference
        contact_queries = [
            # WeChat 4.x WCDB (per Cok reference)
            "SELECT username, nick_name, remark FROM contact",
            "SELECT username, nick_name, alias FROM contact",
            # WeChat 4.x Friend table
            "SELECT userName, dbContactRemark, dbContactHeadImage FROM Friend",
            # WeChat 3.x / older 4.x
            "SELECT UserName, NickName, Remark FROM Contact WHERE Type != 4",
            "SELECT UserName, NickName, Remark FROM Contact",
            "SELECT userName, nickName, remark FROM Contact",
            "SELECT username, nickname, remark FROM contact",
            "SELECT userName, nickName, remarkName FROM Friend",
        ]

        for db_path in all_dbs:
            try:
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()

                cursor.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
                tables = {row[0].lower() for row in cursor.fetchall()}

                if not (tables & {"contact", "friend"}):
                    conn.close()
                    continue

                for query in contact_queries:
                    try:
                        cursor.execute(query)
                        for row in cursor.fetchall():
                            username = row[0]
                            nickname = row[1] or ""
                            remark = row[2] or "" if len(row) > 2 else ""
                            display = remark if remark else nickname
                            if username and display:
                                self.contacts[username] = display
                        if self.contacts:
                            break
                    except sqlite3.OperationalError:
                        continue

                conn.close()
            except Exception:
                continue

        self.contacts.setdefault("filehelper", "File Transfer")

        if progress_callback:
            progress_callback(f"Loaded {len(self.contacts)} contacts.")

        return True, None

    # Tables that are NOT per-chat message tables (system/internal tables)
    _SYSTEM_TABLES = {
        "sqlite_master", "sqlite_sequence", "sqlite_stat1", "sqlite_stat4",
        "name2id", "wcdb_builtin", "wcdb_aux",
        "session", "session_fts", "sessionkv",
        "contact", "contact_fts", "contactlabel", "contactheadimgurl",
        "friend", "chatroom", "chatroominfo",
        "rcontact", "rconversation", "img_flag",
        "emoticon", "sticker", "favorite", "sns", "ticket",
        "head_image", "hardlink", "general", "solitaire",
        "bizchat", "revoke_msg", "search", "profile",
        "favorite_media", "sns_media",
        "voiceinfo", "voiceinfo2", "appinfo", "appattach",
        "addr_upload", "brandcontact", "oplog", "chat_lbs_record",
    }

    # Prefixes for non-chat internal tables (matched case-insensitively)
    _SYSTEM_TABLE_PREFIXES = (
        "snstopitem", "snsitem", "snscomment", "snsmedia",
        "sns_", "voiceinfo", "appattach", "media",
    )

    # Regex for WeChat 4.x per-chat message tables: Msg_<32-hex-chars>
    _MSG_TABLE_RE = re.compile(r'^Msg_[0-9a-fA-F]{32}$')

    def _detect_msg_schema(self, db_path: str) -> Optional[str]:
        """Detect which message schema a database uses.

        Returns:
          'v3_central' — single MSG/ChatMsg/ChatCRMsg table with StrTalker col
          'v4_perchat' — per-chat tables (table name = username)
          None — not a message database
        """
        try:
            conn = sqlite3.connect(db_path)
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {row[0] for row in cur.fetchall()}
            conn.close()
        except Exception:
            return None

        # Check for v3-style central message tables first
        for central in ("MSG", "ChatMsg", "ChatCRMsg"):
            if central in tables:
                return "v3_central"

        # Check for v4-style per-chat tables: Msg_<md5hash>
        msg_tables = [t for t in tables if self._MSG_TABLE_RE.match(t)]
        if msg_tables:
            return "v4_perchat"

        return None

    def get_chat_list(
        self, progress_callback: Optional[Callable[[str], None]] = None
    ) -> Tuple[List[ChatInfo], Optional[str]]:
        """Get list of all chats with message counts.

        Supports:
        - WeChat 3.x: single MSG/ChatMsg table with StrTalker column
        - WeChat 4.x: per-chat tables where table name = username,
          with columns local_id, local_type, create_time, message_content
        """
        if not self.decrypted_dir:
            return [], "Databases not decrypted yet."

        if progress_callback:
            progress_callback("Scanning chat history...")

        all_dbs = self._count_valid_sqlite(self.decrypted_dir)

        chat_counts: Dict[str, int] = {}
        # Store schema info for use during export
        # For v3: (db_path, 'v3_central', central_table_name)
        # For v4: (db_path, 'v4_perchat', table_name_which_is_username)
        self._msg_db_info: List[Tuple[str, str, str]] = []
        self._v4_table_to_username: Dict[str, str] = {}

        for db_path in all_dbs:
            schema = self._detect_msg_schema(db_path)
            if not schema:
                continue

            try:
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()

                if schema == "v3_central":
                    # Try known central table + talker column combos
                    v3_queries = [
                        ("MSG", "SELECT StrTalker, COUNT(*) FROM MSG GROUP BY StrTalker"),
                        ("ChatMsg", "SELECT StrTalker, COUNT(*) FROM ChatMsg GROUP BY StrTalker"),
                        ("ChatMsg", "SELECT strTalker, COUNT(*) FROM ChatMsg GROUP BY strTalker"),
                        ("ChatCRMsg", "SELECT StrTalker, COUNT(*) FROM ChatCRMsg GROUP BY StrTalker"),
                    ]
                    for table, query in v3_queries:
                        try:
                            cursor.execute(query)
                            rows = cursor.fetchall()
                            if rows:
                                self._msg_db_info.append((db_path, "v3_central", table))
                                for talker, count in rows:
                                    if talker:
                                        chat_counts[talker] = chat_counts.get(talker, 0) + count
                                break
                        except sqlite3.OperationalError:
                            continue

                elif schema == "v4_perchat":
                    # Only consider Msg_<md5> tables (actual conversations)
                    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                    all_tables = {row[0] for row in cursor.fetchall()}
                    msg_tables = [t for t in all_tables if self._MSG_TABLE_RE.match(t)]

                    # Build md5(username)->username from Name2Id for name resolution
                    name2id_map: Dict[str, str] = {}  # md5hex -> username
                    if "Name2Id" in all_tables or "name2id" in {t.lower() for t in all_tables}:
                        n2i_tbl = "Name2Id" if "Name2Id" in all_tables else next(
                            t for t in all_tables if t.lower() == "name2id"
                        )
                        try:
                            cursor.execute(f'SELECT user_name FROM "{n2i_tbl}"')
                            for (uname,) in cursor.fetchall():
                                if uname:
                                    md5hex = hashlib.md5(uname.encode("utf-8")).hexdigest()
                                    name2id_map[md5hex] = uname
                        except sqlite3.OperationalError:
                            pass

                    for tbl in msg_tables:
                        try:
                            cursor.execute(f'SELECT COUNT(*) FROM "{tbl}"')
                            count = cursor.fetchone()[0]
                            if count > 0:
                                # Resolve table hash to username
                                tbl_hash = tbl[4:]  # strip "Msg_"
                                username = name2id_map.get(tbl_hash, tbl)
                                chat_counts[username] = chat_counts.get(username, 0) + count
                                self._msg_db_info.append((db_path, "v4_perchat", tbl))
                                # Store table->username mapping for export
                                self._v4_table_to_username[tbl] = username
                        except sqlite3.OperationalError:
                            continue

                conn.close()
            except Exception:
                continue

        # Build chat list, sorted by message count descending
        self.chats = []
        for username, count in sorted(chat_counts.items(), key=lambda x: -x[1]):
            if username in SYSTEM_ACCOUNTS:
                continue
            if username.startswith("fake_"):
                continue

            display_name = self.contacts.get(username, username)
            is_group = "@chatroom" in username

            self.chats.append(
                ChatInfo(
                    username=username,
                    display_name=display_name,
                    msg_count=count,
                    is_group=is_group,
                )
            )

        if progress_callback:
            progress_callback(f"Found {len(self.chats)} chats.")

        return self.chats, None

    def _export_v3_central(self, chat: ChatInfo, db_path: str, table: str,
                            my_name: str) -> List[dict]:
        """Extract messages from a WeChat 3.x central message table."""
        messages = []
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            # Discover columns
            cursor.execute(f'PRAGMA table_info("{table}")')
            columns = {row[1].lower(): row[1] for row in cursor.fetchall()}

            id_col = columns.get("localid", columns.get("_id", "rowid"))
            content_col = columns.get("strcontent", columns.get("content", "StrContent"))
            type_col = columns.get("type", "Type")
            subtype_col = columns.get("subtype", None)
            sender_col = columns.get("issender", None)
            time_col = columns.get("createtime", "CreateTime")
            svrid_col = columns.get("msgsvrid", None)
            talker_col = columns.get("strtalker", "StrTalker")
            seq_col = columns.get("sequence", None)
            compress_col = columns.get("compresscontent", None)

            cols = [id_col, content_col, type_col]
            if subtype_col:
                cols.append(subtype_col)
            if sender_col:
                cols.append(sender_col)
            cols.append(time_col)
            if svrid_col:
                cols.append(svrid_col)
            if compress_col:
                cols.append(compress_col)

            order_col = seq_col if seq_col else time_col
            query = (
                f'SELECT {", ".join(cols)} FROM "{table}" '
                f'WHERE "{talker_col}" = ? ORDER BY "{order_col}" ASC'
            )

            cursor.execute(query, (chat.username,))
            for row in cursor.fetchall():
                idx = 0
                msg_id = row[idx]; idx += 1
                content = row[idx] or ""; idx += 1
                msg_type = row[idx] or 1; idx += 1
                sub_type = 0
                if subtype_col:
                    sub_type = row[idx] or 0; idx += 1
                is_sender = 0
                if sender_col:
                    is_sender = row[idx] or 0; idx += 1
                timestamp = row[idx] or 0; idx += 1
                msg_svr_id = None
                if svrid_col:
                    msg_svr_id = row[idx]; idx += 1
                compress_data = None
                if compress_col:
                    compress_data = row[idx] if idx < len(row) else None; idx += 1

                # Try decompressing from compress_content column first
                if (not content or isinstance(content, (bytes, bytearray))) and compress_data:
                    decompressed = _try_decompress(compress_data)
                    if decompressed:
                        content = decompressed

                # Try decompressing content column itself (replies store compressed XML here)
                if isinstance(content, (bytes, bytearray)):
                    decompressed = _try_decompress(content)
                    content = decompressed if decompressed else ""

                messages.append({
                    "id": msg_id, "content": content, "type": msg_type,
                    "sub_type": sub_type, "is_sender": is_sender,
                    "timestamp": timestamp, "svr_id": msg_svr_id,
                    "sender_name": None,
                })
            conn.close()
        except Exception:
            pass
        return messages

    def _export_v4_perchat(self, chat: ChatInfo, db_path: str, table: str,
                           my_name: str) -> List[dict]:
        """Extract messages from a WeChat 4.x per-chat table."""
        messages = []
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            # Discover columns
            cursor.execute(f'PRAGMA table_info("{table}")')
            columns = {row[1].lower(): row[1] for row in cursor.fetchall()}

            # Check which schema variant
            has_v4_cols = "create_time" in columns or "message_content" in columns

            if has_v4_cols:
                # WeChat 4.x WCDB per-chat schema
                id_col = columns.get("local_id", columns.get("localid", "rowid"))
                content_col = columns.get("message_content", columns.get("strcontent", "message_content"))
                type_col = columns.get("local_type", columns.get("type", "local_type"))
                time_col = columns.get("create_time", columns.get("createtime", "create_time"))
                svrid_col = columns.get("server_id", columns.get("msgsvrid", None))
                sender_id_col = columns.get("real_sender_id", None)
                sort_col = columns.get("sort_seq", time_col)
                compress_col = columns.get("compress_content", columns.get("compresscontent", None))

                # Build query, optionally joining Name2Id for sender resolution
                # Check if Name2Id table exists
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                all_tables = {row[0].lower() for row in cursor.fetchall()}
                has_name2id = "name2id" in all_tables

                cols = [f'"{table}"."{id_col}"', f'"{table}"."{content_col}"',
                        f'"{table}"."{type_col}"', f'"{table}"."{time_col}"']
                if svrid_col:
                    cols.append(f'"{table}"."{svrid_col}"')
                if sender_id_col and has_name2id:
                    cols.append('Name2Id.user_name')
                elif sender_id_col:
                    cols.append(f'"{table}"."{sender_id_col}"')
                if compress_col:
                    cols.append(f'"{table}"."{compress_col}"')

                col_list = ", ".join(cols)
                if sender_id_col and has_name2id:
                    query = (
                        f'SELECT {col_list} FROM "{table}" '
                        f'LEFT JOIN Name2Id ON "{table}"."{sender_id_col}"=Name2Id.rowid '
                        f'ORDER BY "{table}"."{sort_col}" ASC'
                    )
                else:
                    query = (
                        f'SELECT {col_list} FROM "{table}" '
                        f'ORDER BY "{table}"."{sort_col}" ASC'
                    )

                cursor.execute(query)
                wxid = self.wx_info.wxid if self.wx_info else ""

                for row in cursor.fetchall():
                    idx = 0
                    msg_id = row[idx]; idx += 1
                    content = row[idx] or ""; idx += 1
                    raw_type = row[idx] or 1; idx += 1
                    msg_type = raw_type & 0xFFFF  # v4 packs base type in lower bits
                    timestamp = row[idx] or 0; idx += 1
                    msg_svr_id = None
                    if svrid_col:
                        msg_svr_id = row[idx]; idx += 1
                    sender_name = None
                    if sender_id_col:
                        sender_name = row[idx] if idx < len(row) else None; idx += 1
                    compress_data = None
                    if compress_col:
                        compress_data = row[idx] if idx < len(row) else None; idx += 1

                    # Try decompressing from compress_content column first
                    if (not content or isinstance(content, (bytes, bytearray))) and compress_data:
                        decompressed = _try_decompress(compress_data)
                        if decompressed:
                            content = decompressed

                    # Try decompressing content column itself
                    if isinstance(content, (bytes, bytearray)):
                        decompressed = _try_decompress(content)
                        content = decompressed if decompressed else ""

                    # Determine is_sender: if sender == our wxid, it's sent by us
                    is_sender = 0
                    if sender_name and wxid and sender_name == wxid:
                        is_sender = 1
                    elif not sender_name and not chat.is_group:
                        # In private chats without sender info, can't determine
                        is_sender = 0

                    messages.append({
                        "id": msg_id, "content": content, "type": msg_type,
                        "sub_type": 0, "is_sender": is_sender,
                        "timestamp": timestamp, "svr_id": msg_svr_id,
                        "sender_name": sender_name,
                    })
            else:
                # Fallback: might be v3-style columns in a per-chat table name
                content_col = columns.get("strcontent", columns.get("content", "StrContent"))
                type_col = columns.get("type", "Type")
                sender_col = columns.get("issender", None)
                time_col = columns.get("createtime", "CreateTime")
                svrid_col = columns.get("msgsvrid", None)
                fb_compress_col = columns.get("compresscontent", None)

                cols = ["rowid", content_col, type_col]
                if sender_col:
                    cols.append(sender_col)
                cols.append(time_col)
                if svrid_col:
                    cols.append(svrid_col)
                if fb_compress_col:
                    cols.append(fb_compress_col)

                query = f'SELECT {", ".join(cols)} FROM "{table}" ORDER BY "{time_col}" ASC'
                cursor.execute(query)
                for row in cursor.fetchall():
                    idx = 0
                    msg_id = row[idx]; idx += 1
                    content = row[idx] or ""; idx += 1
                    raw_type = row[idx] or 1; idx += 1
                    msg_type = raw_type & 0xFFFF  # v4 packs base type in lower bits
                    is_sender = 0
                    if sender_col:
                        is_sender = row[idx] or 0; idx += 1
                    timestamp = row[idx] or 0; idx += 1
                    msg_svr_id = None
                    if svrid_col:
                        msg_svr_id = row[idx]; idx += 1
                    compress_data = None
                    if fb_compress_col:
                        compress_data = row[idx] if idx < len(row) else None; idx += 1

                    # Try decompressing from compress_content column first
                    if (not content or isinstance(content, (bytes, bytearray))) and compress_data:
                        decompressed = _try_decompress(compress_data)
                        if decompressed:
                            content = decompressed

                    # Try decompressing content column itself
                    if isinstance(content, (bytes, bytearray)):
                        decompressed = _try_decompress(content)
                        content = decompressed if decompressed else ""

                    messages.append({
                        "id": msg_id, "content": content, "type": msg_type,
                        "sub_type": 0, "is_sender": is_sender,
                        "timestamp": timestamp, "svr_id": msg_svr_id,
                        "sender_name": None,
                    })

            conn.close()
        except Exception:
            pass
        return messages

    def export_chat_to_txt(
        self,
        chat: ChatInfo,
        output_dir: str,
        my_name: str = "Me",
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> Tuple[bool, Optional[str]]:
        """Export a single chat's messages to a TXT file.

        Uses the message table schema discovered during get_chat_list().
        Supports both v3 central tables (MSG/ChatMsg) and v4 per-chat tables.
        """
        if not self.decrypted_dir:
            return False, "Databases not decrypted yet."

        msg_db_info = getattr(self, "_msg_db_info", [])

        messages = []
        seen_ids = set()

        for db_path, schema_type, table_or_name in msg_db_info:
            if schema_type == "v3_central":
                batch = self._export_v3_central(chat, db_path, table_or_name, my_name)
            elif schema_type == "v4_perchat":
                # Only process entries for THIS chat's username
                # table_or_name is the Msg_<hash> table; resolve to username
                v4_map = getattr(self, '_v4_table_to_username', {})
                resolved = v4_map.get(table_or_name, table_or_name)
                if resolved != chat.username:
                    continue
                batch = self._export_v4_perchat(chat, db_path, table_or_name, my_name)
            else:
                continue

            for msg in batch:
                svr_id = msg.get("svr_id")
                if svr_id and svr_id in seen_ids:
                    continue
                if svr_id:
                    seen_ids.add(svr_id)
                messages.append(msg)

        messages.sort(key=lambda m: m["timestamp"])

        # Exclude non-text message types
        messages = [m for m in messages if m["type"] not in EXCLUDE_TYPES]

        # Skip messages with binary content (media blobs)
        messages = [m for m in messages if not isinstance(m["content"], (bytes, bytearray))]

        if not messages:
            return False, f"No messages found for {chat.display_name}"

        # Generate safe filename
        safe_name = re.sub(r'[<>:"/\\|?*]', "_", chat.display_name).strip()
        if not safe_name:
            safe_name = chat.username
        output_path = os.path.join(output_dir, f"{safe_name}.txt")

        if os.path.exists(output_path):
            base, ext = os.path.splitext(output_path)
            counter = 1
            while os.path.exists(f"{base}_{counter}{ext}"):
                counter += 1
            output_path = f"{base}_{counter}{ext}"

        try:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(f"Chat History: {chat.display_name}\n")
                f.write(f"{'=' * 60}\n")
                f.write(f"Total Messages: {len(messages)}\n")

                if messages:
                    try:
                        first_dt = datetime.fromtimestamp(messages[0]["timestamp"])
                        f.write(f"From: {first_dt.strftime('%Y-%m-%d %H:%M:%S')}\n")
                    except (OSError, ValueError):
                        pass
                    try:
                        last_dt = datetime.fromtimestamp(messages[-1]["timestamp"])
                        f.write(f"To:   {last_dt.strftime('%Y-%m-%d %H:%M:%S')}\n")
                    except (OSError, ValueError):
                        pass

                f.write(f"{'=' * 60}\n\n")

                current_date = None

                for msg in messages:
                    try:
                        msg_dt = datetime.fromtimestamp(msg["timestamp"])
                        time_str = msg_dt.strftime("%H:%M:%S")
                        date_str = msg_dt.strftime("%Y-%m-%d")
                    except (OSError, ValueError):
                        time_str = "??:??:??"
                        date_str = None

                    if date_str and date_str != current_date:
                        current_date = date_str
                        f.write(f"\n--- {date_str} ---\n\n")

                    content = msg["content"]
                    sender_name = msg.get("sender_name")

                    if msg["is_sender"]:
                        sender = my_name
                    elif sender_name:
                        # v4: sender resolved from Name2Id
                        sender = self.contacts.get(sender_name, sender_name)
                    elif chat.is_group and msg["type"] == MSG_TYPE_TEXT:
                        # v3 group: content may start with "sender_wxid:\n"
                        if ":\n" in content:
                            sender_id, _, content = content.partition(":\n")
                            sender = self.contacts.get(sender_id, sender_id)
                        else:
                            sender = chat.display_name
                    else:
                        sender = chat.display_name

                    display_content = format_message_content(msg["type"], content)
                    if display_content.startswith(_SKIP_PREFIXES):
                        continue
                    f.write(f"[{time_str}] {sender}: {display_content}\n")

            return True, output_path

        except Exception as e:
            return False, f"Error writing file: {e}"

    def export_multiple_chats(
        self,
        chats: List[ChatInfo],
        output_dir: str,
        my_name: str = "Me",
        progress_callback: Optional[Callable[[str, float], None]] = None,
    ) -> Tuple[int, List[str]]:
        """Export multiple chats. Returns (success_count, error_list)."""
        os.makedirs(output_dir, exist_ok=True)
        total = len(chats)
        success_count = 0
        errors = []

        for i, chat in enumerate(chats):
            if progress_callback:
                progress_callback(
                    f"Exporting {chat.display_name}... ({i + 1}/{total})",
                    (i + 1) / total * 100,
                )

            ok, result = self.export_chat_to_txt(chat, output_dir, my_name)
            if ok:
                success_count += 1
            else:
                errors.append(f"{chat.display_name}: {result}")

        return success_count, errors

    def cleanup(self):
        """Remove temporary decrypted database files."""
        for temp_dir in self._temp_dirs:
            try:
                if os.path.exists(temp_dir):
                    shutil.rmtree(temp_dir)
            except Exception:
                pass
        self._temp_dirs.clear()
        self.decrypted_dir = None
