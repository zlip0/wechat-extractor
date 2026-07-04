# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec file for WeChat Message Extractor.

Produces a single-file, console-less Windows executable.
Run:  pyinstaller build.spec
"""

import sys

a = Analysis(
    ["main.py"],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[
        "pywxdump",
        "zstandard",
        "Cryptodome",
        "Cryptodome.Cipher",
        "Cryptodome.Cipher.AES",
        "Crypto",
        "Crypto.Cipher",
        "Crypto.Cipher.AES",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Strip unnecessary stdlib modules to shrink the binary
        "unittest",
        "test",
        "xmlrpc",
        "pydoc",
        "doctest",
    ],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="WeChatExtractor",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,          # Compress with UPX if available on PATH
    console=False,      # No console window (GUI app)
    disable_windowed_traceback=False,
    # Require admin privileges on Windows
    uac_admin=True,
    # Icon (uncomment and point to your .ico file)
    # icon="assets/icon.ico",
)
