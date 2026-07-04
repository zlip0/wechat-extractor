# WeChat Message Extractor

A Windows desktop app that extracts chat history from a logged-in WeChat account and exports selected conversations to readable TXT files.

Supports both **classic WeChat.exe (3.x)** and **newer Weixin.exe (4.x+)**.

## Prerequisites

- **Windows 10/11**
- **Python 3.8+** — [Download](https://www.python.org/downloads/)
- **WeChat for Windows** — installed and **logged in** (must be running when you use this tool)

## Quick Start

### 1. Install dependencies

Double-click **`setup.bat`**, or run manually:

```
py -m pip install -r requirements.txt
```

### 2. Run the app

Right-click **`run.bat`** → **Run as administrator**

> **Administrator privileges are required** because the app needs to read WeChat's process memory to extract the database decryption key.

Alternatively, from an elevated command prompt:

```
cd path\to\wechat-message-extractor
py main.py
```

### 3. Export chats

1. The app will automatically detect your running WeChat instance
2. Wait for database decryption and chat loading to complete
3. Click on chats to select them (☑) — use **Select All** / **Deselect All** as needed
4. Use the **Search** bar to find specific chats
5. Choose an output directory (defaults to `Desktop\WeChat_Export`)
6. Click **Export Selected Chats**
7. The output folder opens automatically when export finishes

## Newer WeChat Versions (Weixin.exe / 4.x)

WeChat 4.x uses a fundamentally different encryption scheme (SQLCipher 4 with per-database keys). The app handles this transparently:

- **SQLCipher 3** (WeChat 3.x): HMAC-SHA1, 64,000 PBKDF2 iterations, single key for all databases
- **SQLCipher 4** (WeChat 4.x): HMAC-SHA512, 256,000 PBKDF2 iterations, each database has its own encryption key

The app will:
1. Detect `Weixin.exe` (4.x) or `WeChat.exe` (3.x) processes
2. Find your data directory automatically (e.g. `xwechat_files` or `WeChat Files`)
3. Scan process memory for encryption keys using WCDB's cached key format
4. Match keys to databases via salt verification
5. Decrypt all databases and load contacts + chat history

If automatic detection fails, click **Manual Key Entry** and provide:
- The 64-character hex decryption key
- The path to your wxid data directory:
  - WeChat 4.x: `...\xwechat_files\wxid_xxxxxxxx`
  - WeChat 3.x: `...\WeChat Files\wxid_xxxxxxxx`

## Troubleshooting

| Problem | Solution |
|---------|----------|
| "No WeChat instance detected" | Make sure WeChat (or Weixin) is running and you are logged in |
| "Administrator privileges required" | Right-click `run.bat` → Run as administrator |
| Automatic detection fails on newer WeChat | The app will try native memory scanning automatically. If that also fails, use **Manual Key Entry** |
| "Could not extract decryption key" | Try updating `pywxdump`: `py -m pip install --upgrade pywxdump`. Or use Manual Key Entry if you have the key |
| "pywxdump is not installed" | Run `setup.bat` or `py -m pip install -r requirements.txt` |
| Decryption fails | Ensure WeChat is running and logged in. The key is only available while the process is active |
| Missing contacts (shows wxid instead of name) | This can happen for contacts not in your contact list |

If you're on Python 3.14 and install fails on `pyaudio`, `setup.bat` automatically uses a fallback install that skips audio-only dependencies.

## How It Works

1. Detects the running WeChat/Weixin process and extracts the database decryption key from memory
   - First tries `pywxdump` (supports classic WeChat 3.x with known version offsets)
   - Falls back to native memory scanning (works with both WeChat.exe and Weixin.exe)
2. Decrypts the local SQLite databases (WeChat encrypts them with SQLCipher)
   - Uses `pywxdump.batch_decrypt` when available, falls back to built-in decryption
3. Reads contacts from `MicroMsg.db` and messages from `MSG*.db` files
4. Exports selected conversations to formatted TXT files
5. Cleans up temporary decrypted files on exit
