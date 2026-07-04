"""
Application configuration constants.

Edit these values before building for distribution.
"""

# ── App Identity ────────────────────────────────────────────────────────────
APP_NAME = "WeChat Message Extractor"
APP_VERSION = "1.0.1"
APP_AUTHOR = "zlip"

# ── Update Server ───────────────────────────────────────────────────────────
# URL to a JSON manifest file describing the latest version.
# Can be a GitHub raw URL, your own server, S3 bucket, etc.
# Example GitHub: "https://raw.githubusercontent.com/you/repo/main/update_manifest.json"
# Example custom:  "https://api.yoursite.com/updates/manifest.json"
UPDATE_MANIFEST_URL = "https://raw.githubusercontent.com/zlip0/wechat-extractor/refs/heads/main/manifest.json"
