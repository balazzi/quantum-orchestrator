"""Platform matrix: runtime detection + packaging guidance."""
from __future__ import annotations

import platform
import sys

PACKAGING = {
    "android": "Embed qo/ with Chaquopy (Gradle) or Briefcase; run.py serve "
               "behind a WebView for the PWA dashboard.",
    "ios": "Briefcase (beeware) project embedding qo/; dashboard via WKWebView.",
    "windows": "python run.py directly, or PyInstaller one-folder build.",
    "macos": "python run.py directly, or Briefcase .app bundle.",
    "linux": "python run.py directly, or deploy/Dockerfile container.",
    "pwa": "Serve web/ over HTTPS (Vercel/Cloudflare); install from browser.",
}


def current() -> dict:
    return {
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "python": sys.version.split()[0],
        "packaging_hint": PACKAGING.get(platform.system().lower(),
                                        PACKAGING["pwa"]),
    }
