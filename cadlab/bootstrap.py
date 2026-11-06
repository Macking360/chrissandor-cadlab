from __future__ import annotations

import os
import subprocess
import sys

from .platform_support import ask, warning

REQUIRED = (42, 0)


class DependencyError(RuntimeError):
    pass


def crypto_version():
    try:
        import cryptography
    except ImportError:
        return None
    try:
        return tuple(int(part) for part in cryptography.__version__.split(".")[:2])
    except ValueError:
        return None


def ensure_crypto() -> None:
    version = crypto_version()
    if version is not None and version >= REQUIRED:
        return
    if version is None:
        warning("The Python package 'cryptography' (version 42 or newer) is required.")
    else:
        warning("cryptography %d.%d is too old; version 42 or newer is required." % version)
    automatic = os.environ.get("CADLAB_AUTO_INSTALL") == "1"
    if not automatic:
        try:
            automatic = ask("Install or upgrade it now with this Python? y/N", "N").lower() in ("y", "yes")
        except EOFError:
            automatic = False
    hint = f'{sys.executable} -m pip install --upgrade "cryptography>=42"'
    if not automatic:
        raise DependencyError("Install the dependency with: " + hint)
    result = subprocess.run([sys.executable, "-m", "pip", "install", "--upgrade", "cryptography>=42"],
                            capture_output=True, text=True)
    if result.returncode != 0:
        message = (result.stderr or "").lower()
        if "externally-managed" in message or "externally managed" in message:
            raise DependencyError("This Python is managed by the operating system. Create a virtual environment first:\n"
                                  "  python3 -m venv .venv && . .venv/bin/activate && pip install cryptography")
        raise DependencyError("pip could not install cryptography:\n" + (result.stderr or result.stdout)[-600:])
    import importlib
    importlib.invalidate_caches()
    version = crypto_version()
    if version is None or version < REQUIRED:
        raise DependencyError("cryptography is still unavailable after installation; restart the program.")
