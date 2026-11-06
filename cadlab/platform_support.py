from __future__ import annotations

import ctypes
import getpass
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

IS_WINDOWS = os.name == "nt"
IS_MAC = sys.platform == "darwin"
IS_TERMUX = "com.termux" in os.environ.get("PREFIX", "").lower() or "TERMUX_VERSION" in os.environ
IS_WSL = (not IS_WINDOWS) and "microsoft" in platform.release().lower()

MIN_PASSWORD = 12
SUBDIRS = ("projects", "config", "logs", "backups", "runtime", "pki", "exports")
PKI_SUBDIRS = ("ca", "issued", "private", "csr", "crl", "archive", "exports", "identities")
NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def platform_label() -> str:
    if IS_TERMUX:
        return "Termux (Android, no root)"
    if IS_WSL:
        return "Linux under WSL"
    if IS_MAC:
        return "macOS"
    if IS_WINDOWS:
        return "Windows"
    return platform.system() or "POSIX"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def app_home() -> Path:
    override = os.environ.get("CADLAB_HOME")
    if override:
        return Path(override).expanduser()
    if IS_WINDOWS:
        root = Path(os.environ.get("LOCALAPPDATA") or (Path.home() / "AppData" / "Local"))
        return root / "ChrisSandor" / "CADLab"
    if IS_MAC:
        return Path.home() / "Library" / "Application Support" / "ChrisSandor CADLab"
    root = Path(os.environ.get("XDG_DATA_HOME") or (Path.home() / ".local" / "share"))
    return root / "chrissandor-cadlab"


class Layout:
    def __init__(self, home: Path):
        self.home = Path(home)
        self.dirs = {name: self.home / name for name in SUBDIRS}
        self.pki = {name: self.dirs["pki"] / name for name in PKI_SUBDIRS}

    @property
    def db_path(self) -> Path:
        return self.dirs["pki"] / "inventory.sqlite3"

    @property
    def config_path(self) -> Path:
        return self.dirs["config"] / "settings.json"

    @property
    def log_path(self) -> Path:
        return self.dirs["logs"] / "cadlab.log"

    @property
    def audit_path(self) -> Path:
        return self.dirs["logs"] / "pki-audit.jsonl"


def current_layout() -> Layout:
    return Layout(app_home())


class Colors:
    enabled = False
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    CYAN = "\033[36m"
    MAGENTA = "\033[35m"


def _enable_vt() -> bool:
    if not IS_WINDOWS:
        return os.environ.get("TERM") != "dumb"
    try:
        kernel = ctypes.windll.kernel32
        handle = kernel.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if not kernel.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        return bool(kernel.SetConsoleMode(handle, mode.value | 0x0004))
    except Exception:
        return False


def configure_console() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    Colors.enabled = bool(sys.stdout.isatty()) and os.environ.get("NO_COLOR") is None and _enable_vt()


def paint(value: str, color: str) -> str:
    return f"{color}{value}{Colors.RESET}" if Colors.enabled else value


def say(message: str = "") -> None:
    print(message)


def success(message: str) -> None:
    say(paint("[+] ", Colors.GREEN) + message)


def warning(message: str) -> None:
    say(paint("[!] ", Colors.YELLOW) + message)


def failure(message: str) -> None:
    say(paint("[-] ", Colors.RED) + message)


def heading(title: str) -> None:
    say()
    say(paint("=" * 76, Colors.CYAN))
    say(paint("  " + title, Colors.CYAN + Colors.BOLD))
    say(paint("=" * 76, Colors.CYAN))


def ask(prompt: str, default: Optional[str] = None) -> str:
    suffix = f" [{default}]" if default is not None else ""
    answer = input(f"{prompt}{suffix}: ").strip()
    return answer if answer else (default or "")


def confirm(prompt: str, default: bool = False) -> bool:
    hint = "Y/n" if default else "y/N"
    answer = ask(f"{prompt} {hint}", "").lower()
    if not answer:
        return default
    return answer in ("y", "yes")


def pause() -> None:
    try:
        input("\nPress Enter to continue...")
    except EOFError:
        pass


def get_password(confirm_entry: bool = False, prompt: str = "Private-key password") -> bytes:
    supplied = os.environ.get("CADLAB_PASSWORD")
    if supplied is not None:
        password = supplied
    else:
        password = getpass.getpass(f"{prompt} (minimum {MIN_PASSWORD} characters): ")
        if len(password) >= MIN_PASSWORD and confirm_entry and password != getpass.getpass("Repeat password: "):
            raise ValueError("Passwords do not match.")
    if len(password) < MIN_PASSWORD:
        raise ValueError(f"Password must contain at least {MIN_PASSWORD} characters.")
    return password.encode("utf-8")


def valid_name(value: str, what: str = "name") -> str:
    if not isinstance(value, str) or not NAME_PATTERN.match(value):
        raise ValueError(f"Invalid {what}: use 1-64 letters, digits, dot, dash or underscore, starting with a letter or digit.")
    return value


def safe_component(value: str, limit: int = 64) -> str:
    cleaned = "".join(c if c.isalnum() or c in "-_." else "_" for c in value).strip("._")
    return (cleaned or "item")[:limit]


def secure_mkdir(path: Path) -> None:
    Path(path).mkdir(parents=True, exist_ok=True)
    if not IS_WINDOWS:
        try:
            os.chmod(path, 0o700)
        except OSError:
            pass


def secure_file(path: Path, mode: int = 0o600) -> None:
    if not IS_WINDOWS:
        try:
            os.chmod(path, mode)
        except OSError:
            pass


def atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp-", suffix=".part")
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if not IS_WINDOWS:
            os.chmod(temporary, mode)
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def protect_windows_acl(path: Path) -> bool:
    if not IS_WINDOWS or os.environ.get("CADLAB_SKIP_ACL"):
        return False
    try:
        user = getpass.getuser()
        result = subprocess.run(
            ["icacls", str(path), "/inheritance:r", "/grant:r", f"{user}:(OI)(CI)F"],
            capture_output=True, text=True, timeout=30)
        return result.returncode == 0
    except Exception:
        return False


def private_folder_status(layout: Layout) -> str:
    target = layout.pki["private"]
    if IS_WINDOWS:
        marker = layout.home / ".acl-restricted"
        return "restricted to the current user (icacls)" if marker.exists() else "default Windows permissions (ACL restriction not applied)"
    try:
        mode = target.stat().st_mode & 0o777
    except OSError:
        return "not created"
    return f"mode {mode:o}" + (" (owner only)" if mode & 0o077 == 0 else " (WARNING: group/world access)")


DEFAULT_CONFIG = {"schema": 2, "last_maintenance": None, "overwatch": {"server": "", "ca_cert": ""}}


def initialize_layout(layout: Optional[Layout] = None) -> Layout:
    layout = layout or current_layout()
    secure_mkdir(layout.home)
    for path in layout.dirs.values():
        secure_mkdir(path)
    for path in layout.pki.values():
        secure_mkdir(path)
    marker = layout.home / ".acl-restricted"
    if IS_WINDOWS and not marker.exists() and protect_windows_acl(layout.home):
        marker.write_text("1", encoding="utf-8")
    if not layout.config_path.exists():
        save_config(layout, dict(DEFAULT_CONFIG))
    return layout


def load_config(layout: Layout) -> dict:
    try:
        data = json.loads(layout.config_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        data = {}
    merged = json.loads(json.dumps(DEFAULT_CONFIG))
    merged.update({k: v for k, v in data.items() if k != "overwatch"})
    merged["overwatch"].update(data.get("overwatch", {}) if isinstance(data.get("overwatch"), dict) else {})
    return merged


def save_config(layout: Layout, config: dict) -> None:
    atomic_write(layout.config_path, json.dumps(config, indent=2, sort_keys=True).encode("utf-8"), 0o600)
