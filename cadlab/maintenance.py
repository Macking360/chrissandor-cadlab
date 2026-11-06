from __future__ import annotations

import hashlib
import platform
import shutil
import sqlite3
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import List, Optional

from . import APP_NAME, VERSION
from .bootstrap import crypto_version
from .log import AppLog, AuditTrail
from .platform_support import (IS_MAC, IS_TERMUX, IS_WINDOWS, IS_WSL, Layout, atomic_write, current_layout,
                               initialize_layout, iso, load_config, platform_label, private_folder_status, save_config,
                               secure_file, utcnow)

BACKUP_FOLDERS = ("projects", "config", "pki")
SNAPSHOT_SKIP = ("inventory.sqlite3", "inventory.sqlite3-wal", "inventory.sqlite3-shm", "inventory.sqlite3-journal")


def diagnostics(layout: Optional[Layout] = None) -> dict:
    layout = layout or current_layout()
    initialize_layout(layout)
    version = crypto_version()
    audit = AuditTrail(layout.audit_path).verify()
    return {
        "application": f"{APP_NAME} {VERSION}",
        "python": sys.version.split()[0],
        "os": platform.platform(),
        "architecture": platform.machine(),
        "platform": platform_label(),
        "flags": {"windows": IS_WINDOWS, "macos": IS_MAC, "termux": IS_TERMUX, "wsl": IS_WSL},
        "data_directory": str(layout.home),
        "free_disk_mib": shutil.disk_usage(layout.home).free // (1024 * 1024),
        "openssl": shutil.which("openssl") or "not found",
        "proot_distro": shutil.which("proot-distro") or "not applicable or not found",
        "cryptography": ".".join(map(str, version)) if version else "not installed (will bootstrap on PKI use)",
        "sqlite": sqlite3.sqlite_version,
        "root_ca": (layout.pki["ca"] / "root-ca.pem").exists(),
        "intermediate_ca": (layout.pki["ca"] / "intermediate-ca.pem").exists(),
        "private_key_folder": private_folder_status(layout),
        "audit_trail": {"ok": audit["ok"], "records": audit["records"], "problem": audit["problem"]},
    }


def check_database(layout: Layout) -> str:
    if not layout.db_path.exists():
        return "PKI inventory not initialized"
    connection = sqlite3.connect(str(layout.db_path))
    try:
        return connection.execute("PRAGMA integrity_check").fetchone()[0]
    finally:
        connection.close()


def run_maintenance(layout: Optional[Layout] = None) -> dict:
    layout = initialize_layout(layout or current_layout())
    AppLog.setup(layout)
    counts = {}
    for label, folder in (("logs", layout.dirs["logs"]), ("backups", layout.dirs["backups"]),
                          ("issued", layout.pki["issued"]), ("private", layout.pki["private"])):
        counts[label] = sum(1 for item in folder.iterdir() if item.is_file())
    result = {"database": check_database(layout), "files": counts,
              "audit": AuditTrail(layout.audit_path).verify(), "deleted_anything": False}
    config = load_config(layout)
    config["last_maintenance"] = iso(utcnow())
    save_config(layout, config)
    AppLog.event("maintenance_check", database=result["database"], audit_ok=result["audit"]["ok"])
    return result


def cleanup_runtime(layout: Optional[Layout] = None, days: int = 7) -> int:
    layout = initialize_layout(layout or current_layout())
    removed = 0
    cutoff = utcnow().timestamp() - days * 86400
    for item in layout.dirs["runtime"].iterdir():
        try:
            if item.is_file() and item.stat().st_mtime < cutoff:
                item.unlink()
                removed += 1
        except OSError:
            continue
    AppLog.setup(layout)
    AppLog.event("runtime_cleanup", removed=removed)
    return removed


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def backup_create(layout: Optional[Layout] = None) -> dict:
    layout = initialize_layout(layout or current_layout())
    AppLog.setup(layout)
    stamp = utcnow().strftime("%Y%m%d-%H%M%S")
    target = layout.dirs["backups"] / f"cadlab-backup-{stamp}.tar.gz"
    counter = 1
    while target.exists():
        counter += 1
        target = layout.dirs["backups"] / f"cadlab-backup-{stamp}-{counter}.tar.gz"
    snapshot_dir = Path(tempfile.mkdtemp(prefix="cadlab-snap-", dir=str(layout.dirs["runtime"])))
    try:
        snapshot = snapshot_dir / "inventory.sqlite3"
        if layout.db_path.exists():
            source = sqlite3.connect(str(layout.db_path))
            copy = sqlite3.connect(str(snapshot))
            try:
                source.backup(copy)
            finally:
                copy.close()
                source.close()

        def keep(info):
            return None if Path(info.name).name in SNAPSHOT_SKIP else info

        with tarfile.open(target, "w:gz") as archive:
            for folder in BACKUP_FOLDERS:
                archive.add(layout.dirs[folder], arcname=folder, filter=keep)
            if layout.audit_path.exists():
                archive.add(layout.audit_path, arcname="logs/pki-audit.jsonl")
            if snapshot.exists():
                archive.add(snapshot, arcname="pki/inventory.sqlite3")
    finally:
        shutil.rmtree(snapshot_dir, ignore_errors=True)
    secure_file(target)
    digest = _sha256(target)
    atomic_write(Path(str(target) + ".sha256"), f"{digest}  {target.name}\n".encode("utf-8"), 0o600)
    AppLog.event("backup_created", file=str(target), sha256=digest)
    return {"path": str(target), "sha256": digest, "bytes": target.stat().st_size}


def backup_list(layout: Optional[Layout] = None) -> List[dict]:
    layout = initialize_layout(layout or current_layout())
    return [{"name": p.name, "bytes": p.stat().st_size} for p in sorted(layout.dirs["backups"].glob("*.tar.gz"))]


def backup_verify(layout: Optional[Layout] = None) -> List[dict]:
    layout = initialize_layout(layout or current_layout())
    results = []
    for item in sorted(layout.dirs["backups"].glob("*.tar.gz")):
        checksum = Path(str(item) + ".sha256")
        if not checksum.exists():
            results.append({"name": item.name, "status": "checksum missing"})
            continue
        expected = checksum.read_text(encoding="utf-8").split()[0]
        results.append({"name": item.name, "status": "OK" if expected == _sha256(item) else "CHECKSUM MISMATCH"})
    return results


def _safe_members(archive: tarfile.TarFile):
    for member in archive.getmembers():
        name = member.name.replace("\\", "/")
        parts = [p for p in name.split("/") if p]
        if name.startswith("/") or ".." in parts or (parts and ":" in parts[0]):
            raise ValueError(f"Unsafe path inside the archive: {member.name!r}")
        if not (member.isfile() or member.isdir()):
            raise ValueError(f"Unsupported entry inside the archive: {member.name!r}")
        yield member


def backup_restore(archive_path: Path, destination: Path) -> dict:
    archive_path, destination = Path(archive_path), Path(destination)
    if not archive_path.exists():
        raise FileNotFoundError(f"No such backup: {archive_path}")
    if destination.exists() and any(destination.iterdir()):
        raise FileExistsError("The restore destination must be a new or empty folder; nothing was overwritten.")
    checksum = Path(str(archive_path) + ".sha256")
    verified = None
    if checksum.exists():
        verified = checksum.read_text(encoding="utf-8").split()[0] == _sha256(archive_path)
        if not verified:
            raise ValueError("The backup checksum does not match; the archive may be damaged or altered.")
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive_path, "r:gz") as archive:
        members = list(_safe_members(archive))
        if hasattr(tarfile, "data_filter"):
            archive.extractall(destination, members=members, filter="data")
        else:
            archive.extractall(destination, members=members)
    return {"destination": str(destination), "checksum_verified": verified, "entries": len(members)}
