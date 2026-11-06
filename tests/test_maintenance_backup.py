import io
import os
import tarfile
import time
from pathlib import Path

import pytest

from cadlab import maintenance
from cadlab.workspace import Workspace


def test_diagnostics_reports_the_platform(layout):
    data = maintenance.diagnostics(layout)
    for key in ("application", "python", "os", "platform", "data_directory", "cryptography", "audit_trail",
                "private_key_folder", "flags"):
        assert key in data
    assert data["data_directory"] == str(layout.home)
    assert data["audit_trail"]["ok"]


def test_maintenance_deletes_nothing_and_stamps_config(lab, layout):
    lab.issue("client", "kept")
    before = sorted(p.name for p in layout.pki["issued"].iterdir())
    result = maintenance.run_maintenance(layout)
    assert result["database"] == "ok" and result["deleted_anything"] is False
    assert sorted(p.name for p in layout.pki["issued"].iterdir()) == before
    from cadlab.platform_support import load_config
    assert load_config(layout)["last_maintenance"]


def test_cleanup_only_removes_old_runtime_files(layout):
    old, new = layout.dirs["runtime"] / "old.tmp", layout.dirs["runtime"] / "new.tmp"
    old.write_text("x")
    new.write_text("y")
    ancient = time.time() - 30 * 86400
    os.utime(old, (ancient, ancient))
    assert maintenance.cleanup_runtime(layout) == 1
    assert not old.exists() and new.exists()


def test_backup_roundtrip_preserves_keys_projects_and_database(lab, layout, tmp_path):
    issued = lab.issue("server", "backup.test")
    Workspace(layout).create_project("saved")
    info = maintenance.backup_create(layout)
    assert maintenance.backup_list(layout)[0]["name"].startswith("cadlab-backup-")
    assert maintenance.backup_verify(layout)[0]["status"] == "OK"
    restored = maintenance.backup_restore(Path(info["path"]), tmp_path / "restore")
    assert restored["checksum_verified"] is True
    root = tmp_path / "restore"
    assert (root / "projects" / "saved" / "project.json").exists()
    assert Path(issued["key_path"]).name in {p.name for p in (root / "pki" / "private").iterdir()}
    import sqlite3
    rows = sqlite3.connect(str(root / "pki" / "inventory.sqlite3")).execute("SELECT serial FROM certificates").fetchall()
    assert [r[0] for r in rows] == [issued["serial"]]
    assert (root / "logs" / "pki-audit.jsonl").exists()


def test_two_backups_in_one_second_do_not_collide(layout):
    first, second = maintenance.backup_create(layout), maintenance.backup_create(layout)
    assert first["path"] != second["path"]


def test_tampered_backup_is_detected(layout, tmp_path):
    info = maintenance.backup_create(layout)
    with open(info["path"], "ab") as stream:
        stream.write(b"junk")
    assert maintenance.backup_verify(layout)[0]["status"] == "CHECKSUM MISMATCH"
    with pytest.raises(ValueError, match="checksum"):
        maintenance.backup_restore(Path(info["path"]), tmp_path / "out")


def test_restore_refuses_a_non_empty_destination(layout, tmp_path):
    info = maintenance.backup_create(layout)
    (tmp_path / "busy").mkdir()
    (tmp_path / "busy" / "file").write_text("x")
    with pytest.raises(FileExistsError):
        maintenance.backup_restore(Path(info["path"]), tmp_path / "busy")
    assert (tmp_path / "busy" / "file").read_text() == "x"


def test_malicious_archive_paths_are_refused(tmp_path):
    archive = tmp_path / "evil.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        data = b"owned"
        info = tarfile.TarInfo("../escape.txt")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    with pytest.raises(ValueError, match="Unsafe"):
        maintenance.backup_restore(archive, tmp_path / "dest")
    assert not (tmp_path / "escape.txt").exists()


def test_symlink_entries_are_refused(tmp_path):
    archive = tmp_path / "link.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        info = tarfile.TarInfo("pki/link")
        info.type = tarfile.SYMTYPE
        info.linkname = "/etc/passwd"
        tar.addfile(info)
    with pytest.raises(ValueError, match="Unsupported"):
        maintenance.backup_restore(archive, tmp_path / "dest")
