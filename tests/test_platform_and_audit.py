import json
import os

import pytest

from cadlab import platform_support as ps
from cadlab.log import AuditTrail, GENESIS


def test_home_override(monkeypatch, tmp_path):
    monkeypatch.setenv("CADLAB_HOME", str(tmp_path / "x"))
    assert ps.app_home() == tmp_path / "x"


def test_windows_layout(monkeypatch):
    monkeypatch.delenv("CADLAB_HOME", raising=False)
    monkeypatch.setattr(ps, "IS_WINDOWS", True)
    monkeypatch.setattr(ps, "IS_MAC", False)
    monkeypatch.setenv("LOCALAPPDATA", "C:/Users/test/AppData/Local")
    assert ps.app_home().parts[-2:] == ("ChrisSandor", "CADLab")


def test_mac_layout(monkeypatch):
    monkeypatch.delenv("CADLAB_HOME", raising=False)
    monkeypatch.setattr(ps, "IS_WINDOWS", False)
    monkeypatch.setattr(ps, "IS_MAC", True)
    assert ps.app_home().parts[-3:] == ("Library", "Application Support", "ChrisSandor CADLab")


def test_linux_layout_uses_xdg(monkeypatch, tmp_path):
    monkeypatch.delenv("CADLAB_HOME", raising=False)
    monkeypatch.setattr(ps, "IS_WINDOWS", False)
    monkeypatch.setattr(ps, "IS_MAC", False)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    assert ps.app_home() == tmp_path / "xdg" / "chrissandor-cadlab"


def test_layout_creates_every_folder(layout):
    for path in list(layout.dirs.values()) + list(layout.pki.values()):
        assert path.is_dir()
    assert layout.config_path.exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_private_folders_are_owner_only(layout):
    assert layout.pki["private"].stat().st_mode & 0o077 == 0
    assert layout.home.stat().st_mode & 0o077 == 0


@pytest.mark.parametrize("bad", ["", "../x", "a b", "x" * 70, ".hidden", "a/b", "a\\b", "-start"])
def test_invalid_names_rejected(bad):
    with pytest.raises(ValueError):
        ps.valid_name(bad)


def test_valid_names_accepted():
    for good in ("part-1", "A.b_c", "x" * 64):
        assert ps.valid_name(good) == good


def test_atomic_write_replaces_and_leaves_no_temp_files(tmp_path):
    target = tmp_path / "f.txt"
    ps.atomic_write(target, b"one")
    ps.atomic_write(target, b"two")
    assert target.read_bytes() == b"two"
    assert [p.name for p in tmp_path.iterdir()] == ["f.txt"]


def test_password_rules(monkeypatch):
    monkeypatch.setenv("CADLAB_PASSWORD", "short")
    with pytest.raises(ValueError):
        ps.get_password()
    monkeypatch.setenv("CADLAB_PASSWORD", "long enough password")
    assert ps.get_password() == b"long enough password"


def test_config_roundtrip_and_defaults(layout):
    config = ps.load_config(layout)
    assert config["overwatch"] == {"server": "", "ca_cert": ""}
    config["overwatch"]["server"] = "https://x"
    ps.save_config(layout, config)
    assert ps.load_config(layout)["overwatch"]["server"] == "https://x"


def test_damaged_config_falls_back_to_defaults(layout):
    layout.config_path.write_text("{not json", encoding="utf-8")
    assert ps.load_config(layout)["schema"] == ps.DEFAULT_CONFIG["schema"]


def test_audit_chain_detects_edit(tmp_path):
    trail = AuditTrail(tmp_path / "a.jsonl")
    for i in range(5):
        trail.append("event", n=i)
    assert trail.verify()["ok"] and trail.verify()["records"] == 5
    lines = (tmp_path / "a.jsonl").read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[2])
    record["n"] = 99
    lines[2] = json.dumps(record, sort_keys=True, separators=(",", ":"))
    (tmp_path / "a.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    result = trail.verify()
    assert not result["ok"] and "line 3" in result["problem"]


def test_audit_chain_detects_deleted_middle_record(tmp_path):
    trail = AuditTrail(tmp_path / "a.jsonl")
    for i in range(4):
        trail.append("event", n=i)
    lines = (tmp_path / "a.jsonl").read_text(encoding="utf-8").splitlines()
    del lines[1]
    (tmp_path / "a.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert not trail.verify()["ok"]


def test_audit_truncation_is_the_documented_blind_spot(tmp_path):
    trail = AuditTrail(tmp_path / "a.jsonl")
    for i in range(4):
        trail.append("event", n=i)
    head = trail.verify()["head"]
    lines = (tmp_path / "a.jsonl").read_text(encoding="utf-8").splitlines()
    (tmp_path / "a.jsonl").write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")
    result = trail.verify()
    assert result["ok"] and result["head"] != head


def test_empty_audit_is_valid(tmp_path):
    assert AuditTrail(tmp_path / "none.jsonl").verify() == {"ok": True, "records": 0, "head": GENESIS, "problem": None}
