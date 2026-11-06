import json
from pathlib import Path

import pytest
from cryptography import x509

from cadlab import seal
from cadlab.identity import IdentityStore
from cadlab.keys import load_cert, load_certs
from cadlab.workspace import Workspace


@pytest.fixture
def sealed(lab, layout):
    store = IdentityStore(layout)
    request = store.create("signer", "ec")
    issued = lab.sign_csr(Path(request["csr_path"]).read_bytes(), "client", 60)
    store.import_certificate("signer", Path(issued["cert_path"]), Path(issued["chain_path"]))
    workspace = Workspace(layout)
    project = Path(workspace.create_project("demo")["path"])
    workspace.add_part("demo", "box", "block", [10, 20, 30])
    seal.seal_project(project, store, "signer")
    roots = list(load_certs(lab.ca_paths("root")[0]))
    return {"project": project, "roots": roots, "lab": lab, "store": store, "issued": issued}


def test_identity_flow_and_listing(sealed):
    names = {i["name"]: i for i in sealed["store"].list()}
    assert names["signer"]["has_certificate"]


def test_intact_project_verifies(sealed):
    report = seal.verify_seal(sealed["project"], sealed["roots"])
    assert report["ok"] and report["state"] == "intact"
    assert report["checked"] >= 4
    assert report["chain"][-1].startswith("CN=ChrisSandor CADLab Root CA")


def test_modified_file_is_found(sealed):
    stl = sealed["project"] / "parts" / "block.stl"
    stl.write_text(stl.read_text(encoding="ascii").replace("1.0", "2.0", 1) + " ", encoding="ascii")
    report = seal.verify_seal(sealed["project"], sealed["roots"])
    assert not report["ok"] and report["state"] == "modified"
    assert report["files"]["modified"] == ["parts/block.stl"]


def test_added_and_missing_files_are_found(sealed):
    (sealed["project"] / "notes.txt").write_text("hi", encoding="utf-8")
    (sealed["project"] / "README.txt").unlink()
    report = seal.verify_seal(sealed["project"], sealed["roots"])
    assert report["files"]["added"] == ["notes.txt"]
    assert report["files"]["missing"] == ["README.txt"]
    assert report["state"] == "modified"


def test_forged_manifest_fails_signature(sealed):
    manifest_path = sealed["project"] / ".cadlab-seal" / "manifest.json"
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    data["files"]["project.json"]["sha256"] = "0" * 64
    manifest_path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    report = seal.verify_seal(sealed["project"], sealed["roots"])
    assert report["state"] == "invalid-signature" and not report["signature_ok"]


def test_attacker_cannot_reseal_with_their_own_key(sealed, tmp_path, monkeypatch, layout):
    from cadlab.platform_support import current_layout, initialize_layout
    from cadlab.pki import PKILab
    monkeypatch.setenv("CADLAB_HOME", str(tmp_path / "attacker"))
    attacker_layout = initialize_layout(current_layout())
    attacker = PKILab(attacker_layout)
    attacker.create_root(cn="Attacker Root")
    attacker.create_intermediate()
    store = IdentityStore(attacker_layout)
    request = store.create("evil", "ec")
    issued = attacker.sign_csr(Path(request["csr_path"]).read_bytes(), "client")
    store.import_certificate("evil", Path(issued["cert_path"]), Path(issued["chain_path"]))
    (sealed["project"] / "malware.txt").write_text("x", encoding="utf-8")
    seal.seal_project(sealed["project"], store, "evil")
    attacker.close()
    report = seal.verify_seal(sealed["project"], sealed["roots"])
    assert report["signature_ok"] and not report["chain_ok"]
    assert report["state"] == "untrusted-signer" and not report["ok"]


def test_revoked_signer_is_untrusted(sealed):
    lab = sealed["lab"]
    lab.revoke(sealed["issued"]["serial"], "key_compromise")
    crl = x509.load_pem_x509_crl(Path(lab.generate_crl()["path"]).read_bytes())
    report = seal.verify_seal(sealed["project"], sealed["roots"], [crl])
    assert report["state"] == "untrusted-signer"
    assert any("revoked" in p for p in report["problems"])


def test_unsealed_and_damaged_seals(lab, layout, sealed):
    workspace = Workspace(layout)
    plain = Path(workspace.create_project("plain")["path"])
    assert seal.verify_seal(plain, sealed["roots"])["state"] == "unsealed"
    (sealed["project"] / ".cadlab-seal" / "manifest.sig").write_text("garbage", encoding="utf-8")
    assert seal.verify_seal(sealed["project"], sealed["roots"])["state"] == "damaged-seal"


def test_resealing_keeps_history(sealed):
    (sealed["project"] / "extra.txt").write_text("new", encoding="utf-8")
    seal.seal_project(sealed["project"], sealed["store"], "signer")
    history = list((sealed["project"] / ".cadlab-seal" / "history").iterdir())
    assert len(history) == 1 and (history[0] / "manifest.json").exists()
    assert seal.verify_seal(sealed["project"], sealed["roots"])["ok"]


def test_exclude_patterns(sealed):
    (sealed["project"] / "scratch.tmp").write_text("a", encoding="utf-8")
    seal.seal_project(sealed["project"], sealed["store"], "signer", exclude=["*.tmp"])
    (sealed["project"] / "scratch.tmp").write_text("changed", encoding="utf-8")
    assert seal.verify_seal(sealed["project"], sealed["roots"])["ok"]


def test_unsafe_manifest_paths_are_never_opened(sealed, tmp_path):
    project = sealed["project"]
    for bad in ("../outside.txt", "/etc/passwd", "a/../../b", "C:/Windows/win.ini", "sub\\evil"):
        assert seal._safe_member(project, bad) is None, bad
    assert seal._safe_member(project, "parts/block.stl") is not None


def test_expired_identity_cannot_seal(lab, layout):
    store = IdentityStore(layout)
    request = store.create("brief", "ec")
    issued = lab.sign_csr(Path(request["csr_path"]).read_bytes(), "client", 1)
    store.import_certificate("brief", Path(issued["cert_path"]))
    project = Path(Workspace(layout).create_project("late")["path"])
    cert = load_cert(issued["cert_path"])
    import cadlab.seal as module
    original = module.utcnow
    from datetime import timedelta
    module.utcnow = lambda: cert.not_valid_after_utc + timedelta(days=1)
    try:
        with pytest.raises(ValueError, match="expired"):
            seal.seal_project(project, store, "brief")
    finally:
        module.utcnow = original


def test_import_rejects_certificate_for_other_key(lab, layout):
    store = IdentityStore(layout)
    store.create("one", "ec")
    other = store.create("two", "ec")
    issued = lab.sign_csr(Path(other["csr_path"]).read_bytes(), "client")
    with pytest.raises(ValueError, match="matches this identity"):
        store.import_certificate("one", Path(issued["cert_path"]))


def test_identity_without_certificate_cannot_sign(layout):
    store = IdentityStore(layout)
    store.create("empty", "rsa")
    with pytest.raises(FileNotFoundError):
        store.load_signer("empty")


def test_duplicate_and_invalid_identity_names(layout):
    store = IdentityStore(layout)
    store.create("dup", "ec")
    with pytest.raises(FileExistsError):
        store.create("dup", "ec")
    with pytest.raises(ValueError):
        store.create("../escape", "ec")
    with pytest.raises(ValueError):
        store.create("ok", "dsa")
