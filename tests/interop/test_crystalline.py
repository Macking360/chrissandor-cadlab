import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("crystalline_pki", reason="crystalline-pki is not installed")


def crystalline(home, *args):
    env = dict(os.environ)
    env["CRYSTALLINE_PKI_HOME"] = str(home)
    result = subprocess.run(
        [sys.executable, "-m", "crystalline_pki", "--home", str(home), *args],
        capture_output=True, text=True, env=env, timeout=180,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout


@pytest.fixture
def authority(tmp_path):
    home = tmp_path / "crystalline-home"
    crystalline(home, "init")
    return home


def issue_to_cadlab(authority, run, layout, name):
    code, out, _ = run("--json", "identity", "create", name)
    assert code == 0
    request = json.loads(out)["csr_path"]
    crystalline(authority, "issue-csr", request, "--name", name)
    produced = sorted((authority / "pki" / "issued" / name).glob("*.pem"))
    chains = [p for p in produced if p.name.endswith("-chain.pem")]
    leaves = [p for p in produced if not p.name.endswith("-chain.pem")]
    assert chains and leaves, [p.name for p in produced]
    code, _, _ = run("identity", "import", name, str(leaves[0]), "--chain", str(chains[0]))
    assert code == 0
    return leaves[0]


def test_crystalline_certificate_seals_and_verifies_in_cadlab(authority, run, layout):
    root = authority / "pki" / "root" / "root-cert.pem"
    assert root.exists()
    issue_to_cadlab(authority, run, layout, "interop-signer")
    assert run("project", "create", "interop")[0] == 0
    assert run("project", "part", "interop", "box", "block", "--size", "10", "20", "30")[0] == 0
    assert run("project", "seal", "interop", "--identity", "interop-signer")[0] == 0
    code, out, _ = run("project", "verify", "interop", "--trust", str(root))
    assert code == 0 and "INTACT" in out
    stl = Path(layout.dirs["projects"], "interop", "parts", "block.stl")
    stl.write_text(stl.read_text(encoding="ascii") + " ", encoding="ascii")
    code, out, _ = run("--json", "project", "verify", "interop", "--trust", str(root))
    assert code == 2 and json.loads(out)["files"]["modified"] == ["parts/block.stl"]


def test_revoking_in_crystalline_makes_the_seal_untrusted(authority, run, layout):
    root = authority / "pki" / "root" / "root-cert.pem"
    leaf = issue_to_cadlab(authority, run, layout, "revoked-signer")
    run("project", "create", "revokable")
    assert run("project", "seal", "revokable", "--identity", "revoked-signer")[0] == 0
    crystalline(authority, "revoke", "revoked-signer", "--reason", "key_compromise")
    crystalline(authority, "crl", "refresh")
    crl = authority / "pki" / "crl" / "intermediate-crl.pem"
    assert crl.exists() and leaf.exists()
    code, out, _ = run("--json", "project", "verify", "revokable", "--trust", str(root), "--crl", str(crl))
    report = json.loads(out)
    assert code == 2 and report["state"] == "untrusted-signer"
    assert any("revoked" in problem for problem in report["problems"])
