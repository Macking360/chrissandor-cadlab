"""Run one complete CADLab workflow through the real command line and print a transcript.

    python scripts/beta_scenario.py > beta-run.txt

Uses a throw-away data folder, so it never touches your real CADLab data.
Exit code 0 means every step behaved as expected.
"""
import getpass
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HOME = Path(tempfile.mkdtemp(prefix="cadlab-beta-"))
ENV = dict(os.environ, CADLAB_HOME=str(HOME), CADLAB_PASSWORD="beta run password 123",
           CADLAB_SKIP_ACL="1", NO_COLOR="1", PYTHONIOENCODING="utf-8")
FAILURES = []


def scrub(text):
    text = text.replace(str(HOME), "<data>").replace(str(ROOT), "<repo>")
    user = getpass.getuser()
    if user and user.lower() not in ("root", "runner"):
        text = re.sub(r"(?<![A-Za-z])" + re.escape(user) + r"(?![A-Za-z])", "<you>", text, flags=re.I)
    return text


def step(title, *args, expect=0):
    command = [sys.executable, "-m", "cadlab", *args]
    result = subprocess.run(command, cwd=str(ROOT), env=ENV, capture_output=True, text=True, encoding="utf-8")
    ok = result.returncode == expect
    print("\n### %s\n$ cadlab %s\n%s%s[exit %d, expected %d] %s" % (
        title, scrub(" ".join(args)), scrub(result.stdout), scrub(result.stderr), result.returncode, expect,
        "OK" if ok else "FAILED"))
    if not ok:
        FAILURES.append(title)
    return result


def main():
    print("ChrisSandor CADLab beta scenario")
    print("platform: %s | python %s" % (platform.platform(), platform.python_version()))
    step("version", "--version")
    step("diagnostics", "diagnostics")
    step("create root CA", "pki", "init-root")
    step("create intermediate CA", "pki", "init-intermediate")
    step("issue a TLS server certificate", "pki", "issue", "server", "--cn", "demo.test", "--san", "demo.test")
    step("create a signing identity (key + CSR)", "identity", "create", "beta-signer")
    request = HOME / "pki" / "identities" / "beta-signer" / "csr.pem"
    issued = step("sign the CSR with the lab intermediate", "--json", "pki", "sign-csr", str(request), "--kind", "client")
    import json
    data = json.loads(issued.stdout)
    step("import the issued certificate", "identity", "import", "beta-signer", data["cert_path"],
         "--chain", data["chain_path"])
    step("create a project", "project", "create", "bracket")
    step("add a box", "project", "part", "bracket", "box", "base", "--size", "40", "20", "10")
    step("add a drilled plate", "project", "part", "bracket", "plate", "cover", "--size", "60", "30",
         "--hole", "10", "10", "5")
    step("add a cylinder", "project", "part", "bracket", "cylinder", "pin", "--size", "3", "12", "--segments", "32")
    step("seal the project", "project", "seal", "bracket", "--identity", "beta-signer")
    step("verify an untouched project", "project", "verify", "bracket")
    target = HOME / "projects" / "bracket" / "parts" / "base.stl"
    target.write_text(target.read_text(encoding="ascii") + " ", encoding="ascii")
    step("verify after a file was altered (must be detected)", "project", "verify", "bracket", expect=2)
    step("revoke the signer", "pki", "revoke", data["serial"], "--reason", "key_compromise")
    step("publish the revocation list", "pki", "crl")
    step("check the audit trail", "pki", "audit-verify")
    step("create a backup", "backup", "create")
    step("verify the backup", "backup", "verify")
    step("maintenance", "maintenance")
    shutil.rmtree(HOME, ignore_errors=True)
    print("\nRESULT: %s" % ("all steps behaved as expected" if not FAILURES else "FAILED: " + ", ".join(FAILURES)))
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())
