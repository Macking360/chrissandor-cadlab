import json
import os
import socket
import sqlite3
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import pytest

OVERWATCH_DIR = os.environ.get("OVERWATCH_DIR")
OVERWATCH_PYTHON = os.environ.get("OVERWATCH_PYTHON", sys.executable)

pytestmark = pytest.mark.skipif(
    not OVERWATCH_DIR or not Path(OVERWATCH_DIR, "overwatch").is_dir(),
    reason="set OVERWATCH_DIR to a checkout of the OverWatch repository",
)


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture
def overwatch(tmp_path):
    instance = tmp_path / "ow-instance"
    port = free_port()
    env = dict(os.environ, OVERWATCH_INSTANCE=str(instance), OVERWATCH_PORT=str(port), OVERWATCH_HOST="127.0.0.1")
    process = subprocess.Popen([OVERWATCH_PYTHON, "-m", "overwatch", "run"], cwd=OVERWATCH_DIR, env=env,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    base = "http://127.0.0.1:%d" % port
    deadline = time.time() + 40
    while time.time() < deadline:
        if process.poll() is not None:
            pytest.fail("OverWatch exited early: " + process.stdout.read().decode(errors="replace"))
        try:
            urllib.request.urlopen(base + "/login", timeout=2)
            break
        except Exception:
            time.sleep(0.5)
    else:
        process.kill()
        pytest.fail("OverWatch did not start")
    enroll_key = (instance / "enroll_key").read_text(encoding="utf-8").strip()
    yield {"base": base, "key": enroll_key, "db": instance / "overwatch.db"}
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()


def stored_events(db_path):
    connection = sqlite3.connect(str(db_path))
    try:
        return connection.execute("SELECT source, monitor, severity, target, action, detail FROM events").fetchall()
    finally:
        connection.close()


def sealed_project(run, layout):
    code, out, _ = run("pki", "init-root")
    assert code == 0
    assert run("pki", "init-intermediate")[0] == 0
    request = json.loads(run("--json", "identity", "create", "ow-signer")[1])["csr_path"]
    issued = json.loads(run("--json", "pki", "sign-csr", request)[1])
    assert run("identity", "import", "ow-signer", issued["cert_path"], "--chain", issued["chain_path"])[0] == 0
    assert run("project", "create", "ow-demo")[0] == 0
    assert run("project", "seal", "ow-demo", "--identity", "ow-signer")[0] == 0
    return Path(layout.dirs["projects"], "ow-demo")


def test_cadlab_enrolls_and_reports_seal_results_to_a_real_overwatch(overwatch, run, layout):
    project = sealed_project(run, layout)
    assert run("overwatch", "enroll", "--server", overwatch["base"], "--enroll-key", overwatch["key"])[0] == 0
    assert run("overwatch", "test")[0] == 0
    assert run("project", "verify", "ow-demo", "--report")[0] == 0
    (project / "README.txt").write_text("changed after sealing", encoding="utf-8")
    assert run("project", "verify", "ow-demo", "--report")[0] == 2
    rows = [row for row in stored_events(overwatch["db"]) if row[1] == "cadlab"]
    actions = [row[4] for row in rows]
    assert "seal_verified" in actions and "seal_violation" in actions
    violation = next(row for row in rows if row[4] == "seal_violation")
    assert violation[2] == "critical" and "README.txt" in violation[5]


def test_a_wrong_enroll_key_is_refused_by_overwatch(overwatch, run, layout):
    code, out, _ = run("overwatch", "enroll", "--server", overwatch["base"], "--enroll-key", "not-the-key")
    assert code == 1
