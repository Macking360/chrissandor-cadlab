import json
from pathlib import Path

import pytest

from cadlab import cli

from .test_overwatch_link import FakeOverWatch, fake_server, url  # noqa: F401,F811


def feed(monkeypatch, answers):
    iterator = iter(answers)

    def fake_input(prompt=""):
        try:
            return next(iterator)
        except StopIteration:
            raise EOFError

    monkeypatch.setattr("builtins.input", fake_input)


def test_version_and_help(run):
    code, out, _ = run("--version")
    assert code == 0 and "ChrisSandor CADLab" in out
    code, out, _ = run("--help-menu")
    assert code == 0 and "THREE-PART FAMILY" in out and "crystalline-pki" in out and "OverWatch" in out
    code, out, _ = run("help")
    assert code == 0 and "PLATFORMS" in out


def test_unknown_command_is_an_argparse_error(run):
    with pytest.raises(SystemExit) as info:
        run("nonsense")
    assert info.value.code == 2


def test_diagnostics_json(run):
    code, out, _ = run("--json", "diagnostics")
    data = json.loads(out)
    assert code == 0 and data["audit_trail"]["ok"] and "flags" in data
    code, out, _ = run("diagnostics", "--json")
    assert json.loads(out)["application"].startswith("ChrisSandor CADLab")


def test_legacy_flags_still_work(run):
    assert run("--diagnostics")[0] == 0
    assert run("--setup")[0] == 0


def test_end_to_end_seal_flow_through_the_cli(run, layout):
    assert run("pki", "init-root")[0] == 0
    assert run("pki", "init-intermediate")[0] == 0
    code, out, _ = run("--json", "identity", "create", "ci-signer")
    request = json.loads(out)["csr_path"]
    code, out, _ = run("--json", "pki", "sign-csr", request, "--kind", "client")
    issued = json.loads(out)
    assert run("identity", "import", "ci-signer", issued["cert_path"], "--chain", issued["chain_path"])[0] == 0
    assert run("project", "create", "widget")[0] == 0
    assert run("project", "part", "widget", "box", "block", "--size", "10", "20", "30")[0] == 0
    assert run("project", "part", "widget", "plate", "cover", "--size", "50", "30", "--hole", "10", "10", "5")[0] == 0
    assert run("project", "part", "widget", "cylinder", "pin", "--size", "2", "8", "--segments", "16")[0] == 0
    code, out, _ = run("project", "seal", "widget", "--identity", "ci-signer")
    assert code == 0 and "Sealed" in out
    code, out, _ = run("project", "verify", "widget")
    assert code == 0 and "INTACT" in out
    stl = Path(layout.dirs["projects"], "widget", "parts", "block.stl")
    stl.write_text(stl.read_text(encoding="ascii").replace("solid block", "solid hacked"), encoding="ascii")
    code, out, _ = run("--json", "project", "verify", "widget")
    report = json.loads(out)
    assert code == cli.EXIT_TAMPER and report["files"]["modified"] == ["parts/block.stl"]
    code, out, _ = run("project", "list")
    assert "widget" in out and "[sealed]" in out


def test_verify_without_any_root_explains_what_to_do(run, layout):
    run("project", "create", "lonely")
    code, out, _ = run("project", "verify", "lonely")
    assert code == cli.EXIT_ERROR and "--trust" in out


def test_pki_commands_and_error_codes(run):
    run("pki", "init-root")
    run("pki", "init-intermediate")
    code, out, _ = run("--json", "pki", "issue", "server", "--cn", "cli.test", "--san", "cli.test")
    serial = json.loads(out)["serial"]
    assert run("pki", "verify", serial)[0] == 0
    assert run("pki", "revoke", serial, "--reason", "key_compromise")[0] == 0
    assert run("pki", "crl")[0] == 0
    assert run("pki", "verify", serial)[0] == cli.EXIT_ERROR
    assert run("pki", "revoke", serial, "--reason", "nonsense")[0] == cli.EXIT_ERROR
    assert run("pki", "inspect", "ffffffff")[0] == cli.EXIT_ERROR
    assert run("pki", "list")[0] == 0 and run("pki", "status")[0] == 0 and run("pki", "expiry")[0] == 0
    code, out, _ = run("pki", "audit-verify")
    assert code == 0 and "intact" in out
    assert run("pki", "audit-export")[0] == 0
    assert run("pki", "init-root")[0] == cli.EXIT_ERROR


def test_backup_commands(run, tmp_path):
    run("pki", "init-root")
    assert run("backup", "create")[0] == 0
    assert "cadlab-backup" in run("backup", "list")[1]
    assert run("backup", "verify")[0] == 0
    archive = json.loads(run("--json", "backup", "list")[1])[0]["name"]
    layout_archive = Path(cli.current_layout().dirs["backups"]) / archive
    assert run("backup", "restore", str(layout_archive), str(tmp_path / "restored"))[0] == 0
    assert run("backup", "restore", str(layout_archive), str(tmp_path / "restored"))[0] == cli.EXIT_ERROR


def test_maintenance_and_cleanup(run):
    assert run("maintenance")[0] == 0
    assert run("cleanup", "--days", "1")[0] == 0


def test_overwatch_commands_report_to_the_server(run, lab, layout, fake_server):  # noqa: F811
    server = url(fake_server)
    assert run("overwatch", "enroll", "--server", server, "--enroll-key", "right-key")[0] == 0
    code, out, _ = run("--json", "overwatch", "status")
    assert json.loads(out)["token_saved"] is True and "device-token-1" not in out
    assert run("overwatch", "test")[0] == 0
    run("--json", "identity", "create", "ow-signer")
    request = Path(layout.pki["identities"], "ow-signer", "csr.pem")
    issued = json.loads(run("--json", "pki", "sign-csr", str(request))[1])
    run("identity", "import", "ow-signer", issued["cert_path"], "--chain", issued["chain_path"])
    run("project", "create", "watched")
    run("project", "seal", "watched", "--identity", "ow-signer")
    FakeOverWatch.seen.clear()
    assert run("project", "verify", "watched", "--report")[0] == 0
    assert FakeOverWatch.seen[-1][2]["events"][0]["action"] == "seal_verified"
    Path(layout.dirs["projects"], "watched", "README.txt").write_text("tampered", encoding="utf-8")
    assert run("project", "verify", "watched", "--report")[0] == cli.EXIT_TAMPER
    event = FakeOverWatch.seen[-1][2]["events"][0]
    assert event["action"] == "seal_violation" and event["severity"] == "critical"
    assert "README.txt" in event["detail"]


def test_overwatch_failure_does_not_hide_the_verification_result(run, lab, layout):
    run("--json", "identity", "create", "s2")
    request = Path(layout.pki["identities"], "s2", "csr.pem")
    issued = json.loads(run("--json", "pki", "sign-csr", str(request))[1])
    run("identity", "import", "s2", issued["cert_path"], "--chain", issued["chain_path"])
    run("project", "create", "p")
    run("project", "seal", "p", "--identity", "s2")
    code, out, _ = run("project", "verify", "p", "--server", "http://127.0.0.1:1", "--token", "t")
    assert code == 0 and "INTACT" in out and "Could not reach" in out


def test_watch_hint(run):
    run("project", "create", "hinted")
    code, out, _ = run("project", "watch-hint", "hinted", "--server", "https://ow:8771")
    assert code == 0 and "overwatch agent" in out and "--watch-file" in out and "hinted" in out


def test_interactive_menu_basics(monkeypatch, capsys):
    feed(monkeypatch, ["12", "", "0"])
    assert cli.main([]) == 0
    out = capsys.readouterr().out
    assert "MAIN MENU" in out and "INTRODUCTION AND USER GUIDE" in out and "CADLab closed." in out


def test_interactive_menu_survives_end_of_input(monkeypatch, capsys):
    feed(monkeypatch, [])
    assert cli.main(["menu"]) == 0
    assert "CADLab closed." in capsys.readouterr().out


def test_interactive_pki_menu_creates_root_with_defaults(monkeypatch, capsys, layout):
    feed(monkeypatch, ["1", "1", "", "", "", "13", "", "0", "0"])
    assert cli.main([]) == 0
    out = capsys.readouterr().out
    assert "Root CA created" in out and "Root CA: CN=ChrisSandor CADLab Root CA" in out
    assert (layout.pki["ca"] / "root-ca.pem").exists()


def test_interactive_project_creation_sanitises_names(monkeypatch, capsys, layout):
    feed(monkeypatch, ["2", "My Part #1", "", "3", "", "0"])
    assert cli.main([]) == 0
    out = capsys.readouterr().out
    assert "folder-safe name 'My_Part__1'" in out and "My_Part__1" in out
    assert (layout.dirs["projects"] / "My_Part__1" / "project.json").exists()


def test_interactive_invalid_choice_does_not_crash(monkeypatch, capsys):
    feed(monkeypatch, ["99", "", "abc", "", "0"])
    assert cli.main([]) == 0
    assert "Choose a listed option." in capsys.readouterr().out
