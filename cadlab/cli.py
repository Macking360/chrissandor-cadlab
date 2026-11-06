from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import List, Optional

from . import APP_NAME, AUTHOR, BRAND, COURSE, VERSION
from . import maintenance, overwatch_link
from .bootstrap import DependencyError, ensure_crypto
from .help_text import full_help
from .log import AppLog
from .platform_support import (Colors, IS_MAC, IS_TERMUX, IS_WINDOWS, ask, configure_console, confirm, current_layout,
                               failure, heading, initialize_layout, paint, pause, platform_label, safe_component, say,
                               success, warning)
from .workspace import Workspace, termux_guest_notes

EXIT_OK, EXIT_ERROR, EXIT_TAMPER = 0, 1, 2


def crypto_modules():
    ensure_crypto()
    from . import chain, identity, keys, pki, seal
    return chain, identity, keys, pki, seal


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="machine-readable output")
    parser = argparse.ArgumentParser(prog="cadlab", description=f"{APP_NAME} - cross-platform CAD workspace and PKI laboratory")
    parser.set_defaults(json=False)
    parser.add_argument("--home", help="data directory (default: the platform's standard location, or CADLAB_HOME)")
    parser.add_argument("--json", action="store_true", dest="json", help="machine-readable output")
    parser.add_argument("--version", action="store_true", help="show the version")
    parser.add_argument("--setup", action="store_true", help="run automated setup")
    parser.add_argument("--diagnostics", action="store_true", help="show platform diagnostics")
    parser.add_argument("--help-menu", action="store_true", help="show the full introduction and help")
    sub = parser.add_subparsers(dest="command")

    def leaf(group, name, help_text, **kwargs):
        return group.add_parser(name, parents=[common], help=help_text, **kwargs)

    leaf(sub, "menu", "interactive menu (default)")
    leaf(sub, "setup", "automated setup for this platform")
    leaf(sub, "diagnostics", "show platform diagnostics")
    leaf(sub, "help", "full introduction and help")
    leaf(sub, "maintenance", "read-only health checks")
    cleanup = leaf(sub, "cleanup", "remove old runtime scratch files")
    cleanup.add_argument("--days", type=int, default=7)

    pki = sub.add_parser("pki", help="private certificate authority")
    pa = pki.add_subparsers(dest="action", required=True)
    root = leaf(pa, "init-root", "create the Root CA")
    root.add_argument("--cn", default="ChrisSandor CADLab Root CA")
    root.add_argument("--years", type=int, default=10)
    root.add_argument("--org", default="ChrisSandor CADLab")
    inter = leaf(pa, "init-intermediate", "create the Intermediate CA")
    inter.add_argument("--cn", default="ChrisSandor CADLab Issuing CA")
    inter.add_argument("--years", type=int, default=5)
    inter.add_argument("--org", default="ChrisSandor CADLab")
    issue = leaf(pa, "issue", "issue a TLS certificate and key")
    issue.add_argument("kind", choices=("server", "client"))
    issue.add_argument("--cn", required=True)
    issue.add_argument("--days", type=int, default=397)
    issue.add_argument("--org", default="ChrisSandor CADLab")
    issue.add_argument("--san", action="append", default=[], help="DNS name or IP address (repeatable)")
    signer = leaf(pa, "sign-csr", "sign a PKCS#10 request made elsewhere")
    signer.add_argument("csr")
    signer.add_argument("--kind", choices=("server", "client"), default="client")
    signer.add_argument("--days", type=int, default=397)
    signer.add_argument("--copy-san", action="store_true", help="copy DNS/IP names from the request")
    leaf(pa, "list", "list the inventory")
    leaf(pa, "status", "CA status")
    for name, text in (("inspect", "show a certificate"), ("verify", "verify chain, dates and CRL"),
                       ("export-chain", "export leaf + intermediate + root")):
        item = leaf(pa, name, text)
        item.add_argument("serial")
    revoke = leaf(pa, "revoke", "revoke a certificate")
    revoke.add_argument("serial")
    revoke.add_argument("--reason", default="unspecified")
    renew = leaf(pa, "renew", "replace a certificate with a new key")
    renew.add_argument("serial")
    renew.add_argument("--revoke-old", action="store_true")
    renew.add_argument("--days", type=int)
    crl = leaf(pa, "crl", "generate a signed CRL")
    crl.add_argument("--days", type=int, default=7)
    leaf(pa, "expiry", "expiry report")
    leaf(pa, "audit-verify", "verify the audit hash chain")
    leaf(pa, "audit-export", "export the audit log to CSV")

    ident = sub.add_parser("identity", help="keys and certificate requests for sealing")
    ia = ident.add_subparsers(dest="action", required=True)
    create = leaf(ia, "create", "make a key and PKCS#10 request")
    create.add_argument("name")
    create.add_argument("--algo", choices=("ec", "rsa"), default="ec")
    create.add_argument("--cn")
    imp = leaf(ia, "import", "attach an issued certificate")
    imp.add_argument("name")
    imp.add_argument("cert")
    imp.add_argument("--chain")
    leaf(ia, "list", "list identities")

    proj = sub.add_parser("project", help="CAD projects, parts and seals")
    pj = proj.add_subparsers(dest="action", required=True)
    pc = leaf(pj, "create", "create a project")
    pc.add_argument("name")
    leaf(pj, "list", "list projects")
    part = leaf(pj, "part", "generate a part")
    part.add_argument("project")
    part.add_argument("kind", choices=("box", "cylinder", "plate"))
    part.add_argument("name")
    part.add_argument("--size", type=float, nargs="+", required=True,
                      help="box: W D H; cylinder: RADIUS HEIGHT; plate: W D")
    part.add_argument("--hole", type=float, nargs=3, action="append", default=[], metavar=("X", "Y", "DIAMETER"))
    part.add_argument("--segments", type=int, default=48)
    seal = leaf(pj, "seal", "sign a manifest of every file in the project")
    seal.add_argument("project")
    seal.add_argument("--identity", required=True)
    seal.add_argument("--exclude", action="append", default=[], help="glob to leave out (repeatable)")
    verify = leaf(pj, "verify", "check the seal and report changed files")
    verify.add_argument("project")
    verify.add_argument("--trust", action="append", default=[], help="trusted root PEM (repeatable)")
    verify.add_argument("--crl", action="append", default=[], help="CRL file (repeatable)")
    verify.add_argument("--report", action="store_true", help="send the result to the linked OverWatch server")
    verify.add_argument("--server")
    verify.add_argument("--token")
    verify.add_argument("--ca-cert")
    hint = leaf(pj, "watch-hint", "print the OverWatch agent command for a project")
    hint.add_argument("project")
    hint.add_argument("--server", default="https://HOST:8771")
    hint.add_argument("--name", default="cadlab-device")
    hint.add_argument("--ca-cert", default="")

    watch = sub.add_parser("overwatch", help="link to an OverWatch server")
    wa = watch.add_subparsers(dest="action", required=True)
    enr = leaf(wa, "enroll", "exchange the enroll key for a device token")
    enr.add_argument("--server", required=True)
    enr.add_argument("--enroll-key", required=True)
    enr.add_argument("--name", default="")
    enr.add_argument("--ca-cert", default="")
    leaf(wa, "status", "show the saved link")
    leaf(wa, "test", "send a test event")

    back = sub.add_parser("backup", help="backups")
    ba = back.add_subparsers(dest="action", required=True)
    leaf(ba, "create", "create a backup")
    leaf(ba, "list", "list backups")
    leaf(ba, "verify", "verify backup checksums")
    res = leaf(ba, "restore", "restore a backup into a new folder")
    res.add_argument("archive")
    res.add_argument("destination")
    return parser


def emit(args, data, render) -> None:
    if args.json:
        print(json.dumps(data, indent=2, default=str))
    else:
        render(data)


def resolve_project(name: str) -> Path:
    candidate = Path(name)
    if candidate.is_dir() and (candidate / "project.json").exists():
        return candidate.resolve()
    return Workspace().project_dir(name)


def print_certificates(rows) -> None:
    if not rows:
        warning("No issued certificates in inventory.")
        return
    say(f"{'SERIAL':18} {'TYPE':9} {'STATUS':9} {'EXPIRES':20} SUBJECT")
    for row in rows:
        say(f"{row['serial'][:16]:18} {row['kind']:9} {row['status']:9} {row['not_after'][:19]:20} {row['common_name']}")


def print_dict(data: dict, indent: int = 0) -> None:
    for key, value in data.items():
        label = key.replace("_", " ")
        if isinstance(value, dict):
            say(" " * indent + f"{label}:")
            print_dict(value, indent + 2)
        elif isinstance(value, list):
            say(" " * indent + f"{label}: " + (", ".join(str(v) for v in value) if value else "none"))
        else:
            say(" " * indent + f"{label}: {value}")


def print_seal_report(report: dict) -> None:
    banner = {"intact": success, "modified": failure}.get(report["state"], failure if not report["ok"] else success)
    banner(f"{report['project']}: {report['state'].upper()}" + ("" if report["ok"] else "  - NOT TRUSTED"))
    say(f"  signer:        {report['signer'] or 'unknown'}")
    say(f"  signature:     {'valid' if report['signature_ok'] else 'INVALID'}")
    say(f"  signer chain:  {' -> '.join(report['chain']) if report['chain_ok'] else 'NOT TRUSTED'}")
    say(f"  files checked: {report['checked']}")
    for label in ("modified", "added", "missing"):
        names = report["files"][label]
        if names:
            say(f"  {label}: " + ", ".join(names[:12]) + (" ..." if len(names) > 12 else ""))
    for text in report["problems"]:
        failure(text)
    for text in report["warnings"]:
        warning(text)


def load_roots(paths: List[str]):
    from .keys import load_certs
    roots = []
    for path in paths:
        roots += list(load_certs(Path(path)))
    return roots


def load_crls(paths: List[str]):
    from cryptography import x509
    result = []
    for path in paths:
        data = Path(path).read_bytes()
        try:
            result.append(x509.load_pem_x509_crl(data))
        except ValueError:
            result.append(x509.load_der_x509_crl(data))
    return result


def cmd_pki(args) -> int:
    chain, identity, keys, pki, seal = crypto_modules()
    lab = pki.PKILab()
    try:
        action = args.action
        if action == "init-root":
            emit(args, lab.create_root(args.cn, args.years, args.org), lambda d: (success("Root CA created."), print_dict(d)))
        elif action == "init-intermediate":
            emit(args, lab.create_intermediate(args.cn, args.years, args.org),
                 lambda d: (success("Intermediate CA created."), print_dict(d)))
        elif action == "issue":
            emit(args, lab.issue(args.kind, args.cn, args.days, args.org, args.san),
                 lambda d: (success(f"Issued {args.kind} certificate. Serial: {d['serial']}"), print_dict(d)))
        elif action == "sign-csr":
            data = lab.sign_csr(Path(args.csr).read_bytes(), args.kind, args.days, args.copy_san)
            emit(args, data, lambda d: (success(f"Signed request. Serial: {d['serial']}"), print_dict(d)))
        elif action == "list":
            emit(args, lab.list_certificates(), print_certificates)
        elif action == "status":
            def render(status):
                for level, info in status.items():
                    if info is None:
                        say(f"{level.title()} CA: not created")
                    else:
                        say(f"{level.title()} CA: {info['subject']}")
                        say(f"  expires: {info['not_after']}")
                        say(f"  encrypted private key present: {info['key_present']}")
                        say(f"  sha256: {info['sha256']}")
            emit(args, lab.ca_status(), render)
        elif action == "inspect":
            emit(args, lab.inspect(args.serial), print_dict)
        elif action == "verify":
            def render(result):
                success("Chain signatures, dates, CA constraints and revocation checks passed.")
                say("  path: " + " -> ".join(result["path"]))
                for text in result["warnings"]:
                    warning(text)
                warning("This is a lab verifier, not a complete RFC 5280 path-validation engine.")
            emit(args, lab.verify(args.serial), render)
        elif action == "export-chain":
            emit(args, lab.export_chain(args.serial), lambda d: (success(f"Public chain exported: {d['path']}"),
                                                                  warning("Private keys are not included.")))
        elif action == "revoke":
            def render(d):
                if d.get("already"):
                    warning("Certificate is already revoked.")
                else:
                    success("Revocation recorded. Generate a fresh CRL and distribute it to relying systems.")
            emit(args, lab.revoke(args.serial, args.reason), render)
        elif action == "renew":
            data = lab.renew(args.serial, args.revoke_old, args.days)
            emit(args, data, lambda d: (success(f"New serial {d['new']['serial']} replaces {d['old_serial']}."),
                                        warning("Generate a new CRL to publish the revocation.") if d["old_revoked"] else None))
        elif action == "crl":
            emit(args, lab.generate_crl(args.days), lambda d: success(f"CRL #{d['number']} written: {d['path']} ({d['revoked']} revoked)"))
        elif action == "expiry":
            def render(rows):
                for row in rows:
                    colour = Colors.RED if row["days"] < 0 else Colors.YELLOW if row["days"] <= 30 else Colors.GREEN
                    say(paint(f"{row['serial'][:14]:14} {row['common_name'][:30]:30} {row['days']:5} days remaining  {row['not_after']}", colour))
                if not rows:
                    warning("No valid certificates in the inventory.")
            emit(args, lab.expiry_report(), render)
        elif action == "audit-verify":
            def render(d):
                (success if d["ok"] else failure)(f"Audit trail {'intact' if d['ok'] else 'BROKEN'}: {d['records']} records." +
                                                  (f" Problem: {d['problem']}" if d["problem"] else ""))
                say(f"  head hash: {d['head']}  (record this somewhere else to detect truncation)")
            result = lab.audit_verify()
            emit(args, result, render)
            return EXIT_OK if result["ok"] else EXIT_TAMPER
        elif action == "audit-export":
            emit(args, {"path": str(lab.audit_export())}, lambda d: success(f"Audit CSV exported: {d['path']}"))
        return EXIT_OK
    finally:
        lab.close()


def cmd_identity(args) -> int:
    chain, identity, keys, pki, seal = crypto_modules()
    store = identity.IdentityStore()
    if args.action == "create":
        data = store.create(args.name, args.algo, args.cn)
        emit(args, data, lambda d: (success(f"Identity {d['name']} created."), print_dict(d),
                                    say("Send csr_path to your authority, for example:"),
                                    say(f"  crystalline-pki issue-csr {d['csr_path']} --name {d['name']}")))
    elif args.action == "import":
        emit(args, store.import_certificate(args.name, Path(args.cert), Path(args.chain) if args.chain else None),
             lambda d: (success(f"Certificate attached to identity {d['name']}."), print_dict(d)))
    else:
        def render(rows):
            if not rows:
                warning("No identities yet.")
            for row in rows:
                say(f"{row['name']:24} {'certificate until ' + row['not_after'][:10] if row['has_certificate'] else 'waiting for a certificate'}")
        emit(args, store.list(), render)
    return EXIT_OK


def cmd_project(args) -> int:
    workspace = Workspace()
    action = args.action
    if action == "create":
        emit(args, workspace.create_project(args.name), lambda d: success(f"Project created: {d['path']}"))
    elif action == "list":
        def render(rows):
            if not rows:
                warning("No projects found.")
            for row in rows:
                say(f"- {row['name']}{'  [sealed]' if row['sealed'] else ''}  {row['path']}")
        emit(args, workspace.list_projects(), render)
    elif action == "part":
        entry = workspace.add_part(args.project, args.kind, args.name, args.size, args.hole, args.segments)
        emit(args, entry, lambda d: (success(f"Part {d['name']} written: " + ", ".join(d["files"])),
                                     say(f"  volume: {d['volume']:.4f}") if "volume" in d else say(f"  area: {d['area']:.4f}")))
    elif action == "seal":
        chain, identity, keys, pki, seal = crypto_modules()
        data = seal.seal_project(resolve_project(args.project), identity.IdentityStore(), args.identity, args.exclude)
        emit(args, data, lambda d: (success(f"Sealed {d['files']} files in {d['project']}."), print_dict(d)))
    elif action == "verify":
        return project_verify(args)
    elif action == "watch-hint":
        target = str(resolve_project(args.project))
        command = overwatch_link.agent_command(target, args.server, args.name, args.ca_cert)
        emit(args, {"command": command, "path": target}, lambda d: (say("Run this where OverWatch is installed:"), say("  " + d["command"])))
    return EXIT_OK


def project_verify(args) -> int:
    chain, identity, keys, pki, seal = crypto_modules()
    layout = current_layout()
    target = resolve_project(args.project)
    trust = list(args.trust)
    if not trust:
        lab_root = layout.pki["ca"] / "root-ca.pem"
        if not lab_root.exists():
            raise ValueError("Give a trusted root with --trust ROOT.pem (CADLab has no Root CA of its own yet).")
        trust = [str(lab_root)]
    report = seal.verify_seal(target, load_roots(trust), load_crls(args.crl))
    emit(args, report, print_seal_report)
    if args.report or args.server:
        link = overwatch_link.load_link(layout)
        server = args.server or link["server"]
        token = args.token or link["token"]
        if not server or not token:
            warning("No OverWatch link is configured (run: cadlab overwatch enroll ...). Result was not sent.")
        else:
            try:
                stored = overwatch_link.send_events(server, token, [overwatch_link.seal_event(report, str(target))],
                                                    args.ca_cert or link["ca_cert"])
                success(f"Reported to OverWatch ({stored} event stored).")
            except overwatch_link.LinkError as error:
                warning(str(error))
    return EXIT_OK if report["ok"] else EXIT_TAMPER


def cmd_overwatch(args) -> int:
    layout = initialize_layout()
    AppLog.setup(layout)
    if args.action == "enroll":
        token = overwatch_link.enroll(args.server, args.enroll_key, args.name, args.ca_cert)
        overwatch_link.save_link(layout, args.server, token, args.ca_cert)
        AppLog.event("overwatch_enrolled", server=args.server)
        emit(args, {"server": args.server, "enrolled": True}, lambda d: success("Enrolled. The device token is saved in the config folder (owner-only)."))
    elif args.action == "status":
        link = overwatch_link.load_link(layout)
        data = {"server": link["server"] or "not set", "ca_cert": link["ca_cert"] or "system trust", "token_saved": bool(link["token"])}
        emit(args, data, print_dict)
    else:
        link = overwatch_link.load_link(layout)
        if not link["server"] or not link["token"]:
            raise ValueError("No OverWatch link is configured.")
        stored = overwatch_link.send_events(link["server"], link["token"], [{
            "monitor": "cadlab", "target": "link-test", "action": "link_test", "severity": "notice",
            "detail": f"{APP_NAME} {VERSION} on {platform_label()}"}], link["ca_cert"])
        emit(args, {"stored": stored}, lambda d: success(f"OverWatch stored {d['stored']} event."))
    return EXIT_OK


def cmd_backup(args) -> int:
    if args.action == "create":
        emit(args, maintenance.backup_create(), lambda d: (success(f"Backup created: {d['path']}"),
                                                           warning("Backup contains encrypted keys and sensitive metadata. Store it securely.")))
    elif args.action == "list":
        def render(rows):
            if not rows:
                warning("No backups found.")
            for row in rows:
                say(f"{row['name']} - {row['bytes']} bytes")
        emit(args, maintenance.backup_list(), render)
    elif args.action == "verify":
        rows = maintenance.backup_verify()
        emit(args, rows, lambda items: [say(f"{r['name']}: {r['status']}") for r in items] or warning("No backup archives found."))
        return EXIT_OK if all(r["status"] == "OK" for r in rows) else EXIT_TAMPER
    else:
        emit(args, maintenance.backup_restore(Path(args.archive), Path(args.destination)),
             lambda d: success(f"Restored {d['entries']} entries into {d['destination']}."))
    return EXIT_OK


def cmd_diagnostics(args) -> int:
    def render(data):
        heading("SYSTEM DIAGNOSTICS")
        print_dict(data)
    emit(args, maintenance.diagnostics(), render)
    return EXIT_OK


def cmd_setup(args) -> int:
    heading("AUTOMATED SETUP")
    layout = initialize_layout()
    AppLog.setup(layout)
    success(f"Platform detected: {platform_label()} / {platform.machine()}")
    if IS_TERMUX:
        say("Termux non-root environment detected. Optional packages: python openssl proot-distro termux-api")
        if sys.stdin.isatty() and shutil.which("pkg") and confirm("Install or update these Termux packages with pkg?"):
            subprocess.run(["pkg", "update", "-y"], check=False)
            subprocess.run(["pkg", "install", "-y", "python", "openssl", "proot-distro", "termux-api"], check=False)
    elif IS_WINDOWS:
        say("Native Windows mode. The data folder is restricted to your account with icacls.")
    elif IS_MAC:
        say("Native macOS mode. Data lives in ~/Library/Application Support.")
    else:
        say("Native Linux/POSIX mode. Python and cryptography are used directly.")
    try:
        ensure_crypto()
        success("Python cryptography dependency is available.")
    except DependencyError as error:
        warning(str(error))
    AppLog.logger.info("setup completed on %s", platform.platform())
    success(f"Data directory initialized: {layout.home}")
    return EXIT_OK


def cmd_maintenance(args) -> int:
    def render(d):
        heading("MAINTENANCE")
        say(f"Database integrity: {d['database']}")
        for label, count in d["files"].items():
            say(f"{label}: {count} files")
        say(f"Audit trail: {'intact' if d['audit']['ok'] else 'BROKEN'} ({d['audit']['records']} records)")
        say("No certificates, keys, backups or logs were deleted.")
        success("Maintenance check completed.")
    emit(args, maintenance.run_maintenance(), render)
    return EXIT_OK


def cmd_cleanup(args) -> int:
    removed = maintenance.cleanup_runtime(days=args.days)
    emit(args, {"removed": removed}, lambda d: success(f"Removed {d['removed']} runtime file(s) older than {args.days} days."))
    return EXIT_OK


def show_help() -> None:
    heading(f"INTRODUCTION AND USER GUIDE - {APP_NAME} {VERSION}")
    say(full_help(str(current_layout().home)))


class Application:
    def __init__(self):
        self.layout = initialize_layout()
        AppLog.setup(self.layout)
        self.lab = None

    def get_lab(self):
        if self.lab is None:
            chain, identity, keys, pki, seal = crypto_modules()
            self.lab = pki.PKILab(self.layout)
        return self.lab

    def pki_menu(self) -> None:
        lab = self.get_lab()

        def init_root():
            data = lab.create_root(ask("Root CA common name", "ChrisSandor CADLab Root CA"), int(ask("Validity in years (1-30)", "10")))
            success(f"Root CA created: {data['cert_path']}")

        def init_intermediate():
            data = lab.create_intermediate(ask("Intermediate CA common name", "ChrisSandor CADLab Issuing CA"), int(ask("Validity in years (1-10)", "5")))
            success(f"Intermediate CA created: {data['cert_path']}")

        def issue(kind):
            cn = ask("Certificate common name")
            days = int(ask("Validity days (1-825)", "397"))
            org = ask("Organization", "ChrisSandor CADLab")
            sans = [s.strip() for s in ask("SAN entries, comma separated (optional)").split(",") if s.strip()]
            data = lab.issue(kind, cn, days, org, sans)
            success(f"Issued {kind} certificate. Serial: {data['serial']}")
            say(f"Certificate: {data['cert_path']}")
            say(f"Encrypted private key: {data['key_path']}")

        def sign_csr():
            path = ask("Path to the PKCS#10 request (.pem)")
            data = lab.sign_csr(Path(path).read_bytes(), ask("Kind: client or server", "client"), int(ask("Validity days", "397")))
            success(f"Signed. Serial: {data['serial']}  Chain: {data['chain_path']}")

        def inspect():
            print_dict(lab.inspect(ask("Certificate serial (hex)")))

        def verify():
            result = lab.verify(ask("Certificate serial (hex)"))
            success("Chain, dates, CA constraints and revocation checks passed.")
            for text in result["warnings"]:
                warning(text)
            warning("This is a lab verifier, not a complete RFC 5280 path-validation engine.")

        def renew():
            serial = ask("Serial of certificate to renew")
            warning("Renewal creates a new private key and serial; it does not extend the old certificate.")
            if confirm("Create the replacement?"):
                data = lab.renew(serial, confirm("Revoke the old certificate as superseded now?"))
                success(f"New serial {data['new']['serial']}")
                if data["old_revoked"]:
                    warning("Generate a new CRL to publish the revocation.")

        def revoke():
            serial = ask("Certificate serial to revoke (hex)")
            reason = ask("Reason: unspecified/key_compromise/ca_compromise/affiliation_changed/superseded/cessation_of_operation", "unspecified")
            lab.revoke(serial, reason)
            success("Revocation recorded. Generate a fresh CRL and distribute it.")

        def crl():
            data = lab.generate_crl()
            success(f"CRL #{data['number']} written: {data['path']} ({data['revoked']} revoked)")

        def expiry():
            rows = lab.expiry_report()
            for row in rows:
                colour = Colors.RED if row["days"] < 0 else Colors.YELLOW if row["days"] <= 30 else Colors.GREEN
                say(paint(f"{row['serial'][:14]:14} {row['common_name'][:30]:30} {row['days']:5} days  {row['not_after']}", colour))

        def status():
            for level, info in lab.ca_status().items():
                say(f"{level.title()} CA: " + (info["subject"] + f" (expires {info['not_after'][:10]})" if info else "not created"))

        def audit():
            result = lab.audit_verify()
            (success if result["ok"] else failure)(f"Audit trail {'intact' if result['ok'] else 'BROKEN'}: {result['records']} records")

        actions = {"1": init_root, "2": init_intermediate, "3": lambda: issue("server"), "4": lambda: issue("client"),
                   "5": lambda: print_certificates(lab.list_certificates()), "6": inspect, "7": verify, "8": renew,
                   "9": revoke, "10": crl, "11": expiry,
                   "12": lambda: success("Public chain exported: " + lab.export_chain(ask("Certificate serial to export"))["path"]),
                   "13": status, "14": lambda: success("Audit CSV exported: " + str(lab.audit_export())),
                   "15": sign_csr, "16": audit}
        while True:
            heading("PKI LAB - CERTIFICATE LIFECYCLE")
            say(" 1 Create Root CA                 2 Create Intermediate CA")
            say(" 3 Issue TLS server certificate   4 Issue TLS client certificate")
            say(" 5 List inventory                 6 Inspect certificate")
            say(" 7 Verify chain and CRL           8 Renew certificate")
            say(" 9 Revoke certificate             10 Generate CRL")
            say("11 Expiry report                 12 Export public chain")
            say("13 CA status                     14 Export audit CSV")
            say("15 Sign a certificate request    16 Verify audit trail")
            say(" 0 Return to main menu")
            choice = ask("PKI selection")
            if choice == "0":
                return
            self.run_action(actions.get(choice))
            pause()

    def identity_menu(self) -> None:
        chain, identity, keys, pki, seal = crypto_modules()
        store = identity.IdentityStore(self.layout)
        while True:
            heading("IDENTITIES - keys and requests for sealing")
            say(" 1 Create identity (key + request)   2 Import issued certificate   3 List   0 Back")
            choice = ask("Identity selection")
            if choice == "0":
                return
            if choice == "1":
                self.run_action(lambda: print_dict(store.create(ask("Identity name"), ask("Algorithm ec/rsa", "ec"))))
            elif choice == "2":
                self.run_action(lambda: print_dict(store.import_certificate(
                    ask("Identity name"), Path(ask("Certificate file")), Path(p) if (p := ask("Chain file (optional)")) else None)))
            elif choice == "3":
                self.run_action(lambda: [say(f"{r['name']}: {'certificate until ' + r['not_after'][:10] if r['has_certificate'] else 'no certificate'}") for r in store.list()])
            pause()

    def seal_menu(self) -> None:
        chain, identity, keys, pki, seal = crypto_modules()
        while True:
            heading("SEAL AND VERIFY A PROJECT")
            say(" 1 Seal a project   2 Verify a project   0 Back")
            choice = ask("Selection")
            if choice == "0":
                return
            if choice == "1":
                self.run_action(lambda: print_dict(seal.seal_project(
                    resolve_project(ask("Project name")), identity.IdentityStore(self.layout), ask("Identity name"))))
            elif choice == "2":
                def verify():
                    root = ask("Trusted root PEM (blank = this lab's root)")
                    target = resolve_project(ask("Project name"))
                    roots = load_roots([root or str(self.layout.pki["ca"] / "root-ca.pem")])
                    print_seal_report(seal.verify_seal(target, roots))
                self.run_action(verify)
            pause()

    def overwatch_menu(self) -> None:
        while True:
            heading("OVERWATCH LINK")
            say(" 1 Enroll with a server   2 Show link   3 Send test event   0 Back")
            choice = ask("Selection")
            if choice == "0":
                return
            if choice == "1":
                def enroll():
                    server, key = ask("OverWatch server URL"), ask("Enroll key")
                    ca = ask("CA certificate file (optional)")
                    token = overwatch_link.enroll(server, key, "", ca)
                    overwatch_link.save_link(self.layout, server, token, ca)
                    success("Enrolled; the device token is saved with owner-only permissions.")
                self.run_action(enroll)
            elif choice == "2":
                self.run_action(lambda: print_dict({k: (bool(v) if k == "token" else v) for k, v in overwatch_link.load_link(self.layout).items()}))
            elif choice == "3":
                self.run_action(lambda: cmd_overwatch(argparse.Namespace(action="test", json=False)))
            pause()

    def run_action(self, action) -> None:
        try:
            if action is None:
                warning("Choose a listed option.")
            else:
                action()
        except KeyboardInterrupt:
            warning("Operation cancelled.")
        except EOFError:
            raise
        except Exception as error:
            AppLog.logger.exception("action failed")
            failure(str(error))

    def run(self) -> None:
        heading(f"{APP_NAME} v{VERSION}")
        say(paint(f"{AUTHOR} | {BRAND} | {COURSE}", Colors.MAGENTA))
        say("Cross-platform CAD workspace + private PKI laboratory")
        workspace = Workspace(self.layout)

        def create_project():
            name = ask("Project name")
            clean = safe_component(name) if name else ""
            if clean and clean != name:
                warning(f"Using the folder-safe name {clean!r}.")
            success("Project created: " + workspace.create_project(clean)["path"]) if clean else None

        def list_projects():
            rows = workspace.list_projects()
            [say(f"- {r['name']}{'  [sealed]' if r['sealed'] else ''}  {r['path']}") for r in rows] or warning("No projects found.")

        actions = {
            "2": create_project, "3": list_projects,
            "4": lambda: [say(line) for line in termux_guest_notes()],
            "5": lambda: cmd_diagnostics(argparse.Namespace(json=False)),
            "6": lambda: cmd_maintenance(argparse.Namespace(json=False)),
            "7": lambda: success(f"Removed {maintenance.cleanup_runtime()} runtime file(s)."),
            "8": lambda: cmd_backup(argparse.Namespace(action="create", json=False)),
            "9": lambda: cmd_backup(argparse.Namespace(action="list", json=False)),
            "10": lambda: cmd_backup(argparse.Namespace(action="verify", json=False)),
            "11": lambda: cmd_setup(argparse.Namespace(json=False)),
            "12": show_help,
        }
        submenus = {"1": self.pki_menu, "13": self.identity_menu, "14": self.seal_menu, "15": self.overwatch_menu}
        try:
            while True:
                heading("MAIN MENU")
                for line in (" 1 PKI laboratory / certificate lifecycle", " 2 Create CAD project", " 3 List CAD projects",
                             " 4 Optional Termux Ubuntu PRoot helper", " 5 System diagnostics", " 6 Maintenance checks",
                             " 7 Clean old runtime scratch files", " 8 Create backup", " 9 List backups",
                             "10 Verify backup checksums", "11 Automated setup", "12 Introduction and complete help",
                             "13 Identities (keys and requests)", "14 Seal and verify a project", "15 OverWatch link",
                             " 0 Exit"):
                    say(line)
                choice = ask("CADLab selection")
                if choice == "0":
                    break
                if choice in submenus:
                    self.run_action(submenus[choice])
                    continue
                self.run_action(actions.get(choice))
                pause()
        except EOFError:
            say()
        if self.lab:
            self.lab.close()
        AppLog.logger.info("%s stopped", APP_NAME)
        success("CADLab closed.")


HANDLERS = {"pki": cmd_pki, "identity": cmd_identity, "project": cmd_project, "overwatch": cmd_overwatch,
            "backup": cmd_backup, "diagnostics": cmd_diagnostics, "setup": cmd_setup, "maintenance": cmd_maintenance,
            "cleanup": cmd_cleanup}


def dispatch(args) -> int:
    if args.version:
        say(f"{APP_NAME} {VERSION}")
        return EXIT_OK
    if args.help_menu or args.command == "help":
        show_help()
        return EXIT_OK
    if args.setup:
        return cmd_setup(args)
    if args.diagnostics:
        return cmd_diagnostics(args)
    initialize_layout()
    AppLog.setup()
    if args.command in (None, "menu"):
        Application().run()
        return EXIT_OK
    return HANDLERS[args.command](args)


def main(argv: Optional[List[str]] = None) -> int:
    configure_console()
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.home:
        os.environ["CADLAB_HOME"] = args.home
    try:
        return dispatch(args)
    except KeyboardInterrupt:
        say("\nInterrupted.")
        return 130
    except (DependencyError, ValueError, RuntimeError, FileNotFoundError, FileExistsError,
            overwatch_link.LinkError, PermissionError) as error:
        try:
            AppLog.logger.exception("command failed")
        except Exception:
            pass
        failure(str(error))
        return EXIT_ERROR
    except Exception as error:
        try:
            AppLog.logger.exception("fatal application error")
        except Exception:
            pass
        failure(f"{type(error).__name__}: {error}")
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
