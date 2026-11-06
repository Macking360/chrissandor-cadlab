from __future__ import annotations

import base64
import fnmatch
import hashlib
import json
import os
import shutil
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Dict, Iterable, Optional, Sequence

from cryptography import x509

from .chain import ChainError, describe, fingerprint, verify_chain
from .identity import IdentityStore
from .keys import cert_pem, load_certs, sign_bytes, verify_bytes
from .log import AppLog
from .platform_support import atomic_write, iso, utcnow

SEAL_DIR = ".cadlab-seal"
FORMAT = "chrissandor-cadlab-seal/1"
MANIFEST = "manifest.json"
SIGNATURE = "manifest.sig"
SIGNER = "signer-chain.pem"
CHUNK = 1024 * 1024


def hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(CHUNK), b""):
            digest.update(block)
    return digest.hexdigest()


def collect_files(project: Path, exclude: Sequence[str] = ()) -> Dict[str, dict]:
    project = Path(project)
    found: Dict[str, dict] = {}
    for current, folders, names in os.walk(project):
        folders[:] = sorted(d for d in folders if d != SEAL_DIR and not (Path(current) / d).is_symlink())
        for name in sorted(names):
            path = Path(current) / name
            if path.is_symlink() or not path.is_file():
                continue
            relative = path.relative_to(project).as_posix()
            if any(fnmatch.fnmatch(relative, pattern) for pattern in exclude):
                continue
            found[relative] = {"sha256": hash_file(path), "size": path.stat().st_size}
    return dict(sorted(found.items()))


def _safe_member(project: Path, relative: str) -> Optional[Path]:
    pure = PurePosixPath(relative)
    if pure.is_absolute() or ".." in pure.parts or not pure.parts or "\\" in relative or ":" in relative.split("/")[0]:
        return None
    candidate = (project / Path(*pure.parts)).resolve()
    try:
        candidate.relative_to(project.resolve())
    except ValueError:
        return None
    return candidate


def seal_project(project: Path, store: IdentityStore, identity: str, exclude: Sequence[str] = ()) -> dict:
    project = Path(project)
    if not (project / "project.json").exists():
        raise FileNotFoundError(f"Not a CADLab project folder: {project}")
    key, leaf, intermediates = store.load_signer(identity)
    now = utcnow()
    if leaf.not_valid_after_utc < now:
        raise ValueError("The identity's certificate has expired; obtain a new one before sealing.")
    files = collect_files(project, exclude)
    manifest = {"format": FORMAT, "project": project.name, "sealed_at": iso(now), "hash": "sha256",
                "exclude": list(exclude), "files": files,
                "signer": {"subject": describe(leaf), "serial": format(leaf.serial_number, "x"),
                           "sha256": fingerprint(leaf)}}
    body = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    algorithm, signature = sign_bytes(key, body)
    folder = project / SEAL_DIR
    if (folder / MANIFEST).exists():
        history = folder / "history" / now.strftime("%Y%m%dT%H%M%S%fZ")
        history.mkdir(parents=True)
        for name in (MANIFEST, SIGNATURE, SIGNER):
            if (folder / name).exists():
                shutil.move(str(folder / name), str(history / name))
    folder.mkdir(exist_ok=True)
    atomic_write(folder / MANIFEST, body, 0o644)
    signature_doc = {"algorithm": algorithm, "signature": base64.b64encode(signature).decode("ascii")}
    atomic_write(folder / SIGNATURE, (json.dumps(signature_doc, indent=2) + "\n").encode("utf-8"), 0o644)
    atomic_write(folder / SIGNER, cert_pem(leaf) + b"".join(cert_pem(c) for c in intermediates), 0o644)
    AppLog.event("project_sealed", project=project.name, files=len(files), signer=describe(leaf),
                 manifest_sha256=hashlib.sha256(body).hexdigest())
    return {"project": project.name, "files": len(files), "signer": describe(leaf), "algorithm": algorithm,
            "manifest_sha256": hashlib.sha256(body).hexdigest(), "seal_dir": str(folder)}


def verify_seal(project: Path, roots: Iterable[x509.Certificate], crls: Iterable = (),
                now: Optional[datetime] = None) -> dict:
    project = Path(project)
    report = {"project": project.name, "state": "intact", "ok": False, "signature_ok": False, "chain_ok": False,
              "signer": None, "chain": None, "warnings": [], "problems": [],
              "files": {"modified": [], "added": [], "missing": []}, "checked": 0}
    folder = project / SEAL_DIR
    if not (folder / MANIFEST).exists():
        report.update(state="unsealed")
        report["problems"].append("This project has not been sealed.")
        return report
    try:
        body = (folder / MANIFEST).read_bytes()
        manifest = json.loads(body.decode("utf-8"))
        signature_doc = json.loads((folder / SIGNATURE).read_text(encoding="utf-8"))
        signer_chain = list(load_certs(folder / SIGNER))
        signature = base64.b64decode(signature_doc["signature"], validate=True)
        algorithm = signature_doc["algorithm"]
        if manifest.get("format") != FORMAT or not isinstance(manifest.get("files"), dict):
            raise ValueError("unrecognised seal format")
    except (OSError, ValueError, KeyError, TypeError) as error:
        report.update(state="damaged-seal")
        report["problems"].append(f"The seal files are missing or unreadable: {error}")
        return report
    leaf = signer_chain[0]
    report["signer"] = describe(leaf)
    report["signature_ok"] = verify_bytes(leaf.public_key(), algorithm, signature, body)
    if not report["signature_ok"]:
        report["problems"].append("The manifest signature does not match the signer's certificate.")
    claimed = manifest.get("signer", {}).get("sha256")
    if claimed and claimed != fingerprint(leaf):
        report["signature_ok"] = False
        report["problems"].append("The signer certificate differs from the one named in the manifest.")
    try:
        details = verify_chain(leaf, signer_chain[1:], list(roots), list(crls), now=now)
        report["chain_ok"], report["chain"] = True, details["path"]
        report["warnings"] += details["warnings"]
    except ChainError as error:
        report["problems"].append(f"Signer certificate is not trusted: {error}")
    recorded: Dict[str, dict] = manifest["files"]
    actual = collect_files(project, manifest.get("exclude", []))
    for relative, entry in recorded.items():
        member = _safe_member(project, relative)
        if member is None:
            report["problems"].append(f"The manifest names an unsafe path and it was ignored: {relative!r}")
            continue
        if relative not in actual:
            report["files"]["missing"].append(relative)
        elif actual[relative]["sha256"] != entry.get("sha256"):
            report["files"]["modified"].append(relative)
    report["files"]["added"] = [r for r in actual if r not in recorded]
    report["checked"] = len(recorded)
    changed = any(report["files"].values())
    if not report["signature_ok"]:
        report["state"] = "invalid-signature"
    elif not report["chain_ok"]:
        report["state"] = "untrusted-signer"
    elif changed:
        report["state"] = "modified"
    report["ok"] = report["signature_ok"] and report["chain_ok"] and not changed and not report["problems"]
    AppLog.event("project_seal_verified", project=project.name, state=report["state"], ok=report["ok"],
                 modified=len(report["files"]["modified"]), added=len(report["files"]["added"]),
                 missing=len(report["files"]["missing"]))
    return report
