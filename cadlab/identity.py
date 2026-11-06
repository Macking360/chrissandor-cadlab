from __future__ import annotations

import shutil
from pathlib import Path
from typing import List, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from .chain import describe, fingerprint
from .keys import cert_pem, load_certs, new_ec_key, new_rsa_key, public_der, read_private_key, write_private_key
from .log import AppLog
from .pki import ORG, make_name
from .platform_support import Layout, atomic_write, current_layout, initialize_layout, iso, valid_name


class IdentityStore:
    def __init__(self, layout: Optional[Layout] = None, password: Optional[bytes] = None):
        self.layout = initialize_layout(layout or current_layout())
        AppLog.setup(self.layout)
        self._password = password

    def folder(self, name: str) -> Path:
        return self.layout.pki["identities"] / valid_name(name, "identity name")

    def create(self, name: str, algorithm: str = "ec", common_name: Optional[str] = None, org: str = ORG) -> dict:
        folder = self.folder(name)
        if folder.exists():
            raise FileExistsError(f"Identity already exists: {name}")
        if algorithm not in ("ec", "rsa"):
            raise ValueError("Algorithm must be 'ec' or 'rsa'.")
        key = new_ec_key() if algorithm == "ec" else new_rsa_key()
        csr = (x509.CertificateSigningRequestBuilder().subject_name(make_name(common_name or name, org))
               .sign(key, hashes.SHA256()))
        folder.mkdir(parents=True)
        try:
            write_private_key(key, folder / "key.pem", self._password)
        except Exception:
            shutil.rmtree(folder, ignore_errors=True)
            raise
        atomic_write(folder / "csr.pem", csr.public_bytes(serialization.Encoding.PEM), 0o644)
        AppLog.event("identity_created", name=name, algorithm=algorithm, subject=csr.subject.rfc4514_string())
        return {"name": name, "algorithm": algorithm, "csr_path": str(folder / "csr.pem"),
                "key_path": str(folder / "key.pem"), "subject": describe(csr)}

    def import_certificate(self, name: str, cert_path: Path, chain_path: Optional[Path] = None) -> dict:
        folder = self.folder(name)
        if not (folder / "csr.pem").exists():
            raise FileNotFoundError(f"No such identity: {name}")
        certs = list(load_certs(Path(cert_path)))
        if chain_path:
            certs += [c for c in load_certs(Path(chain_path)) if fingerprint(c) not in {fingerprint(x) for x in certs}]
        if not certs:
            raise ValueError("No certificate found in the supplied file.")
        csr = x509.load_pem_x509_csr((folder / "csr.pem").read_bytes())
        leaf = next((c for c in certs if public_der(c.public_key()) == public_der(csr.public_key())), None)
        if leaf is None:
            raise ValueError("None of the supplied certificates matches this identity's key. "
                             "Was the certificate issued for a different request?")
        others = [c for c in certs if fingerprint(c) != fingerprint(leaf) and c.subject != c.issuer]
        atomic_write(folder / "cert.pem", cert_pem(leaf), 0o644)
        atomic_write(folder / "chain.pem", cert_pem(leaf) + b"".join(cert_pem(c) for c in others), 0o644)
        AppLog.event("identity_certificate_imported", name=name, serial=format(leaf.serial_number, "x"),
                     issuer=leaf.issuer.rfc4514_string())
        return {"name": name, "subject": describe(leaf), "issuer": leaf.issuer.rfc4514_string(),
                "not_after": iso(leaf.not_valid_after_utc), "intermediates": len(others)}

    def list(self) -> List[dict]:
        found = []
        base = self.layout.pki["identities"]
        for folder in sorted(p for p in base.iterdir() if p.is_dir()):
            info = {"name": folder.name, "has_certificate": (folder / "cert.pem").exists(), "not_after": None}
            if info["has_certificate"]:
                cert = load_certs(folder / "cert.pem")[0]
                info.update(not_after=iso(cert.not_valid_after_utc), subject=describe(cert))
            found.append(info)
        return found

    def load_signer(self, name: str) -> Tuple[object, x509.Certificate, List[x509.Certificate]]:
        folder = self.folder(name)
        if not (folder / "cert.pem").exists():
            raise FileNotFoundError(f"Identity {name!r} has no certificate yet. Import one with: cadlab identity import")
        chain = list(load_certs(folder / "chain.pem"))
        key = read_private_key(folder / "key.pem", self._password)
        leaf = chain[0]
        if public_der(leaf.public_key()) != public_der(key.public_key()):
            raise ValueError("The identity's certificate does not match its private key.")
        return key, leaf, chain[1:]
