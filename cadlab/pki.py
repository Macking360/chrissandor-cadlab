from __future__ import annotations

import csv
import ipaddress
import json
import re
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .chain import describe, fingerprint, verify_chain
from .keys import cert_pem, load_cert, new_rsa_key, read_private_key, write_private_key
from .log import AppLog
from .platform_support import (Layout, atomic_write, current_layout, initialize_layout, iso, safe_component,
                               utcnow)

ORG = "ChrisSandor CADLab"
KINDS = ("server", "client")
REASONS = ("unspecified", "key_compromise", "ca_compromise", "affiliation_changed", "superseded",
           "cessation_of_operation")
LABEL = re.compile(r"^[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$")
CLOCK_SKEW = timedelta(minutes=5)

SCHEMA = """
CREATE TABLE IF NOT EXISTS certificates(
    serial TEXT PRIMARY KEY,
    common_name TEXT NOT NULL,
    kind TEXT NOT NULL,
    issuer TEXT NOT NULL,
    not_before TEXT NOT NULL,
    not_after TEXT NOT NULL,
    cert_path TEXT NOT NULL,
    key_path TEXT,
    status TEXT NOT NULL,
    revoked_at TEXT,
    reason TEXT,
    fingerprint_sha256 TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""


class Database:
    def __init__(self, path: Path):
        self.connection = sqlite3.connect(str(path))
        self.connection.row_factory = sqlite3.Row
        self.connection.executescript(SCHEMA)
        self.connection.commit()

    def execute(self, sql, args=()):
        return self.connection.execute(sql, args)

    def commit(self):
        self.connection.commit()

    def close(self):
        self.connection.close()


def normalize_serial(value: str) -> str:
    text = (value or "").strip().lower()
    if text.startswith("0x"):
        text = text[2:]
    if not re.fullmatch(r"[0-9a-f]+", text or ""):
        raise ValueError("A certificate serial must be hexadecimal digits.")
    return text


def make_name(common_name: str, organization: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
                      x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def valid_hostname(text: str) -> bool:
    if not text or len(text) > 253:
        return False
    labels = text.split(".")
    if labels[0] == "*" and len(labels) > 1:
        labels = labels[1:]
    return all(LABEL.match(label) for label in labels)


def parse_sans(items) -> List[x509.GeneralName]:
    names: List[x509.GeneralName] = []
    for item in items or []:
        text = str(item).strip()
        if not text:
            continue
        try:
            names.append(x509.IPAddress(ipaddress.ip_address(text)))
            continue
        except ValueError:
            pass
        if not valid_hostname(text):
            raise ValueError(f"Invalid subject alternative name: {text!r}")
        names.append(x509.DNSName(text))
    return names


def san_strings(cert) -> List[str]:
    try:
        value = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return []
    found = [str(n) for n in value.get_values_for_type(x509.DNSName)]
    found += [str(n) for n in value.get_values_for_type(x509.IPAddress)]
    return found


def common_name(cert) -> str:
    values = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return values[0].value if values else "(no CN)"


def check_requested_key(public_key) -> None:
    if isinstance(public_key, rsa.RSAPublicKey):
        if public_key.key_size < 2048:
            raise ValueError("RSA keys smaller than 2048 bits are refused.")
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        if public_key.curve.name not in ("secp256r1", "secp384r1", "secp521r1"):
            raise ValueError("Only the P-256, P-384 and P-521 curves are accepted.")
    elif not isinstance(public_key, ed25519.Ed25519PublicKey):
        raise ValueError("Unsupported public key type in the request.")


class PKILab:
    def __init__(self, layout: Optional[Layout] = None, password: Optional[bytes] = None):
        self.layout = initialize_layout(layout or current_layout())
        AppLog.setup(self.layout)
        self.db = Database(self.layout.db_path)
        self._password = password

    def close(self) -> None:
        self.db.close()

    def ca_paths(self, level: str):
        return (self.layout.pki["ca"] / f"{level}-ca.pem", self.layout.pki["private"] / f"{level}-ca-key.pem")

    def _read_key(self, path: Path):
        return read_private_key(path, self._password)

    def _write_key(self, key, path: Path):
        return write_private_key(key, path, self._password)

    def _ca_pair(self, level: str):
        cert_path, key_path = self.ca_paths(level)
        if not cert_path.exists() or not key_path.exists():
            raise RuntimeError("Create the Root CA and Intermediate CA first." if level == "intermediate"
                               else "Create the Root CA first.")
        return load_cert(cert_path), self._read_key(key_path)

    def _ca_extensions(self, builder, key, path_length, issuer_key=None):
        builder = (builder
                   .add_extension(x509.BasicConstraints(ca=True, path_length=path_length), True)
                   .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                                key_encipherment=False, data_encipherment=False,
                                                key_agreement=False, key_cert_sign=True, crl_sign=True,
                                                encipher_only=False, decipher_only=False), True)
                   .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False))
        if issuer_key is not None:
            builder = builder.add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), False)
        return builder

    def create_root(self, cn: str = "ChrisSandor CADLab Root CA", years: int = 10, org: str = ORG) -> dict:
        cert_path, key_path = self.ca_paths("root")
        if cert_path.exists() or key_path.exists():
            raise RuntimeError("Root CA already exists. Refusing to overwrite it.")
        if not cn:
            raise ValueError("A common name is required.")
        if not 1 <= int(years) <= 30:
            raise ValueError("Root validity must be 1-30 years.")
        key, now, name = new_rsa_key(), utcnow(), make_name(cn, org)
        builder = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                   .public_key(key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(now - CLOCK_SKEW).not_valid_after(now + timedelta(days=365 * int(years))))
        cert = self._ca_extensions(builder, key, 1).sign(key, hashes.SHA256())
        self._write_key(key, key_path)
        atomic_write(cert_path, cert_pem(cert), 0o644)
        AppLog.event("root_ca_created", subject=cn, serial=format(cert.serial_number, "x"))
        return {"kind": "root", "subject": describe(cert), "cert_path": str(cert_path), "key_path": str(key_path),
                "not_after": iso(cert.not_valid_after_utc), "serial": format(cert.serial_number, "x")}

    def create_intermediate(self, cn: str = "ChrisSandor CADLab Issuing CA", years: int = 5, org: str = ORG) -> dict:
        root, root_key = self._ca_pair("root")
        cert_path, key_path = self.ca_paths("intermediate")
        if cert_path.exists() or key_path.exists():
            raise RuntimeError("Intermediate CA already exists; refusing overwrite.")
        if not cn:
            raise ValueError("A common name is required.")
        if not 1 <= int(years) <= 10:
            raise ValueError("Intermediate validity must be 1-10 years.")
        key, now = new_rsa_key(), utcnow()
        builder = (x509.CertificateBuilder().subject_name(make_name(cn, org)).issuer_name(root.subject)
                   .public_key(key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(now - CLOCK_SKEW)
                   .not_valid_after(min(now + timedelta(days=365 * int(years)), root.not_valid_after_utc)))
        cert = self._ca_extensions(builder, key, 0, root_key).sign(root_key, hashes.SHA256())
        self._write_key(key, key_path)
        atomic_write(cert_path, cert_pem(cert), 0o644)
        AppLog.event("intermediate_ca_created", subject=cn, serial=format(cert.serial_number, "x"))
        return {"kind": "intermediate", "subject": describe(cert), "cert_path": str(cert_path),
                "key_path": str(key_path), "not_after": iso(cert.not_valid_after_utc),
                "serial": format(cert.serial_number, "x")}

    def _build_leaf(self, subject, public_key, issuer, issuer_key, days: int, kind: str, sans):
        if kind not in KINDS:
            raise ValueError("Certificate kind must be 'server' or 'client'.")
        if not 1 <= int(days) <= 825:
            raise ValueError("Leaf certificate validity must be 1-825 days.")
        now = utcnow()
        builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer.subject)
                   .public_key(public_key).serial_number(x509.random_serial_number())
                   .not_valid_before(now - CLOCK_SKEW)
                   .not_valid_after(min(now + timedelta(days=int(days)), issuer.not_valid_after_utc))
                   .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
                   .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), False)
                   .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), False)
                   .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                                key_encipherment=isinstance(public_key, rsa.RSAPublicKey),
                                                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                                                crl_sign=False, encipher_only=False, decipher_only=False), True)
                   .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH if kind == "server"
                                                         else ExtendedKeyUsageOID.CLIENT_AUTH]), False))
        if sans:
            builder = builder.add_extension(x509.SubjectAlternativeName(sans), False)
        return builder.sign(issuer_key, hashes.SHA256())

    def _store_leaf(self, cert, kind: str, issuer, cn: str, key_path: Optional[Path]) -> dict:
        serial = format(cert.serial_number, "x")
        stem = f"{kind}-{safe_component(cn, 36)}-{serial[:12]}"
        issued = self.layout.pki["issued"]
        cert_path, chain_path = issued / f"{stem}.pem", issued / f"{stem}-chain.pem"
        atomic_write(cert_path, cert_pem(cert), 0o644)
        atomic_write(chain_path, cert_pem(cert) + cert_pem(issuer), 0o644)
        self.db.execute("""INSERT INTO certificates(serial,common_name,kind,issuer,not_before,not_after,cert_path,
                           key_path,status,revoked_at,reason,fingerprint_sha256,created_at)
                           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (serial, cn, kind, issuer.subject.rfc4514_string(), iso(cert.not_valid_before_utc),
                         iso(cert.not_valid_after_utc), str(cert_path), str(key_path) if key_path else None,
                         "VALID", None, None, fingerprint(cert), iso(utcnow())))
        self.db.commit()
        AppLog.event("certificate_issued", serial=serial, kind=kind, subject=cert.subject.rfc4514_string(),
                     fingerprint_sha256=fingerprint(cert))
        return {"serial": serial, "kind": kind, "common_name": cn, "cert_path": str(cert_path),
                "chain_path": str(chain_path), "key_path": str(key_path) if key_path else None,
                "not_after": iso(cert.not_valid_after_utc), "sans": san_strings(cert)}

    def issue(self, kind: str, cn: str, days: int = 397, org: str = ORG, sans=None) -> dict:
        if not cn:
            raise ValueError("A common name is required.")
        issuer, issuer_key = self._ca_pair("intermediate")
        names = parse_sans(sans)
        if kind == "server" and not names:
            names = parse_sans([cn])
        key = new_rsa_key()
        cert = self._build_leaf(make_name(cn, org), key.public_key(), issuer, issuer_key, days, kind, names)
        serial = format(cert.serial_number, "x")
        key_path = self.layout.pki["private"] / f"{kind}-{safe_component(cn, 36)}-{serial[:12]}-key.pem"
        self._write_key(key, key_path)
        return self._store_leaf(cert, kind, issuer, cn, key_path)

    def sign_csr(self, csr_pem: bytes, kind: str = "client", days: int = 397, copy_san: bool = False) -> dict:
        try:
            csr = x509.load_pem_x509_csr(csr_pem)
        except ValueError as error:
            raise ValueError("That is not a valid PEM certificate request.") from error
        if not csr.is_signature_valid:
            raise ValueError("The certificate request signature is invalid.")
        check_requested_key(csr.public_key())
        names = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if not names:
            raise ValueError("The request has no common name.")
        cn = names[0].value
        issuer, issuer_key = self._ca_pair("intermediate")
        sans: List[x509.GeneralName] = []
        if copy_san:
            try:
                requested = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
                sans = [x509.DNSName(v) for v in requested.get_values_for_type(x509.DNSName)]
                sans += [x509.IPAddress(v) for v in requested.get_values_for_type(x509.IPAddress)]
            except x509.ExtensionNotFound:
                sans = []
        if kind == "server" and not sans:
            sans = parse_sans([cn])
        cert = self._build_leaf(csr.subject, csr.public_key(), issuer, issuer_key, days, kind, sans)
        AppLog.event("csr_signed", subject=csr.subject.rfc4514_string(), kind=kind)
        return self._store_leaf(cert, kind, issuer, cn, None)

    def _row(self, serial: str):
        wanted = normalize_serial(serial)
        row = self.db.execute("SELECT * FROM certificates WHERE serial=?", (wanted,)).fetchone()
        if row:
            return row
        matches = self.db.execute("SELECT * FROM certificates WHERE serial LIKE ?", (wanted + "%",)).fetchall()
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            raise ValueError("That serial prefix matches more than one certificate; type more digits.")
        raise ValueError("Certificate not found in the inventory.")

    def list_certificates(self) -> List[dict]:
        return [dict(r) for r in self.db.execute("SELECT * FROM certificates ORDER BY not_after").fetchall()]

    def inspect(self, serial: str) -> dict:
        row = self._row(serial)
        cert = load_cert(Path(row["cert_path"]))
        usage = []
        try:
            usage = [getattr(o, '_name', o.dotted_string) for o in cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value]
        except x509.ExtensionNotFound:
            pass
        public = cert.public_key()
        size = getattr(public, "key_size", None)
        return {"subject": cert.subject.rfc4514_string(), "issuer": cert.issuer.rfc4514_string(),
                "serial": format(cert.serial_number, "x"), "sha256": fingerprint(cert),
                "not_before": iso(cert.not_valid_before_utc), "not_after": iso(cert.not_valid_after_utc),
                "status": row["status"], "kind": row["kind"], "san": san_strings(cert),
                "extended_key_usage": usage, "key": f"{type(public).__name__} {size or ''}".strip(),
                "reason": row["reason"], "has_private_key": bool(row["key_path"])}

    def revoke(self, serial: str, reason: str = "unspecified") -> dict:
        row = self._row(serial)
        if reason not in REASONS:
            raise ValueError("Unsupported revocation reason. Choose one of: " + ", ".join(REASONS))
        if row["status"] == "REVOKED":
            return {"serial": row["serial"], "already": True}
        self.db.execute("UPDATE certificates SET status='REVOKED',revoked_at=?,reason=? WHERE serial=?",
                        (iso(utcnow()), reason, row["serial"]))
        self.db.commit()
        AppLog.event("certificate_revoked", serial=row["serial"], reason=reason)
        return {"serial": row["serial"], "already": False, "reason": reason}

    def _next_crl_number(self) -> int:
        row = self.db.execute("SELECT value FROM meta WHERE key='crl_number'").fetchone()
        number = (int(row["value"]) if row else 0) + 1
        self.db.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('crl_number',?)", (str(number),))
        self.db.commit()
        return number

    def crl_path(self) -> Path:
        return self.layout.pki["crl"] / "intermediate-ca.crl.pem"

    def generate_crl(self, days: int = 7) -> dict:
        issuer, key = self._ca_pair("intermediate")
        now = utcnow()
        number = self._next_crl_number()
        builder = (x509.CertificateRevocationListBuilder().issuer_name(issuer.subject)
                   .last_update(now).next_update(now + timedelta(days=days))
                   .add_extension(x509.CRLNumber(number), False)
                   .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), False))
        rows = self.db.execute("SELECT * FROM certificates WHERE status='REVOKED'").fetchall()
        for row in rows:
            reason = getattr(x509.ReasonFlags, row["reason"] or "unspecified", x509.ReasonFlags.unspecified)
            builder = builder.add_revoked_certificate(
                x509.RevokedCertificateBuilder().serial_number(int(row["serial"], 16))
                .revocation_date(datetime.fromisoformat(row["revoked_at"]))
                .add_extension(x509.CRLReason(reason), False).build())
        crl = builder.sign(key, hashes.SHA256())
        output = self.crl_path()
        atomic_write(output, crl.public_bytes(serialization.Encoding.PEM), 0o644)
        AppLog.event("crl_generated", path=str(output), revoked_count=len(rows), number=number,
                     next_update=iso(now + timedelta(days=days)))
        return {"path": str(output), "revoked": len(rows), "number": number, "next_update": iso(now + timedelta(days=days))}

    def verify(self, serial: str) -> dict:
        row = self._row(serial)
        if row["status"] != "VALID":
            raise ValueError("Certificate is not valid in the local inventory (status: %s)." % row["status"])
        leaf = load_cert(Path(row["cert_path"]))
        root_path, _ = self.ca_paths("root")
        int_path, _ = self.ca_paths("intermediate")
        crls = []
        if self.crl_path().exists():
            crls.append(x509.load_pem_x509_crl(self.crl_path().read_bytes()))
        result = verify_chain(leaf, [load_cert(int_path)], [load_cert(root_path)], crls)
        newest = self.db.execute("SELECT MAX(revoked_at) AS m FROM certificates WHERE status='REVOKED'").fetchone()["m"]
        if crls and newest and crls[0].last_update_utc < datetime.fromisoformat(newest):
            result["warnings"].append("the revocation list is older than the newest revocation; regenerate it")
        AppLog.event("certificate_verified", serial=row["serial"], result="VALID")
        return result

    def renew(self, serial: str, revoke_old: bool = False, days: Optional[int] = None) -> dict:
        row = self._row(serial)
        if row["status"] != "VALID":
            raise ValueError("Only a currently valid inventory certificate can be renewed.")
        if not row["key_path"]:
            raise ValueError("That certificate was issued from a request; submit a new request instead of renewing.")
        old = load_cert(Path(row["cert_path"]))
        lifetime = days or max(1, min(825, round((old.not_valid_after_utc - old.not_valid_before_utc).days)))
        organization = old.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        new = self.issue(row["kind"], row["common_name"], lifetime,
                         organization[0].value if organization else ORG, san_strings(old))
        if revoke_old:
            self.revoke(row["serial"], "superseded")
            AppLog.event("certificate_superseded", old_serial=row["serial"], new_serial=new["serial"])
        return {"old_serial": row["serial"], "new": new, "old_revoked": revoke_old}

    def export_chain(self, serial: str) -> dict:
        row = self._row(serial)
        int_path, _ = self.ca_paths("intermediate")
        root_path, _ = self.ca_paths("root")
        if not int_path.exists() or not root_path.exists():
            raise RuntimeError("CA chain files are missing.")
        output = self.layout.pki["exports"] / f"{row['serial']}-chain.pem"
        atomic_write(output, Path(row["cert_path"]).read_bytes() + int_path.read_bytes() + root_path.read_bytes(), 0o644)
        AppLog.event("public_chain_exported", serial=row["serial"], path=str(output))
        return {"path": str(output)}

    def expiry_report(self) -> List[dict]:
        now = utcnow()
        report = []
        for row in self.db.execute("SELECT * FROM certificates WHERE status='VALID' ORDER BY not_after").fetchall():
            expiry = datetime.fromisoformat(row["not_after"])
            report.append({"serial": row["serial"], "common_name": row["common_name"], "days": (expiry - now).days,
                           "not_after": expiry.date().isoformat()})
        AppLog.event("expiry_report_viewed", count=len(report))
        return report

    def ca_status(self) -> dict:
        status = {}
        for level in ("root", "intermediate"):
            cert_path, key_path = self.ca_paths(level)
            if cert_path.exists():
                cert = load_cert(cert_path)
                status[level] = {"subject": cert.subject.rfc4514_string(), "not_after": iso(cert.not_valid_after_utc),
                                 "key_present": key_path.exists(), "sha256": fingerprint(cert)}
            else:
                status[level] = None
        return status

    def audit_verify(self) -> dict:
        return AppLog.audit.verify()

    def audit_export(self) -> Path:
        source = self.layout.audit_path
        if not source.exists():
            raise RuntimeError("No audit log exists yet.")
        target = self.layout.dirs["exports"] / ("pki-audit-%s.csv" % utcnow().strftime("%Y%m%d-%H%M%S"))
        with source.open(encoding="utf-8") as src, target.open("w", newline="", encoding="utf-8") as out:
            writer = csv.writer(out)
            writer.writerow(["timestamp", "action", "details"])
            for line in src:
                try:
                    record = json.loads(line)
                except ValueError:
                    continue
                timestamp, action = record.pop("timestamp", ""), record.pop("action", "")
                writer.writerow([timestamp, action, json.dumps(record, sort_keys=True)])
        return target
