from __future__ import annotations

from datetime import datetime
from typing import Iterable, List, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from .platform_support import utcnow

MAX_DEPTH = 6


class ChainError(ValueError):
    pass


def fingerprint(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


def describe(cert: x509.Certificate) -> str:
    return cert.subject.rfc4514_string() or "(empty subject)"


def _basic_constraints(cert):
    try:
        return cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound:
        return None


def _key_usage(cert):
    try:
        return cert.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        return None


def _check_dates(cert, label: str, now: datetime) -> None:
    if now < cert.not_valid_before_utc:
        raise ChainError(f"{label} certificate is not valid until {cert.not_valid_before_utc.isoformat()}: {describe(cert)}")
    if now > cert.not_valid_after_utc:
        raise ChainError(f"{label} certificate expired on {cert.not_valid_after_utc.isoformat()}: {describe(cert)}")


def _signed_by(cert, issuer) -> bool:
    try:
        cert.verify_directly_issued_by(issuer)
        return True
    except Exception:
        return False


def build_path(leaf, intermediates: Iterable, roots: Iterable) -> List:
    roots = list(roots)
    pool = list(intermediates)
    anchors = {fingerprint(root): root for root in roots}
    path = [leaf]
    current = leaf
    if fingerprint(leaf) in anchors:
        return path
    for _ in range(MAX_DEPTH):
        own = fingerprint(current)
        candidates = [c for c in roots + pool if c.subject == current.issuer and fingerprint(c) != own]
        issuer = next((c for c in candidates if _signed_by(current, c)), None)
        if issuer is None:
            if current.subject == current.issuer:
                raise ChainError(f"self-signed certificate is not a trusted root: {describe(current)}")
            raise ChainError(f"no trusted issuer found for {describe(current)}; check the intermediate and root files")
        path.append(issuer)
        if fingerprint(issuer) in anchors:
            return path
        current = issuer
    raise ChainError("certificate chain is longer than the supported depth")


def verify_chain(leaf, intermediates: Iterable = (), roots: Iterable = (), crls: Iterable = (),
                 now: Optional[datetime] = None, require_signing: bool = True) -> dict:
    now = now or utcnow()
    roots = list(roots)
    if not roots:
        raise ChainError("no trusted root certificate was supplied")
    path = build_path(leaf, intermediates, roots)
    warnings: List[str] = []
    if len(path) == 1:
        warnings.append("the certificate is itself a pinned trust anchor")
    for index, cert in enumerate(path):
        label = "leaf" if index == 0 else ("root" if index == len(path) - 1 else "intermediate")
        _check_dates(cert, label, now)
        constraints = _basic_constraints(cert)
        usage = _key_usage(cert)
        if index > 0:
            if constraints is None or not constraints.ca:
                raise ChainError(f"{label} certificate is not marked as a CA: {describe(cert)}")
            if usage is not None and not usage.key_cert_sign:
                raise ChainError(f"{label} certificate may not sign certificates: {describe(cert)}")
            allowed = constraints.path_length
            below = index - 1
            if allowed is not None and below > allowed:
                raise ChainError(f"{label} certificate path length limit {allowed} exceeded: {describe(cert)}")
        else:
            if constraints is not None and constraints.ca and len(path) > 1:
                raise ChainError(f"leaf certificate is marked as a CA: {describe(cert)}")
            if require_signing and usage is not None and not usage.digital_signature:
                raise ChainError(f"leaf certificate key usage does not allow digital signatures: {describe(cert)}")
    anchor = path[-1]
    if len(path) > 1 and not _signed_by(anchor, anchor):
        warnings.append("the trust anchor's own signature could not be confirmed (not self-signed)")
    covered = False
    for position in range(len(path) - 1):
        subject_cert, issuer_cert = path[position], path[position + 1]
        for crl in crls:
            if crl.issuer != issuer_cert.subject:
                continue
            try:
                valid = crl.is_signature_valid(issuer_cert.public_key())
            except Exception:
                valid = False
            if not valid:
                raise ChainError(f"revocation list signature is invalid for issuer {describe(issuer_cert)}")
            expires = crl.next_update_utc
            if expires is not None and expires < now:
                raise ChainError(f"revocation list for {describe(issuer_cert)} expired on {expires.isoformat()}; regenerate it")
            entry = crl.get_revoked_certificate_by_serial_number(subject_cert.serial_number)
            if entry is not None:
                raise ChainError(f"certificate is revoked: {describe(subject_cert)}")
            if position == 0:
                covered = True
    if not covered:
        warnings.append("no revocation list was supplied for the leaf's issuer, so revocation was not checked")
    return {"path": [describe(c) for c in path], "anchor": describe(anchor), "warnings": warnings, "revocation_checked": covered}
