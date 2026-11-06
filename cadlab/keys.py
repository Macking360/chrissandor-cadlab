from __future__ import annotations

from pathlib import Path
from typing import Optional, Tuple

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

from .platform_support import atomic_write, get_password

RSA_SHA256 = "rsa-pkcs1v15-sha256"
ECDSA_SHA256 = "ecdsa-sha256"
ED25519 = "ed25519"


def new_rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=3072)


def new_ec_key():
    return ec.generate_private_key(ec.SECP256R1())


def write_private_key(key, path: Path, password: Optional[bytes] = None) -> Path:
    secret = password if password is not None else get_password(confirm_entry=True)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.BestAvailableEncryption(secret))
    atomic_write(path, pem, 0o600)
    return Path(path)


def read_private_key(path: Path, password: Optional[bytes] = None):
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Private key not found: {path}")
    data = path.read_bytes()
    encrypted = b"ENCRYPTED" in data
    secret = password if password is not None else (get_password(prompt=f"Password for {path.name}") if encrypted else None)
    try:
        return serialization.load_pem_private_key(data, password=secret)
    except (ValueError, TypeError) as error:
        raise ValueError(f"Could not open {path.name}: wrong password or damaged key file.") from error


def load_cert(path: Path) -> x509.Certificate:
    return x509.load_pem_x509_certificate(Path(path).read_bytes())


def load_certs(path: Path):
    data = Path(path).read_bytes()
    return x509.load_pem_x509_certificates(data)


def cert_pem(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def public_der(public_key) -> bytes:
    return public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def sign_bytes(key, data: bytes) -> Tuple[str, bytes]:
    if isinstance(key, rsa.RSAPrivateKey):
        return RSA_SHA256, key.sign(data, padding.PKCS1v15(), hashes.SHA256())
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return ECDSA_SHA256, key.sign(data, ec.ECDSA(hashes.SHA256()))
    if isinstance(key, ed25519.Ed25519PrivateKey):
        return ED25519, key.sign(data)
    raise TypeError("Unsupported private key type.")


def verify_bytes(public_key, algorithm: str, signature: bytes, data: bytes) -> bool:
    try:
        if algorithm == RSA_SHA256 and isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
        elif algorithm == ECDSA_SHA256 and isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        elif algorithm == ED25519 and isinstance(public_key, ed25519.Ed25519PublicKey):
            public_key.verify(signature, data)
        else:
            return False
        return True
    except InvalidSignature:
        return False
