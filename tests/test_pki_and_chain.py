import shutil
import subprocess
from datetime import timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from cadlab.chain import ChainError, verify_chain
from cadlab.keys import load_cert, new_ec_key
from cadlab.pki import PKILab, check_requested_key, normalize_serial, parse_sans
from cadlab.platform_support import utcnow


def csr_pem(key, cn="requester", sans=None):
    builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
    if sans:
        builder = builder.add_extension(x509.SubjectAlternativeName(sans), False)
    algorithm = hashes.SHA256()
    return builder.sign(key, algorithm).public_bytes(serialization.Encoding.PEM)


def test_lifecycle_inventory_and_files(lab):
    server = lab.issue("server", "app.test", 90, sans=["app.test", "10.1.2.3"])
    client = lab.issue("client", "alice", 30)
    assert Path(server["key_path"]).exists() and b"ENCRYPTED" in Path(server["key_path"]).read_bytes()
    assert server["sans"] == ["app.test", "10.1.2.3"]
    assert {r["serial"] for r in lab.list_certificates()} == {server["serial"], client["serial"]}
    assert lab.ca_status()["root"]["key_present"]


def test_server_certificate_always_gets_a_san(lab):
    data = lab.issue("server", "host.test")
    assert data["sans"] == ["host.test"]


def test_ca_constraints_are_correct(lab):
    root = load_cert(lab.ca_paths("root")[0])
    inter = load_cert(lab.ca_paths("intermediate")[0])
    assert root.extensions.get_extension_for_class(x509.BasicConstraints).value.path_length == 1
    assert inter.extensions.get_extension_for_class(x509.BasicConstraints).value.path_length == 0
    assert inter.issuer == root.subject


def test_refuses_to_overwrite_authorities(lab):
    with pytest.raises(RuntimeError):
        lab.create_root()
    with pytest.raises(RuntimeError):
        lab.create_intermediate()


def test_intermediate_needs_root(layout):
    lab = PKILab(layout)
    try:
        with pytest.raises(RuntimeError):
            lab.create_intermediate()
        with pytest.raises(RuntimeError):
            lab.issue("server", "x.test")
    finally:
        lab.close()


def test_verify_revoke_crl_roundtrip(lab):
    data = lab.issue("client", "bob")
    assert lab.verify(data["serial"])["path"][-1].startswith("CN=ChrisSandor CADLab Root CA")
    lab.revoke(data["serial"], "key_compromise")
    with pytest.raises(ValueError):
        lab.verify(data["serial"])
    crl = lab.generate_crl()
    parsed = x509.load_pem_x509_crl(Path(crl["path"]).read_bytes())
    assert [e.serial_number for e in parsed] == [int(data["serial"], 16)]
    assert parsed.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number == crl["number"]
    assert lab.generate_crl()["number"] == crl["number"] + 1


def test_revoke_twice_and_bad_reason(lab):
    data = lab.issue("client", "carol")
    assert lab.revoke(data["serial"], "superseded")["already"] is False
    assert lab.revoke(data["serial"])["already"] is True
    other = lab.issue("client", "dave")
    with pytest.raises(ValueError):
        lab.revoke(other["serial"], "because")


def test_stale_crl_warning(lab):
    first = lab.issue("client", "erin")
    lab.generate_crl()
    second = lab.issue("client", "frank")
    lab.revoke(first["serial"])
    assert lab.verify(second["serial"])["warnings"]


def test_serial_prefix_lookup(lab):
    data = lab.issue("client", "gina")
    assert lab.inspect(data["serial"][:10])["serial"] == data["serial"]
    assert lab.inspect("0x" + data["serial"].upper())["serial"] == data["serial"]
    with pytest.raises(ValueError):
        lab.inspect("zzzz")
    with pytest.raises(ValueError):
        lab.inspect("abcdef0123456789abcdef")


def test_renew_keeps_names_and_can_supersede(lab):
    old = lab.issue("server", "api.test", 60, sans=["api.test", "api2.test"])
    result = lab.renew(old["serial"], revoke_old=True)
    assert result["new"]["serial"] != old["serial"]
    assert result["new"]["sans"] == ["api.test", "api2.test"]
    assert lab.inspect(old["serial"])["status"] == "REVOKED"
    assert lab.inspect(old["serial"])["reason"] == "superseded"


def test_cannot_renew_csr_issued_certificate(lab):
    key = new_ec_key()
    data = lab.sign_csr(csr_pem(key), "client")
    with pytest.raises(ValueError):
        lab.renew(data["serial"])


def test_sign_csr_ec_and_rsa(lab):
    for key in (new_ec_key(), rsa.generate_private_key(public_exponent=65537, key_size=2048)):
        data = lab.sign_csr(csr_pem(key, cn="device-%s" % type(key).__name__[:6]), "client", 30)
        cert = load_cert(data["cert_path"])
        assert cert.public_key().public_numbers() == key.public_key().public_numbers()
        assert data["key_path"] is None


def test_sign_csr_ignores_requested_sans_unless_asked(lab):
    key = new_ec_key()
    request = csr_pem(key, cn="svc", sans=[x509.DNSName("evil.example")])
    assert lab.sign_csr(request, "client")["sans"] == []
    assert lab.sign_csr(csr_pem(new_ec_key(), cn="svc2", sans=[x509.DNSName("ok.test")]), "client", copy_san=True)["sans"] == ["ok.test"]


def test_sign_csr_rejects_weak_or_broken_requests(lab):
    weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    with pytest.raises(ValueError):
        lab.sign_csr(csr_pem(weak), "client")
    with pytest.raises(ValueError):
        lab.sign_csr(b"not a csr", "client")
    with pytest.raises(ValueError):
        check_requested_key(ec.generate_private_key(ec.SECP256K1()).public_key())


def test_validity_limits(lab):
    with pytest.raises(ValueError):
        lab.issue("client", "long", 826)
    with pytest.raises(ValueError):
        lab.issue("client", "zero", 0)
    with pytest.raises(ValueError):
        lab.issue("bogus", "x")


def test_parse_sans_validation():
    assert len(parse_sans(["a.test", "1.2.3.4", "::1", "*.wild.test"])) == 4
    for bad in ("bad name", "-x.test", "a..b", "x" * 300):
        with pytest.raises(ValueError):
            parse_sans([bad])


def test_normalize_serial():
    assert normalize_serial(" 0xABC ") == "abc"
    with pytest.raises(ValueError):
        normalize_serial("")


def test_wrong_password_is_reported_clearly(layout, monkeypatch):
    lab = PKILab(layout)
    lab.create_root()
    lab.create_intermediate()
    monkeypatch.setenv("CADLAB_PASSWORD", "a different long password")
    other = PKILab(layout, password=None)
    try:
        with pytest.raises(ValueError, match="wrong password"):
            other.issue("client", "x")
    finally:
        lab.close()
        other.close()


def test_export_chain_has_three_certificates_and_no_key(lab):
    data = lab.issue("server", "chain.test")
    path = Path(lab.export_chain(data["serial"])["path"])
    text = path.read_text(encoding="ascii")
    assert text.count("BEGIN CERTIFICATE") == 3 and "PRIVATE KEY" not in text


def test_expiry_report(lab):
    lab.issue("client", "soon", 10)
    rows = lab.expiry_report()
    assert rows[0]["common_name"] == "soon" and 8 <= rows[0]["days"] <= 10


def test_audit_trail_covers_the_lifecycle(lab):
    lab.issue("client", "audited")
    result = lab.audit_verify()
    assert result["ok"] and result["records"] >= 3
    assert Path(lab.audit_export()).exists()


def test_chain_verifier_failure_modes(lab):
    leaf = load_cert(lab.issue("client", "who")["cert_path"])
    inter = load_cert(lab.ca_paths("intermediate")[0])
    root = load_cert(lab.ca_paths("root")[0])
    assert verify_chain(leaf, [inter], [root])["revocation_checked"] is False
    with pytest.raises(ChainError, match="no trusted root"):
        verify_chain(leaf, [inter], [])
    with pytest.raises(ChainError, match="no trusted issuer"):
        verify_chain(leaf, [], [root])
    with pytest.raises(ChainError, match="expired"):
        verify_chain(leaf, [inter], [root], now=utcnow() + timedelta(days=5000))
    with pytest.raises(ChainError, match="not valid until"):
        verify_chain(leaf, [inter], [root], now=utcnow() - timedelta(days=5))


def test_other_root_is_not_trusted(tmp_path, monkeypatch, lab):
    leaf = load_cert(lab.issue("client", "who2")["cert_path"])
    inter = load_cert(lab.ca_paths("intermediate")[0])
    monkeypatch.setenv("CADLAB_HOME", str(tmp_path / "other"))
    from cadlab.platform_support import current_layout, initialize_layout
    other = PKILab(initialize_layout(current_layout()))
    try:
        other.create_root(cn="Some Other Root")
        stranger = load_cert(other.ca_paths("root")[0])
    finally:
        other.close()
    with pytest.raises(ChainError):
        verify_chain(leaf, [inter], [stranger])


def test_leaf_cannot_masquerade_as_ca(lab):
    leaf = load_cert(lab.issue("client", "pretender")["cert_path"])
    inter = load_cert(lab.ca_paths("intermediate")[0])
    root = load_cert(lab.ca_paths("root")[0])
    fake_leaf_key = new_ec_key()
    fake = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fake")]))
            .issuer_name(leaf.subject).public_key(fake_leaf_key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(utcnow() - timedelta(days=1))
            .not_valid_after(utcnow() + timedelta(days=1)))
    lab_key = None
    from cadlab.keys import read_private_key
    leaf_key_path = [r["key_path"] for r in lab.list_certificates() if r["common_name"] == "pretender"][0]
    lab_key = read_private_key(Path(leaf_key_path))
    child = fake.sign(lab_key, hashes.SHA256())
    with pytest.raises(ChainError, match="not marked as a CA"):
        verify_chain(child, [leaf, inter], [root])


def test_revocation_list_is_enforced_by_chain_verifier(lab):
    data = lab.issue("client", "revoked-one")
    lab.revoke(data["serial"])
    crl = x509.load_pem_x509_crl(Path(lab.generate_crl()["path"]).read_bytes())
    leaf = load_cert(data["cert_path"])
    inter = load_cert(lab.ca_paths("intermediate")[0])
    root = load_cert(lab.ca_paths("root")[0])
    with pytest.raises(ChainError, match="revoked"):
        verify_chain(leaf, [inter], [root], [crl])
    good = load_cert(lab.issue("client", "fine-one")["cert_path"])
    assert verify_chain(good, [inter], [root], [crl])["revocation_checked"] is True


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl not installed")
def test_openssl_accepts_our_chain_and_our_crl(lab, tmp_path):
    good = lab.issue("server", "interop.test")
    bad = lab.issue("server", "dead.test")
    lab.revoke(bad["serial"])
    lab.generate_crl()
    root, inter = lab.ca_paths("root")[0], lab.ca_paths("intermediate")[0]
    crl = lab.crl_path()
    bundle = tmp_path / "bundle.pem"
    bundle.write_bytes(root.read_bytes() + crl.read_bytes())

    def verify(leaf):
        return subprocess.run(["openssl", "verify", "-crl_check", "-CAfile", str(bundle), "-untrusted", str(inter),
                               leaf["cert_path"]], capture_output=True, text=True)

    ok = verify(good)
    assert ok.returncode == 0 and "OK" in ok.stdout, ok.stdout + ok.stderr
    revoked = verify(bad)
    assert revoked.returncode != 0 and "revoked" in (revoked.stdout + revoked.stderr).lower()
