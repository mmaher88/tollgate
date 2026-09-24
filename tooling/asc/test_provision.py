import datetime as dt
import plistlib
import subprocess

import jwt
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

import provision


@pytest.fixture
def ec_key_pem():
    key = ec.generate_private_key(ec.SECP256R1())
    return key, key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )


def test_team_token_claims(ec_key_pem):
    key, pem = ec_key_pem
    now = dt.datetime(2026, 9, 24, 12, 0, tzinfo=dt.timezone.utc)
    token = provision.make_token("KEY123", "issuer-uuid", pem, now)
    header = jwt.get_unverified_header(token)
    assert header == {"alg": "ES256", "kid": "KEY123", "typ": "JWT"}
    claims = jwt.decode(token, key.public_key(), algorithms=["ES256"], audience="appstoreconnect-v1",
                        options={"verify_exp": False})
    assert claims["iss"] == "issuer-uuid"
    assert claims["exp"] - claims["iat"] == 15 * 60
    assert "sub" not in claims


def test_individual_token_uses_sub(ec_key_pem):
    key, pem = ec_key_pem
    token = provision.make_token("KEY123", "", pem, dt.datetime.now(dt.timezone.utc))
    claims = jwt.decode(token, key.public_key(), algorithms=["ES256"], audience="appstoreconnect-v1")
    assert claims["sub"] == "user"
    assert "iss" not in claims


def test_csr_is_rsa_2048_with_common_name():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = provision.make_csr(key, "Tollgate CI")
    csr = x509.load_pem_x509_csr(pem.encode())
    assert csr.is_signature_valid
    assert csr.public_key().key_size == 2048
    assert csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "Tollgate CI"


def self_signed(key):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Apple Development: Test")])
    now = dt.datetime.now(dt.timezone.utc)
    return (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(now).not_valid_after(now + dt.timedelta(days=1))
            .sign(key, hashes.SHA256()))


def test_p12_roundtrip_and_legacy_algorithms(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = self_signed(key)
    blob = provision.make_p12(key, cert.public_bytes(serialization.Encoding.DER), "s3cret")
    loaded_key, loaded_cert, _ = pkcs12.load_key_and_certificates(blob, b"s3cret")
    assert loaded_cert == cert
    assert loaded_key.private_numbers() == key.private_numbers()
    # macOS `security import` needs SHA1/3DES PKCS#12, not the OpenSSL 3 AES default.
    p = tmp_path / "c.p12"
    p.write_bytes(blob)
    info = subprocess.run(["openssl", "pkcs12", "-in", str(p), "-info", "-noout", "-passin", "pass:s3cret", "-legacy"],
                          capture_output=True, text=True)
    assert "pbeWithSHA1And3-KeyTripleDES-CBC" in info.stderr + info.stdout


def test_profile_plist_extracts_embedded_xml():
    inner = {"Name": "Tollgate App Dev", "TeamIdentifier": ["ABCDE12345"],
             "Entitlements": {"com.apple.security.application-groups": ["group.x"]}}
    blob = b"\x30\x82junk" + plistlib.dumps(inner) + b"\x00trailing-signature"
    assert provision.profile_plist(blob)["TeamIdentifier"] == ["ABCDE12345"]


def test_load_config_reads_quoted_values(tmp_path):
    p = tmp_path / "config.env"
    p.write_text('# comment\nTOLLGATE_BUNDLE_ID="io.example.app"\nTOLLGATE_APP_PROFILE="Tollgate App Dev"\n')
    assert provision.load_config(p) == {"TOLLGATE_BUNDLE_ID": "io.example.app",
                                        "TOLLGATE_APP_PROFILE": "Tollgate App Dev"}
