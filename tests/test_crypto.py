"""Unit tests for pkicore.crypto + the software KMS backend: end-to-end
build-a-root-CA / issue-a-leaf / build-CRL / build-OCSP-response, all using
real ASN.1 encoding and real signature verification (via `cryptography`).
"""
from __future__ import annotations

import base64
import datetime as dt
import os

import pytest
from cryptography import x509 as c_x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

os.environ.setdefault("PKICA_ALLOW_SOFTWARE_KMS", "true")
os.environ.setdefault("PKICA_SOFTWARE_KMS_MASTER_KEY", base64.b64encode(os.urandom(32)).decode())

from pkicore import crypto  # noqa: E402
from pkicore.kms.base import KeySpec, SignatureAlgorithm  # noqa: E402
from pkicore.kms.software import SoftwareKMSBackend  # noqa: E402

INVALID_KEY_IDS = ["../escape", "nested/key", "/tmp/escape", r"nested\key"]


@pytest.fixture()
def kms(tmp_path):
    return SoftwareKMSBackend(storage_path=str(tmp_path / "kms"))


def _verify_signature(cert: c_x509.Certificate, issuer_public_key) -> None:
    """Raises if the certificate's signature does not verify against issuer_public_key."""
    if isinstance(issuer_public_key, rsa.RSAPublicKey):
        issuer_public_key.verify(
            cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), cert.signature_hash_algorithm
        )
    else:
        issuer_public_key.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))


def test_root_ca_is_self_signed_and_verifiable(kms):
    key_id = kms.create_key(KeySpec(key_id="root", algorithm="EC_P384", label="root"))
    public_key = kms.public_key(key_id)
    algorithm = crypto.default_algorithm_for_public_key(public_key)
    assert algorithm == SignatureAlgorithm.ECDSA_SHA384

    subject = crypto.name_from_attributes({"cn": "Test Root CA", "o": "PKICA Tests"})
    ski = crypto.compute_subject_key_identifier(public_key)
    now = dt.datetime.now(dt.timezone.utc)

    extensions = crypto.build_extensions(crypto.ExtensionSpec(
        is_ca=True, key_usage={"key_cert_sign", "crl_sign"}, subject_key_id=ski, authority_key_id=ski,
    ))
    tbs = crypto.build_tbs_certificate(
        serial_number=crypto.generate_serial_number(),
        issuer_name=subject, subject_name=subject, subject_public_key=public_key,
        not_before=now, not_after=now + dt.timedelta(days=3650),
        extensions=extensions, signature_algorithm=algorithm,
    )
    der = crypto.sign_certificate(tbs, kms, key_id, algorithm)
    cert = crypto.load_certificate_der(der)

    assert cert.subject.rfc4514_string() == cert.issuer.rfc4514_string()
    basic_constraints = cert.extensions.get_extension_for_class(c_x509.BasicConstraints).value
    assert basic_constraints.ca is True
    _verify_signature(cert, public_key)  # raises cryptography.exceptions.InvalidSignature on failure


def test_issue_leaf_certificate_chains_to_ca(kms):
    ca_key_id = kms.create_key(KeySpec(key_id="ca", algorithm="EC_P256", label="ca"))
    ca_public_key = kms.public_key(ca_key_id)
    algorithm = crypto.default_algorithm_for_public_key(ca_public_key)
    issuer_name = crypto.name_from_attributes({"cn": "Test Issuing CA"})
    ca_ski = crypto.compute_subject_key_identifier(ca_public_key)
    now = dt.datetime.now(dt.timezone.utc)

    # Build a CSR for the leaf.
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        c_x509.CertificateSigningRequestBuilder()
        .subject_name(c_x509.Name([c_x509.NameAttribute(c_x509.NameOID.COMMON_NAME, "leaf.example.com")]))
        .sign(leaf_key, hashes.SHA256())
    )
    assert csr.is_signature_valid

    leaf_ski = crypto.compute_subject_key_identifier(csr.public_key())
    extensions = crypto.build_extensions(crypto.ExtensionSpec(
        is_ca=False, key_usage={"digital_signature", "key_encipherment"},
        extended_key_usage=["server_auth"], subject_alt_names=["dns:leaf.example.com"],
        subject_key_id=leaf_ski, authority_key_id=ca_ski,
    ))
    tbs = crypto.build_tbs_certificate(
        serial_number=crypto.generate_serial_number(),
        issuer_name=issuer_name, subject_name=crypto.name_from_attributes({"cn": "leaf.example.com"}),
        subject_public_key=csr.public_key(), not_before=now, not_after=now + dt.timedelta(days=90),
        extensions=extensions, signature_algorithm=algorithm,
    )
    der = crypto.sign_certificate(tbs, kms, ca_key_id, algorithm)
    leaf_cert = crypto.load_certificate_der(der)

    _verify_signature(leaf_cert, ca_public_key)
    san = leaf_cert.extensions.get_extension_for_class(c_x509.SubjectAlternativeName).value
    assert san.get_values_for_type(c_x509.DNSName) == ["leaf.example.com"]


def test_pem_roundtrip(kms):
    key_id = kms.create_key(KeySpec(key_id="root2", algorithm="EC_P256", label="root2"))
    public_key = kms.public_key(key_id)
    algorithm = crypto.default_algorithm_for_public_key(public_key)
    subject = crypto.name_from_attributes({"cn": "PEM Roundtrip CA"})
    ski = crypto.compute_subject_key_identifier(public_key)
    now = dt.datetime.now(dt.timezone.utc)
    extensions = crypto.build_extensions(crypto.ExtensionSpec(is_ca=True, subject_key_id=ski, authority_key_id=ski))
    tbs = crypto.build_tbs_certificate(
        serial_number=crypto.generate_serial_number(), issuer_name=subject, subject_name=subject,
        subject_public_key=public_key, not_before=now, not_after=now + dt.timedelta(days=1),
        extensions=extensions, signature_algorithm=algorithm,
    )
    der = crypto.sign_certificate(tbs, kms, key_id, algorithm)
    pem = crypto.der_to_pem_certificate(der)
    assert pem.startswith("-----BEGIN CERTIFICATE-----")
    reparsed = c_x509.load_pem_x509_certificate(pem.encode())
    assert reparsed.subject.rfc4514_string() == "CN=PEM Roundtrip CA"


def test_crl_and_ocsp_signing(kms):
    key_id = kms.create_key(KeySpec(key_id="ca3", algorithm="EC_P256", label="ca3"))
    public_key = kms.public_key(key_id)
    algorithm = crypto.default_algorithm_for_public_key(public_key)
    issuer_name = crypto.name_from_attributes({"cn": "CRL/OCSP Test CA"})
    ski = crypto.compute_subject_key_identifier(public_key)
    now = dt.datetime.now(dt.timezone.utc)

    crl_der = crypto.build_and_sign_crl(
        issuer_name=issuer_name, this_update=now, next_update=now + dt.timedelta(hours=24),
        revoked=[(12345, now, "key_compromise")], crl_number=1, authority_key_id=ski,
        kms=kms, key_id=key_id, signature_algorithm=algorithm,
    )
    assert isinstance(crl_der, bytes) and len(crl_der) > 0

    ocsp_der = crypto.build_and_sign_ocsp_response(
        responder_name=issuer_name, issuer_public_key=public_key, cert_serial=12345,
        status="revoked", revoked_at=now, revocation_reason="key_compromise",
        this_update=now, next_update=now + dt.timedelta(hours=1),
        kms=kms, key_id=key_id, signature_algorithm=algorithm,
    )
    assert isinstance(ocsp_der, bytes) and len(ocsp_der) > 0


def test_software_kms_refuses_without_opt_in(monkeypatch, tmp_path):
    monkeypatch.delenv("PKICA_ALLOW_SOFTWARE_KMS", raising=False)
    with pytest.raises(RuntimeError, match="disabled"):
        SoftwareKMSBackend(storage_path=str(tmp_path / "kms2"))


@pytest.mark.parametrize("key_id", INVALID_KEY_IDS)
def test_software_kms_rejects_invalid_key_ids_on_create(kms, key_id):
    with pytest.raises(ValueError, match="Invalid key_id"):
        kms.create_key(KeySpec(key_id=key_id, algorithm="EC_P256", label="bad"))


@pytest.mark.parametrize("key_id", INVALID_KEY_IDS)
def test_software_kms_rejects_invalid_key_ids_for_public_operations(kms, key_id):
    kms.create_key(KeySpec(key_id="good-key", algorithm="EC_P256", label="good"))

    with pytest.raises(ValueError, match="Invalid key_id"):
        kms.public_key(key_id)

    with pytest.raises(ValueError, match="Invalid key_id"):
        kms.sign(key_id, b"payload", SignatureAlgorithm.ECDSA_SHA256)

    with pytest.raises(ValueError, match="Invalid key_id"):
        kms.key_exists(key_id)
