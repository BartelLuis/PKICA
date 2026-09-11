"""Generate a throwaway local 'infra CA' and the internal mTLS certificates
needed to run the full docker-compose stack for development/testing.

**Development only.** In production, service-to-service mTLS certificates
must be issued by the platform's own infrastructure intermediate CA (or your
existing enterprise PKI) with short lifetimes and automated rotation — see
docs/DEPLOYMENT.md ("Bootstrapping internal mTLS").

Usage:
    python scripts/generate-dev-certs.py
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

OUT_DIR = Path(__file__).resolve().parent.parent / "certs"
SERVICE_IDENTITIES = ["ra", "ocsp", "crl", "ca-mtls-proxy", "gateway"]


def _write_key(path: Path, key) -> None:
    path.write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    os.chmod(path, 0o600)


def _generate_ca() -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    key = ec.generate_private_key(ec.SECP384R1())
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "PKICA Dev Infra CA")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(issuer).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now).not_valid_after(now + dt.timedelta(days=730))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
            encipher_only=False, decipher_only=False), critical=True)
        .sign(key, hashes.SHA384())
    )
    return key, cert


def _issue_leaf(name: str, ca_key, ca_cert: x509.Certificate) -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = dt.datetime.now(dt.timezone.utc)
    san = x509.SubjectAlternativeName([x509.DNSName(name), x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(ca_cert.subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now).not_valid_after(now + dt.timedelta(days=90))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=True,
            data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False,
            encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH, x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .add_extension(san, critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    _write_key(OUT_DIR / f"{name}.key", key)
    (OUT_DIR / f"{name}.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    ca_key, ca_cert = _generate_ca()
    _write_key(OUT_DIR / "infra-ca.key", ca_key)
    (OUT_DIR / "infra-ca.crt").write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    (OUT_DIR / "client-ca-bundle.crt").write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))

    for name in SERVICE_IDENTITIES:
        _issue_leaf(name, ca_key, ca_cert)
        if name != "gateway":
            # ca-mtls-proxy / RA / OCSP / CRL certs double as their own "server.crt/key"
            pass

    # ca-mtls-proxy expects server.crt/server.key filenames
    (OUT_DIR / "server.crt").write_bytes((OUT_DIR / "ca-mtls-proxy.crt").read_bytes())
    (OUT_DIR / "server.key").write_bytes((OUT_DIR / "ca-mtls-proxy.key").read_bytes())

    print(f"Dev mTLS material written to {OUT_DIR}")
    print("DO NOT use these certificates outside local development/testing.")


if __name__ == "__main__":
    main()
