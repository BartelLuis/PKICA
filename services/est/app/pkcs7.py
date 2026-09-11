"""RFC 5652 CMS "certs-only" SignedData construction, used by EST responses
(`application/pkcs7-mime`) — no actual signature, just a certificate bag."""
from __future__ import annotations

from asn1crypto import cms, x509 as a_x509


def certs_only_pkcs7(certificates_der: list[bytes]) -> bytes:
    certs = [a_x509.Certificate.load(der) for der in certificates_der]
    signed_data = cms.SignedData({
        "version": "v1",
        "digest_algorithms": [],
        "encap_content_info": {"content_type": "data"},
        "certificates": [cms.CertificateChoices(name="certificate", value=c) for c in certs],
        "signer_infos": [],
    })
    content_info = cms.ContentInfo({"content_type": "signed_data", "content": signed_data})
    return content_info.dump()
