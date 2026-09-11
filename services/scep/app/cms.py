"""Minimal CMS (RFC 5652) EnvelopedData/SignedData handling for SCEP
(RFC 8894) — RSA key-transport + AES-128-CBC content encryption only, which
covers the vast majority of real-world SCEP clients (sscep, Cisco IOS,
Windows NDES/MS-SCEP clients).
"""
from __future__ import annotations

import os

from asn1crypto import cms, algos, core
from cryptography.hazmat.primitives import hashes, padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def decrypt_enveloped_data(der: bytes, recipient_private_key_decrypt) -> bytes:
    """`recipient_private_key_decrypt(ciphertext: bytes) -> bytes` performs the
    RSA decryption (delegated so KMS-backed keys can be used transparently —
    note: most KMS/HSM backends only support *sign*, not *decrypt*, for
    asymmetric keys; SCEP therefore requires a dedicated software or
    HSM-decrypt-capable RSA key, configured separately from the CA signing key)."""
    content_info = cms.ContentInfo.load(der)
    enveloped = content_info["content"]
    recipient_info = enveloped["recipient_infos"][0].chosen
    encrypted_key = recipient_info["encrypted_key"].native

    content_enc_algo = enveloped["encrypted_content_info"]["content_encryption_algorithm"]
    algo_oid = content_enc_algo["algorithm"].native
    iv = content_enc_algo["parameters"].native
    ciphertext = enveloped["encrypted_content_info"]["encrypted_content"].native

    symmetric_key = recipient_private_key_decrypt(encrypted_key)

    if "aes128" in algo_oid:
        cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv))
    elif "des_ede3" in algo_oid or "3des" in algo_oid or algo_oid == "1.2.840.113549.3.7":
        cipher = Cipher(algorithms.TripleDES(symmetric_key), modes.CBC(iv))
    else:
        raise ValueError(f"Unsupported SCEP content encryption algorithm: {algo_oid}")

    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128 if "aes" in algo_oid else 64).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def build_enveloped_data(plaintext: bytes, recipient_certificate_der: bytes, recipient_public_key: rsa.RSAPublicKey) -> bytes:
    key = os.urandom(16)
    iv = os.urandom(16)
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    encrypted_key = recipient_public_key.encrypt(key, asym_padding.PKCS1v15())

    from asn1crypto import x509 as a_x509

    cert = a_x509.Certificate.load(recipient_certificate_der)
    recipient_info = cms.KeyTransRecipientInfo({
        "version": "v0",
        "rid": cms.RecipientIdentifier({
            "issuer_and_serial_number": cms.IssuerAndSerialNumber({
                "issuer": cert.issuer,
                "serial_number": cert.serial_number,
            })
        }),
        "key_encryption_algorithm": {"algorithm": "rsaes_pkcs1v15"},
        "encrypted_key": encrypted_key,
    })

    enveloped = cms.EnvelopedData({
        "version": "v0",
        "recipient_infos": [cms.RecipientInfo(name="ktri", value=recipient_info)],
        "encrypted_content_info": {
            "content_type": "data",
            "content_encryption_algorithm": {
                "algorithm": "aes128_cbc",
                "parameters": iv,
            },
            "encrypted_content": ciphertext,
        },
    })
    content_info = cms.ContentInfo({"content_type": "enveloped_data", "content": enveloped})
    return content_info.dump()


def sign_data(data: bytes, signer_certificate_der: bytes, sign_callback) -> bytes:
    """`sign_callback(tbs_bytes) -> signature` — allows the caller to sign with
    a KMS/HSM-backed key. Produces a detached-content SignedData over `data`."""
    from asn1crypto import x509 as a_x509

    cert = a_x509.Certificate.load(signer_certificate_der)
    digest = __import__("hashlib").sha256(data).digest()

    signed_attrs = cms.CMSAttributes([
        cms.CMSAttribute({"type": "content_type", "values": [cms.ContentType("data")]}),
        cms.CMSAttribute({"type": "message_digest", "values": [core.OctetString(digest)]}),
    ])
    signature = sign_callback(signed_attrs.dump())

    signer_info = cms.SignerInfo({
        "version": "v1",
        "sid": cms.SignerIdentifier({
            "issuer_and_serial_number": cms.IssuerAndSerialNumber({
                "issuer": cert.issuer, "serial_number": cert.serial_number,
            })
        }),
        "digest_algorithm": {"algorithm": "sha256"},
        "signed_attrs": signed_attrs,
        "signature_algorithm": {"algorithm": "rsassa_pkcs1v15"},
        "signature": signature,
    })
    signed_data = cms.SignedData({
        "version": "v1",
        "digest_algorithms": [{"algorithm": "sha256"}],
        "encap_content_info": {"content_type": "data", "content": data},
        "certificates": [cms.CertificateChoices(name="certificate", value=cert)],
        "signer_infos": [signer_info],
    })
    content_info = cms.ContentInfo({"content_type": "signed_data", "content": signed_data})
    return content_info.dump()
