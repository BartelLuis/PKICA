"""Google Cloud KMS backend."""
from __future__ import annotations

from google.cloud import kms
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from pkicore.kms.base import KeySpec, KMSBackend, SignatureAlgorithm

_PURPOSE = kms.CryptoKey.CryptoKeyPurpose.ASYMMETRIC_SIGN

_ALGO_MAP = {
    "RSA_2048": kms.CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PKCS1_2048_SHA256,
    "RSA_4096": kms.CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PKCS1_4096_SHA256,
    "EC_P256": kms.CryptoKeyVersion.CryptoKeyVersionAlgorithm.EC_SIGN_P256_SHA256,
    "EC_P384": kms.CryptoKeyVersion.CryptoKeyVersionAlgorithm.EC_SIGN_P384_SHA384,
}

_DIGEST_MAP = {
    SignatureAlgorithm.RSA_PKCS1_SHA256: hashes.SHA256(),
    SignatureAlgorithm.RSA_PKCS1_SHA384: hashes.SHA384(),
    SignatureAlgorithm.RSA_PSS_SHA256: hashes.SHA256(),
    SignatureAlgorithm.ECDSA_SHA256: hashes.SHA256(),
    SignatureAlgorithm.ECDSA_SHA384: hashes.SHA384(),
}


class GCPKMSBackend(KMSBackend):
    name = "gcp_kms"

    def __init__(self, project_id: str, location: str, key_ring: str) -> None:
        self._client = kms.KeyManagementServiceClient()
        self._key_ring_path = self._client.key_ring_path(project_id, location, key_ring)

    def _crypto_key_path(self, key_id: str) -> str:
        return f"{self._key_ring_path}/cryptoKeys/{key_id}"

    def create_key(self, spec: KeySpec) -> str:
        crypto_key = {
            "purpose": _PURPOSE,
            "version_template": {"algorithm": _ALGO_MAP[spec.algorithm]},
            "labels": {"pkica_label": spec.label.lower().replace(" ", "-")},
        }
        result = self._client.create_crypto_key(
            request={
                "parent": self._key_ring_path,
                "crypto_key_id": spec.key_id,
                "crypto_key": crypto_key,
            }
        )
        return result.name + "/cryptoKeyVersions/1"

    def public_key(self, key_id: str) -> rsa.RSAPublicKey | ec.EllipticCurvePublicKey:
        response = self._client.get_public_key(request={"name": key_id})
        return load_pem_public_key(response.pem.encode())

    def sign(self, key_id: str, data: bytes, algorithm: SignatureAlgorithm) -> bytes:
        digest = hashes.Hash(_DIGEST_MAP[algorithm])
        digest.update(data)
        digest_bytes = digest.finalize()
        digest_field = "sha384" if "384" in algorithm.value else "sha256"
        response = self._client.asymmetric_sign(
            request={"name": key_id, "digest": {digest_field: digest_bytes}}
        )
        return response.signature

    def key_exists(self, key_id: str) -> bool:
        try:
            self._client.get_crypto_key_version(request={"name": key_id})
            return True
        except Exception:
            return False
