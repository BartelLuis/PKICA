"""HashiCorp Vault Transit engine backend.

Vault Transit keys are never exportable unless `exportable=true` was set at
creation time — this backend always creates non-exportable keys.
"""
from __future__ import annotations

import base64

import hvac
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from pkicore.kms.base import KeySpec, KMSBackend, SignatureAlgorithm

_VAULT_KEY_TYPE = {
    "RSA_2048": "rsa-2048",
    "RSA_4096": "rsa-4096",
    "EC_P256": "ecdsa-p256",
    "EC_P384": "ecdsa-p384",
}

_VAULT_HASH_ALGO = {
    SignatureAlgorithm.RSA_PKCS1_SHA256: "sha2-256",
    SignatureAlgorithm.RSA_PKCS1_SHA384: "sha2-384",
    SignatureAlgorithm.RSA_PSS_SHA256: "sha2-256",
    SignatureAlgorithm.ECDSA_SHA256: "sha2-256",
    SignatureAlgorithm.ECDSA_SHA384: "sha2-384",
}

_VAULT_SIGNATURE_ALGO = {
    SignatureAlgorithm.RSA_PKCS1_SHA256: "pkcs1v15",
    SignatureAlgorithm.RSA_PKCS1_SHA384: "pkcs1v15",
    SignatureAlgorithm.RSA_PSS_SHA256: "pss",
}


class VaultTransitBackend(KMSBackend):
    name = "vault_transit"

    def __init__(self, addr: str, token: str, mount_point: str = "transit") -> None:
        self._client = hvac.Client(url=addr, token=token)
        self._mount = mount_point
        if not self._client.is_authenticated():
            raise RuntimeError("Vault authentication failed for Transit backend")

    def create_key(self, spec: KeySpec) -> str:
        self._client.secrets.transit.create_key(
            name=spec.key_id,
            key_type=_VAULT_KEY_TYPE[spec.algorithm],
            exportable=False,
            allow_plaintext_backup=False,
            mount_point=self._mount,
        )
        return spec.key_id

    def public_key(self, key_id: str) -> rsa.RSAPublicKey | ec.EllipticCurvePublicKey:
        info = self._client.secrets.transit.read_key(name=key_id, mount_point=self._mount)
        latest_version = str(info["data"]["latest_version"])
        pem = info["data"]["keys"][latest_version]["public_key"]
        return load_pem_public_key(pem.encode())

    def sign(self, key_id: str, data: bytes, algorithm: SignatureAlgorithm) -> bytes:
        b64_input = base64.b64encode(data).decode()
        kwargs = dict(
            name=key_id,
            hash_input=b64_input,
            hash_algorithm=_VAULT_HASH_ALGO[algorithm],
            prehashed=False,
            mount_point=self._mount,
        )
        if algorithm in _VAULT_SIGNATURE_ALGO:
            kwargs["signature_algorithm"] = _VAULT_SIGNATURE_ALGO[algorithm]
        resp = self._client.secrets.transit.sign_data(**kwargs)
        vault_sig = resp["data"]["signature"]  # "vault:v1:<base64>"
        raw = base64.b64decode(vault_sig.split(":")[-1])
        return raw

    def key_exists(self, key_id: str) -> bool:
        try:
            self._client.secrets.transit.read_key(name=key_id, mount_point=self._mount)
            return True
        except Exception:
            return False

    def rotate_key(self, key_id: str, spec: KeySpec) -> str:
        self._client.secrets.transit.rotate_key(name=key_id, mount_point=self._mount)
        return key_id
