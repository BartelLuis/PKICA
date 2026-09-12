"""Software-only KMS backend for local development and CI — NEVER for production.

Keys are held in memory / an AES-256-GCM encrypted file. This backend
actively refuses to initialize unless the operator explicitly opts in via
`PKICA_ALLOW_SOFTWARE_KMS=true`, so it can never be selected by accident in
a production deployment.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from pkicore.kms.base import KeySpec, KMSBackend, SignatureAlgorithm

_DIGEST = {
    SignatureAlgorithm.RSA_PKCS1_SHA256: hashes.SHA256(),
    SignatureAlgorithm.RSA_PKCS1_SHA384: hashes.SHA384(),
    SignatureAlgorithm.RSA_PSS_SHA256: hashes.SHA256(),
    SignatureAlgorithm.ECDSA_SHA256: hashes.SHA256(),
    SignatureAlgorithm.ECDSA_SHA384: hashes.SHA384(),
}

class SoftwareKMSBackend(KMSBackend):
    name = "software"

    def __init__(self, storage_path: str, master_key_env: str = "PKICA_SOFTWARE_KMS_MASTER_KEY") -> None:
        if os.environ.get("PKICA_ALLOW_SOFTWARE_KMS", "false").lower() != "true":
            raise RuntimeError(
                "Software KMS backend is disabled. Set PKICA_ALLOW_SOFTWARE_KMS=true "
                "only for local development/CI. Never use this backend in production."
            )
        master_key_b64 = os.environ.get(master_key_env)
        if not master_key_b64:
            raise RuntimeError(f"{master_key_env} must be set (32 random bytes, base64)")
        import base64

        self._aesgcm = AESGCM(base64.b64decode(master_key_b64))
        self._path = Path(storage_path)
        self._path.mkdir(parents=True, exist_ok=True)

    def _key_file(self, key_id: str) -> Path:
        if not key_id or key_id in {".", ".."} or "\\" in key_id:
            raise ValueError("Invalid key_id")
        key_path = Path(key_id)
        if key_path.is_absolute() or len(key_path.parts) != 1:
            raise ValueError("Invalid key_id")
        base_path = self._path.resolve(strict=True)
        filename = f"{hashlib.sha256(key_id.encode()).hexdigest()}.enc"
        return base_path / filename

    def create_key(self, spec: KeySpec) -> str:
        key_id = spec.key_id
        key_path = self._key_file(key_id)
        if spec.algorithm.startswith("RSA"):
            bits = int(spec.algorithm.split("_")[1])
            key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        else:
            curve = ec.SECP256R1() if spec.algorithm == "EC_P256" else ec.SECP384R1()
            key = ec.generate_private_key(curve)
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        nonce = os.urandom(12)
        ciphertext = self._aesgcm.encrypt(nonce, pem, key_id.encode())
        key_path.write_bytes(nonce + ciphertext)
        return key_id

    def _load_private(self, key_id: str):
        blob = self._key_file(key_id).read_bytes()
        nonce, ciphertext = blob[:12], blob[12:]
        pem = self._aesgcm.decrypt(nonce, ciphertext, key_id.encode())
        return serialization.load_pem_private_key(pem, password=None)

    def public_key(self, key_id: str):
        return self._load_private(key_id).public_key()

    def sign(self, key_id: str, data: bytes, algorithm: SignatureAlgorithm) -> bytes:
        key = self._load_private(key_id)
        digest = _DIGEST[algorithm]
        if isinstance(key, rsa.RSAPrivateKey):
            pad = (
                padding.PSS(mgf=padding.MGF1(digest), salt_length=padding.PSS.MAX_LENGTH)
                if algorithm == SignatureAlgorithm.RSA_PSS_SHA256
                else padding.PKCS1v15()
            )
            return key.sign(data, pad, digest)
        return key.sign(data, ec.ECDSA(digest))

    def key_exists(self, key_id: str) -> bool:
        return self._key_file(key_id).exists()
