"""Azure Key Vault backend (supports Premium/HSM-backed key SKUs)."""
from __future__ import annotations

from azure.identity import DefaultAzureCredential
from azure.keyvault.keys import KeyClient, KeyType
from azure.keyvault.keys.crypto import CryptographyClient, SignatureAlgorithm as AzSigAlg
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_der_public_key

from pkicore.kms.base import KeySpec, KMSBackend, SignatureAlgorithm

_ALGO_MAP = {
    SignatureAlgorithm.RSA_PKCS1_SHA256: AzSigAlg.rs256,
    SignatureAlgorithm.RSA_PKCS1_SHA384: AzSigAlg.rs384,
    SignatureAlgorithm.RSA_PSS_SHA256: AzSigAlg.ps256,
    SignatureAlgorithm.ECDSA_SHA256: AzSigAlg.es256,
    SignatureAlgorithm.ECDSA_SHA384: AzSigAlg.es384,
}

_DIGEST_MAP = {
    SignatureAlgorithm.RSA_PKCS1_SHA256: hashes.SHA256(),
    SignatureAlgorithm.RSA_PKCS1_SHA384: hashes.SHA384(),
    SignatureAlgorithm.RSA_PSS_SHA256: hashes.SHA256(),
    SignatureAlgorithm.ECDSA_SHA256: hashes.SHA256(),
    SignatureAlgorithm.ECDSA_SHA384: hashes.SHA384(),
}


class AzureKeyVaultBackend(KMSBackend):
    name = "azure_key_vault"

    def __init__(self, vault_url: str, hsm_backed: bool = True) -> None:
        credential = DefaultAzureCredential()
        self._key_client = KeyClient(vault_url=vault_url, credential=credential)
        self._credential = credential
        self._hsm_backed = hsm_backed

    def create_key(self, spec: KeySpec) -> str:
        key_type = KeyType.rsa_hsm if spec.algorithm.startswith("RSA") else KeyType.ec_hsm
        size = int(spec.algorithm.split("_")[1]) if spec.algorithm.startswith("RSA") else None
        curve = spec.algorithm.split("_")[1] if spec.algorithm.startswith("EC") else None
        kwargs = {"key_type": key_type}
        if size:
            kwargs["size"] = size
        if curve:
            kwargs["curve"] = f"P-{curve[1:]}" if curve.startswith("P") else curve
        key = self._key_client.create_key(name=spec.key_id, **kwargs)
        return key.id

    def _crypto_client(self, key_id: str) -> CryptographyClient:
        return CryptographyClient(key_id, credential=self._credential)

    def public_key(self, key_id: str) -> rsa.RSAPublicKey | ec.EllipticCurvePublicKey:
        key = self._key_client.get_key(key_id)
        return self._to_cryptography_key(key)

    @staticmethod
    def _to_cryptography_key(key):
        jwk = key.key
        if jwk.kty and "RSA" in jwk.kty:
            pub_numbers = rsa.RSAPublicNumbers(
                e=int.from_bytes(jwk.e, "big"), n=int.from_bytes(jwk.n, "big")
            )
            return pub_numbers.public_key()
        curve_map = {"P-256": ec.SECP256R1(), "P-384": ec.SECP384R1()}
        pub_numbers = ec.EllipticCurvePublicNumbers(
            x=int.from_bytes(jwk.x, "big"),
            y=int.from_bytes(jwk.y, "big"),
            curve=curve_map[jwk.crv],
        )
        return pub_numbers.public_key()

    def sign(self, key_id: str, data: bytes, algorithm: SignatureAlgorithm) -> bytes:
        client = self._crypto_client(key_id)
        digest = hashes.Hash(_DIGEST_MAP[algorithm])
        digest.update(data)
        result = client.sign(_ALGO_MAP[algorithm], digest.finalize())
        return result.signature

    def key_exists(self, key_id: str) -> bool:
        try:
            self._key_client.get_key(key_id)
            return True
        except Exception:
            return False
