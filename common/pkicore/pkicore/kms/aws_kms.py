"""AWS KMS backend — asymmetric CMKs, raw-sign only, never exportable."""
from __future__ import annotations

import boto3
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import load_der_public_key

from pkicore.kms.base import KeySpec, KMSBackend, SignatureAlgorithm

_ALGO_MAP = {
    SignatureAlgorithm.RSA_PKCS1_SHA256: "RSASSA_PKCS1_V1_5_SHA_256",
    SignatureAlgorithm.RSA_PKCS1_SHA384: "RSASSA_PKCS1_V1_5_SHA_384",
    SignatureAlgorithm.RSA_PSS_SHA256: "RSASSA_PSS_SHA_256",
    SignatureAlgorithm.ECDSA_SHA256: "ECDSA_SHA_256",
    SignatureAlgorithm.ECDSA_SHA384: "ECDSA_SHA_384",
}

_KEY_SPEC_MAP = {
    "RSA_2048": "RSA_2048",
    "RSA_4096": "RSA_4096",
    "EC_P256": "ECC_NIST_P256",
    "EC_P384": "ECC_NIST_P384",
}


class AWSKMSBackend(KMSBackend):
    name = "aws_kms"

    def __init__(self, region: str) -> None:
        self._client = boto3.client("kms", region_name=region)

    def create_key(self, spec: KeySpec) -> str:
        resp = self._client.create_key(
            KeyUsage="SIGN_VERIFY",
            KeySpec=_KEY_SPEC_MAP[spec.algorithm],
            Description=spec.label,
            Tags=[{"TagKey": "pkica-key-id", "TagValue": spec.key_id}],
            MultiRegion=False,
        )
        key_arn = resp["KeyMetadata"]["Arn"]
        self._client.create_alias(AliasName=f"alias/pkica-{spec.key_id}", TargetKeyId=key_arn)
        # KMS keys default to non-exportable ("origin=AWS_KMS"); never call
        # GetParametersForImport/export APIs from this codebase.
        return key_arn

    def public_key(self, key_id: str) -> rsa.RSAPublicKey | ec.EllipticCurvePublicKey:
        resp = self._client.get_public_key(KeyId=key_id)
        return load_der_public_key(resp["PublicKey"])

    def sign(self, key_id: str, data: bytes, algorithm: SignatureAlgorithm) -> bytes:
        resp = self._client.sign(
            KeyId=key_id,
            Message=data,
            MessageType="RAW",
            SigningAlgorithm=_ALGO_MAP[algorithm],
        )
        return resp["Signature"]

    def key_exists(self, key_id: str) -> bool:
        try:
            self._client.describe_key(KeyId=key_id)
            return True
        except self._client.exceptions.NotFoundException:
            return False
