"""PKCS#11 HSM backend (Thales Luna, Entrust nShield, SoftHSM2 for dev/test).

Keys are generated with `CKA_EXTRACTABLE=false` / `CKA_SENSITIVE=true` so the
HSM refuses any attempt to wrap or export the private object.
"""
from __future__ import annotations

import pkcs11
from pkcs11 import KeyType, Mechanism, ObjectClass
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import load_der_public_key

from pkicore.kms.base import KeySpec, KMSBackend, SignatureAlgorithm

_MECHANISM_MAP = {
    SignatureAlgorithm.RSA_PKCS1_SHA256: Mechanism.SHA256_RSA_PKCS,
    SignatureAlgorithm.RSA_PKCS1_SHA384: Mechanism.SHA384_RSA_PKCS,
    SignatureAlgorithm.RSA_PSS_SHA256: Mechanism.SHA256_RSA_PKCS_PSS,
    SignatureAlgorithm.ECDSA_SHA256: Mechanism.ECDSA_SHA256,
    SignatureAlgorithm.ECDSA_SHA384: Mechanism.ECDSA_SHA384,
}

_EC_PARAMS = {
    "EC_P256": ec.SECP256R1(),
    "EC_P384": ec.SECP384R1(),
}


class PKCS11Backend(KMSBackend):
    name = "pkcs11_hsm"

    def __init__(self, module_path: str, slot: int, pin: str) -> None:
        self._lib = pkcs11.lib(module_path)
        token = self._lib.get_slots(token_present=True)[slot].get_token()
        self._session = token.open(user_pin=pin, rw=True)

    def create_key(self, spec: KeySpec) -> str:
        if spec.algorithm.startswith("RSA"):
            bits = int(spec.algorithm.split("_")[1])
            pub, _priv = self._session.generate_keypair(
                KeyType.RSA,
                bits,
                label=spec.key_id,
                store=True,
                capabilities=frozenset({pkcs11.MechanismFlag.SIGN}),
                extractable=False,
                sensitive=True,
            )
        else:
            from asn1crypto.keys import ECDomainParameters, NamedCurve

            curve_name = "secp256r1" if spec.algorithm == "EC_P256" else "secp384r1"
            params = ECDomainParameters(name="named", value=NamedCurve(curve_name)).dump()
            pub, _priv = self._session.generate_keypair(
                KeyType.EC,
                label=spec.key_id,
                store=True,
                ecdsa_params=params,
                capabilities=frozenset({pkcs11.MechanismFlag.SIGN}),
                extractable=False,
                sensitive=True,
            )
        return spec.key_id

    def _find_private(self, key_id: str):
        return self._session.get_key(label=key_id, object_class=ObjectClass.PRIVATE_KEY)

    def _find_public(self, key_id: str):
        return self._session.get_key(label=key_id, object_class=ObjectClass.PUBLIC_KEY)

    def public_key(self, key_id: str) -> rsa.RSAPublicKey | ec.EllipticCurvePublicKey:
        pub = self._find_public(key_id)
        der = pub.to_pem() if hasattr(pub, "to_pem") else pub[pkcs11.Attribute.EC_POINT]
        return load_der_public_key(der)

    def sign(self, key_id: str, data: bytes, algorithm: SignatureAlgorithm) -> bytes:
        priv = self._find_private(key_id)
        mechanism = _MECHANISM_MAP[algorithm]
        return priv.sign(data, mechanism=mechanism)

    def key_exists(self, key_id: str) -> bool:
        try:
            self._find_private(key_id)
            return True
        except pkcs11.NoSuchKey:
            return False
