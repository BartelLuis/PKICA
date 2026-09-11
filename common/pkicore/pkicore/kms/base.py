"""Key-custody abstraction.

The golden rule of this module: **private key material never leaves the
KMS/HSM boundary.** Every backend exposes only `sign()` (raw signature over
a digest/message) and `public_key()`. There is no `export_private_key()`
method anywhere in this codebase, by design.
"""
from __future__ import annotations

import abc
from dataclasses import dataclass
from enum import Enum

from cryptography.hazmat.primitives.asymmetric import ec, rsa


class SignatureAlgorithm(str, Enum):
    RSA_PKCS1_SHA256 = "RSA_PKCS1_SHA256"
    RSA_PKCS1_SHA384 = "RSA_PKCS1_SHA384"
    RSA_PSS_SHA256 = "RSA_PSS_SHA256"
    ECDSA_SHA256 = "ECDSA_SHA256"
    ECDSA_SHA384 = "ECDSA_SHA384"


@dataclass(frozen=True)
class KeySpec:
    """Describes a key to be created in the backend."""

    key_id: str
    algorithm: str  # "RSA_2048", "RSA_4096", "EC_P256", "EC_P384"
    label: str


class KMSBackend(abc.ABC):
    """Common interface implemented by every key-custody backend."""

    name: str = "base"

    @abc.abstractmethod
    def create_key(self, spec: KeySpec) -> str:
        """Create a new asymmetric key pair inside the backend, return its key_id."""

    @abc.abstractmethod
    def public_key(self, key_id: str) -> rsa.RSAPublicKey | ec.EllipticCurvePublicKey:
        """Return the public key for a given key id."""

    @abc.abstractmethod
    def sign(self, key_id: str, data: bytes, algorithm: SignatureAlgorithm) -> bytes:
        """Sign `data` (already the exact bytes to be hashed, e.g. TBSCertificate DER)
        and return the DER-encoded signature (or raw r||s for backends that need it
        converted by the caller — see each backend's docstring)."""

    @abc.abstractmethod
    def key_exists(self, key_id: str) -> bool:
        ...

    def rotate_key(self, key_id: str, spec: KeySpec) -> str:
        """Default rotation = create a brand new key. Backends with native
        rotation support (e.g. Vault Transit) should override this."""
        return self.create_key(spec)
