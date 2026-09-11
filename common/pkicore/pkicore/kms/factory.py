"""Backend factory — selects the configured KMS/HSM implementation."""
from __future__ import annotations

from pkicore.config import Settings
from pkicore.kms.base import KMSBackend


def build_kms_backend(settings: Settings) -> KMSBackend:
    backend = settings.ca_key_backend.lower()

    if backend == "aws_kms":
        from pkicore.kms.aws_kms import AWSKMSBackend

        return AWSKMSBackend(region=settings.aws_region)

    if backend == "azure_key_vault":
        from pkicore.kms.azure_kv import AzureKeyVaultBackend

        return AzureKeyVaultBackend(vault_url=settings.azure_key_vault_url)

    if backend == "gcp_kms":
        from pkicore.kms.gcp_kms import GCPKMSBackend

        return GCPKMSBackend(
            project_id=settings.gcp_project_id,
            location=settings.gcp_location,
            key_ring=settings.gcp_kms_key_ring,
        )

    if backend == "vault_transit":
        from pkicore.kms.vault_transit import VaultTransitBackend

        return VaultTransitBackend(
            addr=settings.vault_addr,
            token=settings.vault_token,
            mount_point=settings.vault_transit_mount,
        )

    if backend == "pkcs11_hsm":
        from pkicore.kms.pkcs11_hsm import PKCS11Backend

        return PKCS11Backend(
            module_path=settings.pkcs11_module_path,
            slot=settings.pkcs11_slot,
            pin=settings.pkcs11_pin,
        )

    if backend == "software":
        if not settings.allow_software_kms:
            raise RuntimeError(
                "CA_KEY_BACKEND=software requires PKICA_ALLOW_SOFTWARE_KMS=true. "
                "This backend must never be used in production."
            )
        from pkicore.kms.software import SoftwareKMSBackend

        return SoftwareKMSBackend(storage_path="/data/software-kms")

    raise ValueError(f"Unknown CA_KEY_BACKEND: {backend!r}")
