"""Seed baseline certificate profiles referenced by the protocol adapters
(acme/est/scep) and a couple of REST examples. Run once after the issuing
CA has been created:

    docker compose exec ra python -m app.seed_profiles   # or run locally with PKICA_DATABASE_URL set
"""
from __future__ import annotations

from sqlalchemy import select

from pkicore.config import get_settings
from pkicore.db.models import CertificateAuthority, CertProfile
from pkicore.db.session import build_engine, init_schema, make_session_factory

PROFILES = [
    dict(name="acme-tls-server", max_validity_days=90, key_usage="digital_signature,key_encipherment",
         extended_key_usage="server_auth", allow_san_dns=True, allow_san_ip=False,
         require_approval=False, allowed_protocols="acme"),
    dict(name="est-device", max_validity_days=397, key_usage="digital_signature,key_encipherment",
         extended_key_usage="client_auth", allow_san_dns=True, allow_san_ip=True,
         require_approval=False, allowed_protocols="est"),
    dict(name="scep-device", max_validity_days=397, key_usage="digital_signature,key_encipherment",
         extended_key_usage="client_auth", allow_san_dns=True, allow_san_ip=True,
         require_approval=False, allowed_protocols="scep"),
    dict(name="rest-tls-server", max_validity_days=397, key_usage="digital_signature,key_encipherment",
         extended_key_usage="server_auth", allow_san_dns=True, allow_san_ip=True,
         require_approval=True, allowed_protocols="rest"),
]


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--issuing-ca", default="issuing-ca-1")
    args = parser.parse_args()

    settings = get_settings()
    engine = build_engine(settings)
    init_schema(engine)
    session_factory = make_session_factory(engine)

    with session_factory() as session:
        ca = session.scalar(select(CertificateAuthority).where(CertificateAuthority.name == args.issuing_ca))
        if ca is None:
            raise SystemExit(f"Issuing CA '{args.issuing_ca}' not found — create it first via `app.bootstrap`.")

        for spec in PROFILES:
            existing = session.scalar(select(CertProfile).where(CertProfile.name == spec["name"]))
            if existing:
                print(f"Profile '{spec['name']}' already exists, skipping")
                continue
            session.add(CertProfile(issuing_ca_id=ca.id, **spec))
            print(f"Created profile '{spec['name']}'")
        session.commit()


if __name__ == "__main__":
    main()
