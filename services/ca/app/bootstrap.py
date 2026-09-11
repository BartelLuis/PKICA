"""One-time / operator CLI for CA lifecycle actions, run inside the `ca`
container (never exposed over HTTP): `docker compose exec ca python -m app.bootstrap ...`
"""
from __future__ import annotations

import argparse
import json
import sys

from pkicore.config import get_settings
from pkicore.db.session import build_engine, init_schema, make_session_factory
from pkicore.kms.factory import build_kms_backend

from app.service import CAService


def main() -> None:
    parser = argparse.ArgumentParser(prog="pkica-ca-bootstrap")
    sub = parser.add_subparsers(dest="command", required=True)

    root = sub.add_parser("create-root")
    root.add_argument("--name", required=True)
    root.add_argument("--subject", required=True, help='JSON, e.g. {"cn":"PKICA Root CA","o":"ACME"}')
    root.add_argument("--key-algorithm", default="EC_P384")
    root.add_argument("--validity-days", type=int, default=7300)

    inter = sub.add_parser("create-intermediate")
    inter.add_argument("--name", required=True)
    inter.add_argument("--parent", required=True)
    inter.add_argument("--subject", required=True)
    inter.add_argument("--key-algorithm", default="EC_P384")
    inter.add_argument("--validity-days", type=int, default=3650)
    inter.add_argument("--path-len", type=int, default=0)

    args = parser.parse_args()

    settings = get_settings()
    engine = build_engine(settings)
    init_schema(engine)
    session_factory = make_session_factory(engine)
    kms = build_kms_backend(settings)

    with session_factory() as session:
        svc = CAService(session=session, kms=kms, audit_secret=settings.audit_hash_chain_secret or "dev-secret")
        if args.command == "create-root":
            ca = svc.create_root_ca(
                name=args.name, subject=json.loads(args.subject),
                key_algorithm=args.key_algorithm, validity_days=args.validity_days,
            )
        else:
            ca = svc.create_intermediate_ca(
                name=args.name, parent_name=args.parent, subject=json.loads(args.subject),
                key_algorithm=args.key_algorithm, validity_days=args.validity_days, path_len=args.path_len,
            )
        session.commit()
        print(f"Created CA '{ca.name}':\n{ca.certificate_pem}")


if __name__ == "__main__":
    sys.exit(main())
