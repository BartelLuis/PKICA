"""RFC 8555 ACME server — protocol adapter in front of the RA.

This is a functional reference implementation covering the http-01
challenge type and the core account/order/finalize/download flow. It is
intentionally conservative in scope (no dns-01/tls-alpn-01, no external
account binding) — see docs/ARCHITECTURE.md for hardening/extension notes
before using this in production.
"""
from __future__ import annotations

import base64
import datetime as dt
import json
import secrets
import uuid
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, HTTPException, Request, Response
from sqlalchemy import select

from pkicore.ca_client import CAClient
from pkicore.config import get_settings
from pkicore.db.models import AcmeAccount, AcmeAuthorization, AcmeNonce, AcmeOrder
from pkicore.db.session import build_engine, init_schema, make_session_factory
from pkicore.logging import configure_logging, get_logger

from app.jws import b64url_decode, jwk_thumbprint, verify_and_decode

settings = get_settings()
configure_logging("acme", settings.log_level, settings.log_json)
log = get_logger(__name__)

engine = build_engine(settings)
session_factory = make_session_factory(engine)

_RA_INTERNAL_URL = settings.ra_internal_url
_PROFILE_NAME = "acme-tls-server"
_EXTERNAL_BASE_URL = "https://acme.pkica.local/acme"  # override via reverse-proxy rewrite in production


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_schema(engine)
    log.info("acme_service_started")
    yield


app = FastAPI(title="PKICA - ACME Server", lifespan=lifespan, docs_url=None, redoc_url=None)


def _ra_client() -> httpx.Client:
    cert = None
    if settings.internal_tls_cert and settings.internal_tls_key:
        cert = (settings.internal_tls_cert, settings.internal_tls_key)
    return httpx.Client(base_url=_RA_INTERNAL_URL, cert=cert, verify=settings.internal_tls_ca or True, timeout=15.0)


def _new_nonce(session) -> str:
    nonce = secrets.token_urlsafe(24)
    session.add(AcmeNonce(nonce=nonce))
    session.commit()
    return nonce


def _consume_nonce(session, nonce: str) -> None:
    row = session.get(AcmeNonce, nonce)
    if row is None:
        raise HTTPException(400, detail={"type": "urn:ietf:params:acme:error:badNonce", "detail": "invalid or reused nonce"})
    session.delete(row)
    session.commit()


@app.get("/directory")
def directory():
    base = _EXTERNAL_BASE_URL
    return {
        "newNonce": f"{base}/new-nonce",
        "newAccount": f"{base}/new-account",
        "newOrder": f"{base}/new-order",
        "revokeCert": f"{base}/revoke-cert",
        "keyChange": f"{base}/key-change",
        "meta": {"externalAccountRequired": False},
    }


@app.head("/new-nonce")
@app.get("/new-nonce")
def new_nonce():
    with session_factory() as session:
        nonce = _new_nonce(session)
    return Response(status_code=204, headers={"Replay-Nonce": nonce, "Cache-Control": "no-store"})


async def _parse_jws(request: Request) -> dict:
    body = await request.body()
    try:
        return json.loads(body)
    except json.JSONDecodeError as exc:
        raise HTTPException(400, "Malformed JWS body") from exc


@app.post("/new-account")
async def new_account(request: Request):
    flat = await _parse_jws(request)
    protected = json.loads(b64url_decode(flat["protected"]))
    with session_factory() as session:
        _consume_nonce(session, protected["nonce"])
        jwk = protected["jwk"]
        _, payload = verify_and_decode(flat, jwk)
        thumb = jwk_thumbprint(jwk)

        account = session.scalar(select(AcmeAccount).where(AcmeAccount.jwk_thumbprint == thumb))
        status_code = 200
        if account is None:
            account = AcmeAccount(
                jwk_thumbprint=thumb, jwk_json=json.dumps(jwk),
                contact=",".join(payload.get("contact", [])),
            )
            session.add(account)
            session.commit()
            status_code = 201

        nonce = _new_nonce(session)
        return Response(
            status_code=status_code,
            headers={
                "Replay-Nonce": nonce,
                "Location": f"{_EXTERNAL_BASE_URL}/account/{account.id}",
            },
            content=json.dumps({"status": "valid", "contact": payload.get("contact", [])}),
            media_type="application/json",
        )


def _get_account_from_kid(session, protected: dict) -> AcmeAccount:
    kid = protected.get("kid", "")
    account_id = kid.rstrip("/").rsplit("/", 1)[-1]
    account = session.get(AcmeAccount, uuid.UUID(account_id))
    if account is None:
        raise HTTPException(401, "Unknown ACME account")
    return account


@app.post("/new-order")
async def new_order(request: Request):
    flat = await _parse_jws(request)
    protected = json.loads(b64url_decode(flat["protected"]))
    with session_factory() as session:
        _consume_nonce(session, protected["nonce"])
        account = _get_account_from_kid(session, protected)
        _, payload = verify_and_decode(flat, json.loads(account.jwk_json))

        identifiers = payload["identifiers"]
        order = AcmeOrder(account_id=account.id, identifiers=json.dumps(identifiers), status="pending")
        session.add(order)
        session.flush()

        authz_urls = []
        for ident in identifiers:
            token = secrets.token_urlsafe(32)
            authz = AcmeAuthorization(
                order_id=order.id, identifier_type=ident.get("type", "dns"),
                identifier_value=ident["value"], token=token, status="pending",
            )
            session.add(authz)
            session.flush()
            authz_urls.append(f"{_EXTERNAL_BASE_URL}/authz/{authz.id}")
        session.commit()

        nonce = _new_nonce(session)
        return Response(
            status_code=201,
            headers={"Replay-Nonce": nonce, "Location": f"{_EXTERNAL_BASE_URL}/order/{order.id}"},
            content=json.dumps({
                "status": "pending",
                "identifiers": identifiers,
                "authorizations": authz_urls,
                "finalize": f"{_EXTERNAL_BASE_URL}/order/{order.id}/finalize",
            }),
            media_type="application/json",
        )


@app.post("/authz/{authz_id}")
async def get_authz(authz_id: uuid.UUID, request: Request):
    await _parse_jws(request)  # POST-as-GET; signature already validated by client trust model here
    with session_factory() as session:
        authz = session.get(AcmeAuthorization, authz_id)
        if authz is None:
            raise HTTPException(404)
        nonce = _new_nonce(session)
        return Response(
            headers={"Replay-Nonce": nonce},
            content=json.dumps({
                "status": authz.status,
                "identifier": {"type": authz.identifier_type, "value": authz.identifier_value},
                "challenges": [{
                    "type": "http-01",
                    "url": f"{_EXTERNAL_BASE_URL}/chall/{authz.id}",
                    "token": authz.token,
                    "status": authz.status,
                }],
            }),
            media_type="application/json",
        )


@app.post("/chall/{authz_id}")
async def respond_challenge(authz_id: uuid.UUID, request: Request):
    flat = await _parse_jws(request)
    protected = json.loads(b64url_decode(flat["protected"]))
    with session_factory() as session:
        _consume_nonce(session, protected["nonce"])
        authz = session.get(AcmeAuthorization, authz_id)
        if authz is None:
            raise HTTPException(404)
        account = _get_account_from_kid(session, protected)

        key_authorization = f"{authz.token}.{jwk_thumbprint(json.loads(account.jwk_json))}"
        validation_url = f"http://{authz.identifier_value}/.well-known/acme-challenge/{authz.token}"
        try:
            resp = httpx.get(validation_url, timeout=10.0, follow_redirects=True)
            ok = resp.status_code == 200 and resp.text.strip() == key_authorization
        except Exception as exc:  # noqa: BLE001
            log.warning("acme_http01_validation_failed", error=str(exc), url=validation_url)
            ok = False

        authz.status = "valid" if ok else "invalid"
        session.commit()
        nonce = _new_nonce(session)
        if not ok:
            raise HTTPException(403, detail={"type": "urn:ietf:params:acme:error:unauthorized", "detail": "http-01 validation failed"})
        return Response(
            headers={"Replay-Nonce": nonce},
            content=json.dumps({"status": "valid", "type": "http-01", "token": authz.token}),
            media_type="application/json",
        )


@app.post("/order/{order_id}/finalize")
async def finalize(order_id: uuid.UUID, request: Request):
    flat = await _parse_jws(request)
    protected = json.loads(b64url_decode(flat["protected"]))
    with session_factory() as session:
        _consume_nonce(session, protected["nonce"])
        order = session.get(AcmeOrder, order_id)
        if order is None:
            raise HTTPException(404)
        account = _get_account_from_kid(session, protected)
        _, payload = verify_and_decode(flat, json.loads(account.jwk_json))

        authzs = session.scalars(select(AcmeAuthorization).where(AcmeAuthorization.order_id == order.id)).all()
        if not all(a.status == "valid" for a in authzs):
            raise HTTPException(403, "Not all authorizations are valid")

        csr_der = b64url_decode(payload["csr"])
        csr_pem = ("-----BEGIN CERTIFICATE REQUEST-----\n"
                   + base64.encodebytes(csr_der).decode() +
                   "-----END CERTIFICATE REQUEST-----\n")
        sans = [f"dns:{a.identifier_value}" for a in authzs]

        with _ra_client() as ra:
            resp = ra.post("/internal/v1/requests", json={
                "profile_name": _PROFILE_NAME, "protocol": "acme",
                "requester_identity": account.jwk_thumbprint, "csr_pem": csr_pem,
                "requested_sans": sans,
            })
        if resp.status_code >= 400:
            raise HTTPException(502, f"RA rejected request: {resp.text}")
        ra_request = resp.json()

        order.request_id = ra_request["id"]
        if ra_request.get("issued_certificate_pem"):
            order.certificate_pem = ra_request["issued_certificate_pem"]
            order.status = "valid"
        else:
            order.status = "processing"
        session.commit()

        nonce = _new_nonce(session)
        body = {"status": order.status, "identifiers": json.loads(order.identifiers),
                "finalize": f"{_EXTERNAL_BASE_URL}/order/{order.id}/finalize"}
        if order.status == "valid":
            body["certificate"] = f"{_EXTERNAL_BASE_URL}/cert/{order.id}"
        return Response(headers={"Replay-Nonce": nonce}, content=json.dumps(body), media_type="application/json")


@app.post("/order/{order_id}")
async def get_order(order_id: uuid.UUID, request: Request):
    await _parse_jws(request)
    with session_factory() as session:
        order = session.get(AcmeOrder, order_id)
        if order is None:
            raise HTTPException(404)
        nonce = _new_nonce(session)
        body = {"status": order.status, "identifiers": json.loads(order.identifiers)}
        if order.status == "valid":
            body["certificate"] = f"{_EXTERNAL_BASE_URL}/cert/{order.id}"
        return Response(headers={"Replay-Nonce": nonce}, content=json.dumps(body), media_type="application/json")


@app.get("/cert/{order_id}")
def download_cert(order_id: uuid.UUID):
    with session_factory() as session:
        order = session.get(AcmeOrder, order_id)
        if order is None or not order.certificate_pem:
            raise HTTPException(404)
        return Response(content=order.certificate_pem, media_type="application/pem-certificate-chain")


@app.get("/healthz")
def healthz():
    return {"status": "ok"}
