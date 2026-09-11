from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import Response

from pkicore.ca_client import CAClient
from pkicore.config import get_settings
from pkicore.logging import configure_logging, get_logger

settings = get_settings()
configure_logging("ocsp", settings.log_level, settings.log_json)
log = get_logger(__name__)

ca_client = CAClient(settings)

# TTL cache to avoid hammering the CA for every single request while still
# refreshing frequently enough to reflect new revocations promptly.
_CACHE: dict[str, tuple[float, bytes]] = {}
_CACHE_TTL_SECONDS = 60


@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("ocsp_service_started")
    yield


app = FastAPI(title="PKICA - OCSP Responder", lifespan=lifespan, docs_url=None, redoc_url=None)


def _extract_serial_from_ocsp_request(der: bytes) -> tuple[str, str]:
    """Returns (ca_name placeholder, serial_hex). A real implementation maps
    the issuer name/key hash in the request to a known CA; for simplicity we
    require the CA name as a URL path segment (`/ocsp/{ca_name}`)."""
    from asn1crypto import ocsp as a_ocsp

    req = a_ocsp.OCSPRequest.load(der)
    single = req["tbs_request"]["request_list"][0]
    serial = single["req_cert"]["serial_number"].native
    return format(serial, "x")


@app.post("/ocsp/{ca_name}")
async def ocsp_post(ca_name: str, request: Request):
    body = await request.body()
    return _handle(ca_name, body)


@app.get("/ocsp/{ca_name}/{b64_request}")
async def ocsp_get(ca_name: str, b64_request: str):
    import base64

    der = base64.b64decode(b64_request)
    return _handle(ca_name, der)


def _handle(ca_name: str, der: bytes) -> Response:
    import time

    try:
        serial_hex = _extract_serial_from_ocsp_request(der)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(400, f"Malformed OCSP request: {exc}") from exc

    cache_key = f"{ca_name}:{serial_hex}"
    cached = _CACHE.get(cache_key)
    now = time.time()
    if cached and (now - cached[0]) < _CACHE_TTL_SECONDS:
        return Response(content=cached[1], media_type="application/ocsp-response")

    der_response = ca_client.sign_ocsp(ca_name=ca_name, serial_number=serial_hex)
    _CACHE[cache_key] = (now, der_response)
    return Response(content=der_response, media_type="application/ocsp-response")


@app.get("/healthz")
def healthz():
    return {"status": "ok"}
