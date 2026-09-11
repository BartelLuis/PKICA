from __future__ import annotations

import asyncio
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.responses import Response

from pkicore.ca_client import CAClient
from pkicore.config import get_settings
from pkicore.logging import configure_logging, get_logger

settings = get_settings()
configure_logging("crl", settings.log_level, settings.log_json)
log = get_logger(__name__)

ca_client = CAClient(settings)

_CRL_CACHE: dict[str, tuple[float, bytes]] = {}
_REFRESH_SECONDS = 900  # regenerate at most every 15 minutes per CA


@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("crl_service_started")
    yield


app = FastAPI(title="PKICA - CRL Publisher", lifespan=lifespan, docs_url=None, redoc_url=None)


@app.get("/crl/{ca_name}.crl")
def get_crl(ca_name: str):
    now = time.time()
    cached = _CRL_CACHE.get(ca_name)
    if cached and (now - cached[0]) < _REFRESH_SECONDS:
        return Response(content=cached[1], media_type="application/pkix-crl")
    try:
        der = ca_client.fetch_crl(ca_name)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(502, f"Unable to fetch CRL from CA: {exc}") from exc
    _CRL_CACHE[ca_name] = (now, der)
    return Response(content=der, media_type="application/pkix-crl")


@app.get("/healthz")
def healthz():
    return {"status": "ok"}
