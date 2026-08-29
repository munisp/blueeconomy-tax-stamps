"""FastAPI application assembly.

Boot is fail-closed:
- the signing key MUST load and MUST NOT be placeholder material;
- the PBAC policy directory MUST parse with at least one valid rule;
- when OIDC is configured the JWKS MUST load;
- without a database URL the service refuses to boot.

Optional integrations (Kafka, Redis, payment rail) do not block boot but are
reported unavailable in GET /v1/capabilities and their dependent routes
return 503.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from taxstamps.api.auth import JwksKeyring
from taxstamps.api.pbac import PolicyEngine
from taxstamps.api.routes_flow import router as flow_router
from taxstamps.api.routes_ops import router as ops_router
from taxstamps.api.routes_stamps import router as stamps_router
from taxstamps.api.routes_verify import router as verify_router
from taxstamps.config import get_settings
from taxstamps.crypto.eddsa import load_signing_key
from taxstamps.db import dispose_engine, init_engine
from taxstamps.services import redis_guard

log = logging.getLogger("taxstamps")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    if not settings.database_url:
        raise RuntimeError("TAXSTAMPS_DATABASE_URL is required")
    if not settings.signing_key_path:
        raise RuntimeError("TAXSTAMPS_SIGNING_KEY_PATH is required")
    if not settings.issuer_did:
        raise RuntimeError("TAXSTAMPS_ISSUER_DID is required")
    if not settings.policy_dir:
        raise RuntimeError("TAXSTAMPS_POLICY_DIR is required")
    app.state.settings = settings
    # Boot-fatal: placeholder/dummy key material refuses to boot here.
    app.state.signing_key = load_signing_key(settings.signing_key_path, settings.kid)
    # Boot-fatal: policy directory must be valid and non-empty.
    app.state.policy_engine = PolicyEngine.load(settings.policy_dir)
    # OIDC optional; when configured the JWKS must load or boot fails.
    app.state.keyring = JwksKeyring.load(settings) if settings.oidc_configured else None
    init_engine(settings.database_url)
    redis_guard.init_redis(settings)
    app.state.kafka_available = settings.kafka_configured
    log.info("blueeconomy-tax-stamps booted (kid=%s)", settings.kid)
    yield
    await redis_guard.close_redis()
    await dispose_engine()


app = FastAPI(
    title="blueeconomy-tax-stamps",
    version="0.1.0",
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


@app.exception_handler(RequestValidationError)
async def validation_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    return JSONResponse(
        status_code=422,
        media_type="application/problem+json",
        content={
            "type": "about:blank",
            "title": "Unprocessable Entity",
            "status": 422,
            "detail": "request validation failed; client-supplied totals are rejected — "
                      "pricing is computed server-side",
            "errors": exc.errors()[:10],
        },
    )


@app.exception_handler(Exception)
async def unhandled_handler(request: Request, exc: Exception) -> JSONResponse:
    log.exception("unhandled error on %s", request.url.path)
    return JSONResponse(
        status_code=500,
        media_type="application/problem+json",
        content={"type": "about:blank", "title": "Internal Server Error", "status": 500},
    )


app.include_router(ops_router)
app.include_router(flow_router)
app.include_router(stamps_router)
app.include_router(verify_router)


def run_api() -> None:
    settings = get_settings()
    uvicorn.run(
        "taxstamps.main:app",
        host=settings.http_host,
        port=settings.http_port,
        log_level="info",
    )


if __name__ == "__main__":
    run_api()
