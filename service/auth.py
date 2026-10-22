"""REST bearer/JWT protection and safe loopback-only unauthenticated mode."""

from __future__ import annotations

import ipaddress
import os

from fastapi import Header, HTTPException, Request


def _loopback(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return value in {"localhost", "testclient"}


async def require_service_auth(request: Request, authorization: str | None = Header(default=None)) -> None:
    service_token = os.getenv("CYBERMAP_SERVICE_TOKEN", "")
    bind_host = os.getenv("CYBERMAP_BIND_HOST", "127.0.0.1")
    if not service_token:
        # The environment variable only states the *intended* bind address; the guarantee in
        # SECURITY.md ("unauthenticated mode is loopback-only") must hold for the connection that
        # actually arrived. Measured hole before this check: `uvicorn --host 0.0.0.0` with the
        # variable unset served /v1/account and /v1/search unauthenticated over the LAN.
        client_host = request.client.host if request.client else ""
        if not _loopback(bind_host) or not _loopback(client_host):
            raise HTTPException(
                status_code=503,
                detail="unauthenticated service is loopback-only; set CYBERMAP_SERVICE_TOKEN to expose it",
            )
        return
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Bearer token required")
    token = authorization.removeprefix("Bearer ").strip()
    if token == service_token:
        return
    public_key = os.getenv("CYBERMAP_JWT_PUBLIC_KEY", "")
    issuer = os.getenv("CYBERMAP_JWT_ISSUER", "")
    audience = os.getenv("CYBERMAP_JWT_AUDIENCE", "cybermap")
    if public_key and issuer:
        try:
            import jwt  # type: ignore

            jwt.decode(token, public_key, algorithms=["RS256", "ES256"], issuer=issuer, audience=audience)
            return
        except Exception as exc:
            raise HTTPException(status_code=401, detail="invalid JWT") from exc
    raise HTTPException(status_code=401, detail="invalid bearer token")
