"""Caller authentication for the Policy API.

Three kinds of callers:
- user:    a developer, via an OIDC ID token (launcher, credential broker on the user's behalf)
- session: an agent session, via the opaque session token issued at session creation
           (Permission MCP inside the sandbox). Identity comes from the stored session,
           never from the request body.
- service: an internal service, via a shared service token: the credential broker
           (CREDENTIAL_BROKER_TOKEN), the CI policy publisher (POLICY_PUBLISHER_TOKEN)
           the SIEM collector (SIEM_TOKEN), the LLM gateway (LLM_GATEWAY_TOKEN) or the
           sandbox orchestrator (ORCHESTRATOR_TOKEN) or the OpenShell gateway interceptor
           (INTERCEPTOR_TOKEN).

Settings are read per call so tests and deployments can change them via environment.
"""
import hashlib
import os
import secrets
from dataclasses import dataclass
from functools import lru_cache

import jwt
from fastapi import HTTPException, Request

SESSION_TOKEN_PREFIX = "ast_"


@dataclass(frozen=True)
class Principal:
    kind: str  # "user" | "session" | "service"
    user_id: str
    groups: tuple[str, ...] = ()
    device_id: str | None = None
    device_verified: bool = False
    session_id: str | None = None


def env(name, default=""):
    return os.environ.get(name, default)


def bearer(request: Request) -> str:
    h = request.headers.get("authorization", "")
    scheme, _, token = h.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(401, "missing bearer token", headers={"WWW-Authenticate": "Bearer"})
    return token.strip()


def new_session_token() -> tuple[str, str]:
    token = SESSION_TOKEN_PREFIX + secrets.token_urlsafe(32)
    return token, hash_token(token)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


@lru_cache(maxsize=4)
def _jwks(url):
    return jwt.PyJWKClient(url, cache_keys=True)


def verify_user_token(token: str) -> tuple[str, tuple[str, ...]]:
    """Return (user id, groups) from an OIDC ID token."""
    if env("AUTH_MODE", "oidc") == "dev":
        # Local development only: "dev:<user>[:<group>,<group>]" is accepted without verification.
        _, user, groups = (token.split(":", 2) + ["", ""])[:3]
        if not token.startswith("dev:") or not user:
            raise HTTPException(401, "dev mode expects a 'dev:<user>[:<groups>]' token")
        return user, tuple(g for g in groups.split(",") if g)
    issuer, audience, jwks_url = env("OIDC_ISSUER"), env("OIDC_AUDIENCE"), env("OIDC_JWKS_URL")
    if not (issuer and audience and jwks_url):
        raise HTTPException(500, "OIDC is not configured")
    try:
        key = _jwks(jwks_url).get_signing_key_from_jwt(token).key
        claims = jwt.decode(token, key, algorithms=["RS256", "ES256"], audience=audience, issuer=issuer,
                            options={"require": ["exp", "iat", "iss", "aud"]}, leeway=30)
    except jwt.PyJWTError as e:
        raise HTTPException(401, f"invalid token: {e}", headers={"WWW-Authenticate": "Bearer"})
    user = claims.get(env("OIDC_USER_CLAIM", "email"))
    if not isinstance(user, str) or not user:
        raise HTTPException(401, "token has no user claim")
    groups = claims.get(env("OIDC_GROUPS_CLAIM", "groups")) or []
    return user, tuple(g for g in groups if isinstance(g, str)) if isinstance(groups, list) else ()


def verified_device(request: Request) -> str | None:
    """Device id asserted by the mTLS-terminating proxy, if one is configured.

    The proxy must verify the client certificate and overwrite this header; the API
    must not be reachable except through that proxy.
    """
    header = env("DEVICE_ID_HEADER")
    if not header:
        return None
    device = request.headers.get(header)
    if not device:
        raise HTTPException(401, "client certificate required")
    return device


SERVICES = {"CREDENTIAL_BROKER_TOKEN": "credential-broker", "POLICY_PUBLISHER_TOKEN": "policy-publisher", "SIEM_TOKEN": "siem",
            "LLM_GATEWAY_TOKEN": "llm-gateway", "ORCHESTRATOR_TOKEN": "sandbox-orchestrator",
            "INTERCEPTOR_TOKEN": "gateway-interceptor"}


def service_principal(token: str) -> Principal | None:
    for var, name in SERVICES.items():
        expected = env(var)
        if expected and secrets.compare_digest(token, expected):
            return Principal(kind="service", user_id=name)
    return None


def is_admin(p: Principal) -> bool:
    admins = {g for g in env("ADMIN_GROUPS", "agent-security-admins").split(",") if g}
    return p.kind == "user" and bool(admins & set(p.groups))
