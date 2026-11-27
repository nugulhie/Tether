"""Caller authentication for the Policy API.

Three kinds of callers:
- user:    a developer, via an OIDC ID token (launcher, credential broker on the user's behalf), or with
           AUTH_MODE=mtls a short-lived token this API issues to a verified client certificate
           (POST /v1/auth/token through the mTLS front; see client_identity)
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
import ipaddress
import json
import os
import urllib.request
import re
import secrets
import time
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


USER_TOKEN_ISSUER = "tether-policy-api"
USER_TOKEN_AUDIENCE = "tether"
USER_NAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,62}")


def _user_token_key() -> str:
    key = env("USER_TOKEN_KEY")
    if len(key) < 32:
        raise HTTPException(500, "USER_TOKEN_KEY is not configured (at least 32 characters)")
    return key


def admin_users() -> set[str]:
    return {u.strip() for u in env("ADMIN_USERS").split(",") if u.strip()}


def issue_user_token(user: str) -> tuple[str, int]:
    """AUTH_MODE=mtls: a bearer token for the person a client certificate names. Short-lived, so a
    certificate taken off the front's trust (CRL) stops working within the TTL."""
    ttl = int(env("USER_TOKEN_TTL_SECONDS", "3600"))
    now = int(time.time())
    groups = [g for g in env("ADMIN_GROUPS", "tether-admins").split(",") if g][:1] if user in admin_users() else []
    claims = {"iss": USER_TOKEN_ISSUER, "aud": USER_TOKEN_AUDIENCE, "sub": user, "groups": groups, "iat": now, "exp": now + ttl}
    return jwt.encode(claims, _user_token_key(), algorithm="HS256"), now + ttl


def client_identity(request: Request) -> tuple[str, str | None]:
    """(user, certificate serial) asserted by the mTLS front for a verified client certificate.

    Trusted only from IDENTITY_PROXY_ADDRESSES (the front's fixed address): the front verifies the
    certificate against the user CA and overwrites these headers; any other peer could set them."""
    proxies = [ipaddress.ip_network(a.strip(), strict=False) for a in env("IDENTITY_PROXY_ADDRESSES").split(",") if a.strip()]
    peer = request.client.host if request.client else ""
    try:
        trusted = any(ipaddress.ip_address(peer) in n for n in proxies)
    except ValueError:
        trusted = False
    if not trusted:
        raise HTTPException(403, "client certificate identity is accepted only from the mTLS front")
    subject = request.headers.get(env("CLIENT_SUBJECT_HEADER", "x-tether-client-subject"), "")
    # RFC 2253 subject, e.g. "CN=kim,O=Tether". Names are restricted, so no escaped commas can occur.
    cns = [part.strip()[3:] for part in subject.split(",") if part.strip().upper().startswith("CN=")]
    if len(cns) != 1 or not USER_NAME.fullmatch(cns[0]):
        raise HTTPException(401, "client certificate required")
    return cns[0], request.headers.get(env("CLIENT_SERIAL_HEADER", "x-tether-client-serial")) or None


def verify_user_token(token: str) -> tuple[str, tuple[str, ...]]:
    """Return (user id, groups) from an OIDC ID token (or, with AUTH_MODE=mtls, a token from issue_user_token)."""
    if env("AUTH_MODE", "oidc") == "mtls":
        try:
            claims = jwt.decode(token, _user_token_key(), algorithms=["HS256"], audience=USER_TOKEN_AUDIENCE, issuer=USER_TOKEN_ISSUER,
                                options={"require": ["exp", "iat", "iss", "aud", "sub"]}, leeway=30)
        except jwt.PyJWTError as e:
            raise HTTPException(401, f"invalid token: {e}", headers={"WWW-Authenticate": "Bearer"})
        user = claims["sub"]
        if not isinstance(user, str) or not USER_NAME.fullmatch(user):
            raise HTTPException(401, "token has no user")
        groups = claims.get("groups") or []
        return user, tuple(g for g in groups if isinstance(g, str))
    if env("AUTH_MODE", "oidc") == "dev":
        # Local development only: "dev:<user>[:<group>,<group>]" is accepted without verification.
        _, user, groups = (token.split(":", 2) + ["", ""])[:3]
        if not token.startswith("dev:") or not user:
            raise HTTPException(401, "dev mode expects a 'dev:<user>[:<groups>]' token")
        return user, tuple(g for g in groups.split(",") if g)
    issuer, audience = env("OIDC_ISSUER"), env("OIDC_AUDIENCE")
    if not (issuer and audience):
        raise HTTPException(500, "OIDC is not configured")
    domains = hosted_domains()
    if issuer.rstrip("/") in GOOGLE_ISSUERS and not domains:
        # A Google client ID accepts any Google account unless the Workspace domain (hd) is checked.
        raise HTTPException(500, "OIDC_HOSTED_DOMAINS must be set for Google sign-in")
    try:
        key = _jwks(env("OIDC_JWKS_URL") or jwks_uri(issuer)).get_signing_key_from_jwt(token).key
        claims = jwt.decode(token, key, algorithms=["RS256", "ES256"], audience=audience, issuer=issuer,
                            options={"require": ["exp", "iat", "iss", "aud"]}, leeway=30)
    except (jwt.PyJWTError, OSError, ValueError, KeyError) as e:
        raise HTTPException(401, f"invalid token: {e}", headers={"WWW-Authenticate": "Bearer"})
    if domains and claims.get("hd") not in domains:
        raise HTTPException(401, "token is not from an allowed organization (hd)")
    user_claim = env("OIDC_USER_CLAIM", "email")
    user = claims.get(user_claim)
    if not isinstance(user, str) or not user:
        raise HTTPException(401, "token has no user claim")
    if user_claim == "email":
        # An unverified address is a name anyone can type; IdPs that omit the claim verify addresses themselves.
        if claims.get("email_verified") in (False, "false"):
            raise HTTPException(401, "token email is not verified")
        user = user.lower()
    groups = claims.get(env("OIDC_GROUPS_CLAIM", "groups")) or []
    return user, tuple(g for g in groups if isinstance(g, str)) if isinstance(groups, list) else ()


GOOGLE_ISSUERS = {"https://accounts.google.com", "accounts.google.com"}


def hosted_domains() -> set[str]:
    """OIDC_HOSTED_DOMAINS: the Google Workspace domains (hd claim) whose accounts may sign in."""
    return {d.strip().lower() for d in env("OIDC_HOSTED_DOMAINS").split(",") if d.strip()}


@lru_cache(maxsize=4)
def _discovery(issuer: str) -> dict:
    with urllib.request.urlopen(issuer.rstrip("/") + "/.well-known/openid-configuration", timeout=10) as r:
        return json.load(r)


def jwks_uri(issuer: str) -> str:
    """The IdP's signing keys, from its discovery document (OIDC_JWKS_URL overrides)."""
    return _discovery(issuer)["jwks_uri"]


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
    """A person in ADMIN_GROUPS (IdP groups), or named in ADMIN_USERS (certificate names, or with OIDC the
    sign-in e-mail: Google ID tokens carry no groups)."""
    admins = {g for g in env("ADMIN_GROUPS", "tether-admins").split(",") if g}
    if p.kind != "user":
        return False
    return bool(admins & set(p.groups)) or p.user_id.lower() in {u.lower() for u in admin_users()}
