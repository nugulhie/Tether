"""gRPC GatewayInterceptor service: Describe, Evaluate, SnapshotProviderProfiles."""
import asyncio
import hashlib
import json
import logging
import os
from pathlib import Path

import grpc
import httpx
import jwt
import yaml
from google.protobuf import json_format, struct_pb2

from . import convert
from .protos import extension_pb2, gateway_interceptor_pb2 as gi, gateway_interceptor_pb2_grpc as gi_grpc, openshell_pb2
from .rules import BINDINGS, Governance

log = logging.getLogger("gateway-interceptor")
PHASES = {"modify_operation": gi.GATEWAY_INTERCEPTOR_PHASE_MODIFY_OPERATION, "validate": gi.GATEWAY_INTERCEPTOR_PHASE_VALIDATE}
CONTRACT = "openshell.gateway-interceptor.contract"
policy_transport = None  # overridable in tests


def env(name, default=""):
    return os.environ.get(name, default)


def load_profiles(directory: str) -> list[openshell_pb2.ProviderProfile]:
    """Company profiles; the file name is the profile id. Any invalid file stops startup."""
    profiles = []
    for f in sorted(Path(directory).glob("*.yaml")):
        profiles.append(convert.provider_profile(f.stem, yaml.safe_load(f.read_text())))
    if not profiles:
        raise SystemExit(f"no provider profiles in {directory}")
    return profiles


async def policy_api_authorize(name: str) -> dict | None:
    if not name:
        return None
    async with httpx.AsyncClient(timeout=3, transport=policy_transport) as c:
        r = await c.get(f"{env('POLICY_API', 'http://localhost:8080')}/v1/sandboxes/{name}/authorization",
                        headers={"Authorization": f"Bearer {env('INTERCEPTOR_TOKEN')}"})
    if r.status_code == 404:
        return None
    r.raise_for_status()  # anything else is an interceptor failure -> gateway fails closed
    return r.json()


class Service(gi_grpc.GatewayInterceptorServicer):
    def __init__(self, governance: Governance, profiles: list, audience: str, verifier=None):
        self.governance, self.profiles, self.audience, self.verifier = governance, profiles, audience, verifier
        digest = hashlib.sha256(b"".join(p.SerializeToString(deterministic=True) for p in profiles)).hexdigest()
        self.revision = f"sha256:{digest}"

    async def _authenticate(self, context):
        if self.verifier is None:
            return
        auth = dict(context.invocation_metadata()).get("authorization", "")
        try:
            self.verifier(auth[7:] if auth.lower().startswith("bearer ") else "")
        except jwt.PyJWTError as e:
            await context.abort(grpc.StatusCode.UNAUTHENTICATED, f"invalid gateway token: {e}")

    async def Describe(self, request, context):
        await self._authenticate(context)
        if request.gateway.protocol_version.major != 1 or CONTRACT not in request.gateway.supported_capabilities:
            await context.abort(grpc.StatusCode.FAILED_PRECONDITION, "gateway does not speak gateway-interceptor protocol 1")
        return gi.InterceptorManifest(
            name="tether-governance", failure_policy="fail_closed", provider_profiles=True, expected_audience=self.audience,
            bindings=[gi.InterceptorBinding(id=f"tether-{m}", selector=gi.InterceptorSelector(rpc=f"openshell.v1.OpenShell/{m}"),
                                            phases=[PHASES[p] for p in phases], failure_policy="fail_closed")
                      for m, phases in BINDINGS.items()],
            extension=extension_pb2.PeerMetadata(
                protocol_version=extension_pb2.ProtocolVersion(major=1, minor=0), implementation_name="tether/governance",
                implementation_version="0.1.0", supported_capabilities=[CONTRACT], required_capabilities=[CONTRACT]))

    async def SnapshotProviderProfiles(self, request, context):
        await self._authenticate(context)
        return gi.ProviderProfileSnapshot(revision=self.revision, profiles=self.profiles)

    async def Evaluate(self, request, context):
        await self._authenticate(context)
        phase = request.WhichOneof("phase")
        if phase == "post_commit":
            return gi.InterceptorResult(allowed=True)
        op = json_format.MessageToDict(getattr(request, phase).proposed_operation)
        try:
            r = await self.governance.evaluate(request.method, phase, op, dict(request.principal))
        except (httpx.HTTPError, convert.ConversionError) as e:
            # Not a decision: abort so the gateway applies the binding's fail_closed policy.
            log.error("evaluation failed for %s/%s: %s", request.method, phase, e)
            await context.abort(grpc.StatusCode.UNAVAILABLE, "governance check unavailable")
        log.info(json.dumps({"method": request.method, "phase": phase, "allowed": r.allowed, "reason": r.reason,
                             "principal": dict(request.principal).get("subject", dict(request.principal).get("kind"))}))
        out = gi.InterceptorResult(allowed=r.allowed, reason=r.reason, status_code=r.status_code, log_annotations=r.log_annotations)
        for p in r.patches:
            value = struct_pb2.Value()
            json_format.ParseDict(p["value"], value)
            out.patches.append(gi.JsonPatch(op=p["op"], path=p["path"], value=value))
        return out


def gateway_token_verifier(public_key_pem: str, gateway_id: str, audience: str):
    """Gateway-issued extension tokens: EdDSA, typ openshell-ext+jwt, iss openshell-gateway:<id>."""
    def verify(token: str):
        if jwt.get_unverified_header(token).get("typ") != "openshell-ext+jwt":
            raise jwt.InvalidTokenError("unexpected token type")
        claims = jwt.decode(token, public_key_pem, algorithms=["EdDSA"], audience=audience, issuer=f"openshell-gateway:{gateway_id}",
                            options={"require": ["exp", "iss", "aud"]})
        if claims.get("caller_kind") != "gateway":
            raise jwt.InvalidTokenError("caller_kind must be gateway")
    return verify


def build_service() -> Service:
    audience = env("INTERCEPTOR_AUDIENCE", "urn:openshell:extension:interceptor:tether-governance")
    profiles = load_profiles(env("PROFILES_DIR", "/profiles"))
    governance = Governance(policy_api_authorize, {p.id for p in profiles},
                            {i for i in env("ALLOWED_SANDBOX_IMAGES").split(",") if i}, env("PLATFORM_ADMIN_ROLE", "openshell-platform-admin"))
    if env("INTERCEPTOR_ALLOW_UNAUTHENTICATED") == "1":  # local development only
        verifier = None
    else:
        key = env("GATEWAY_EXTENSION_PUBLIC_KEY") or Path(env("GATEWAY_EXTENSION_PUBLIC_KEY_FILE", "/nonexistent")).read_text()
        verifier = gateway_token_verifier(key, env("GATEWAY_ID") or exit("GATEWAY_ID is required"), audience)
    return Service(governance, profiles, audience, verifier)


async def serve():
    logging.basicConfig(level=logging.INFO)
    server = grpc.aio.server()
    gi_grpc.add_GatewayInterceptorServicer_to_server(build_service(), server)
    addr = env("LISTEN", "0.0.0.0:18081")
    if env("TLS_CERT_FILE"):
        creds = grpc.ssl_server_credentials([(Path(env("TLS_KEY_FILE")).read_bytes(), Path(env("TLS_CERT_FILE")).read_bytes())])
        server.add_secure_port(addr, creds)
    else:
        server.add_insecure_port(addr)  # only behind a TLS-terminating, authenticated hop
    await server.start()
    log.info("gateway interceptor listening on %s", addr)
    await server.wait_for_termination()


if __name__ == "__main__":
    asyncio.run(serve())
