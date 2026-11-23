import asyncio
import copy
import time
from pathlib import Path

import grpc
import httpx
import jwt
import pytest
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from google.protobuf import json_format, struct_pb2

from interceptor import convert, server
from interceptor.protos import extension_pb2, gateway_interceptor_pb2 as gi, gateway_interceptor_pb2_grpc as gi_grpc
from interceptor.rules import Governance
from policy_compiler import compile_policy
from policy_compiler.bundle import document

ROOT = Path(__file__).parents[3]
DOC = document(yaml.safe_load((ROOT / "policies" / "backend-dev.yaml").read_text()))
PLATFORM = {"llm_gateway_host": "llm-gateway.company.internal", "policy_api_host": "policy-api.company.internal"}
ISSUED = compile_policy(DOC, "/workspace", PLATFORM)
NAME = "agent-kim-0a1b2c3d-4e5f6a7b"
PROVIDERS = {f"{NAME}-llm": "tether-llm", f"{NAME}-policy": "tether-policy", f"{NAME}-github": "github-org"}
AUTH = {"authorized": True, "sandbox_name": NAME, "session_id": "sid-1", "user_id": "kim", "policy_version": 2,
        "policy_hash": "abc", "openshell_policy": ISSUED, "providers": PROVIDERS}
PROFILES = server.load_profiles(str(ROOT / "openshell" / "profiles"))
GATEWAY_META = extension_pb2.PeerMetadata(protocol_version=extension_pb2.ProtocolVersion(major=1, minor=0),
                                          supported_capabilities=["openshell.gateway-interceptor.contract"])


class PolicyAPI:
    def __init__(self, status=200):
        self.status, self.calls = status, []

    def handle(self, req):
        self.calls.append(req)
        assert req.headers["authorization"] == "Bearer interceptor-secret"
        name = req.url.path.split("/")[3]
        if self.status != 200:
            return httpx.Response(self.status)
        return httpx.Response(200, json=AUTH) if name == NAME else httpx.Response(404, json={"detail": "no"})


@pytest.fixture
def api(monkeypatch):
    a = PolicyAPI()
    monkeypatch.setattr(server, "policy_transport", httpx.MockTransport(a.handle))
    monkeypatch.setenv("INTERCEPTOR_TOKEN", "interceptor-secret")
    return a


def run(coro):
    return asyncio.run(coro)


async def with_stub(fn, verifier=None):
    svc = server.Service(Governance(server.policy_api_authorize, {p.id for p in PROFILES}, {"registry.company.internal/agent:1"}),
                         PROFILES, "urn:test", verifier)
    srv = grpc.aio.server()
    gi_grpc.add_GatewayInterceptorServicer_to_server(svc, srv)
    port = srv.add_insecure_port("127.0.0.1:0")
    await srv.start()
    try:
        async with grpc.aio.insecure_channel(f"127.0.0.1:{port}") as ch:
            return await fn(gi_grpc.GatewayInterceptorStub(ch))
    finally:
        await srv.stop(None)


def struct(d):
    s = struct_pb2.Struct()
    json_format.ParseDict(d, s)
    return s


def evaluate(method, phase, op, principal=None, metadata=None, verifier=None):
    payload = {"modify_operation": lambda: gi.InterceptorEvaluation(modify_operation=gi.ModifyOperationEvaluation(proposed_operation=struct(op))),
               "validate": lambda: gi.InterceptorEvaluation(validate=gi.ValidateEvaluation(proposed_operation=struct(op)))}[phase]()
    payload.method, payload.service = method, "openshell.v1.OpenShell"
    payload.principal.update(principal or {"kind": "user", "subject": "orchestrator"})
    return run(with_stub(lambda stub: stub.Evaluate(payload, metadata=metadata), verifier))


def apply_patches(op, patches):
    """Minimal RFC 6902 `add` (the only op the interceptor emits), as the gateway applies it."""
    op = copy.deepcopy(op)
    for p in patches:
        assert p.op == "add"
        parts = [s.replace("~1", "/").replace("~0", "~") for s in p.path.split("/")[1:]]
        target = op
        for part in parts[:-1]:
            target = target[part]
        target[parts[-1]] = json_format.MessageToDict(p.value)
    return op


def create_op(policy=None, providers=None, **extra):
    spec = {"policy": policy if policy is not None else convert.to_json(convert.sandbox_policy(ISSUED)),
            "providers": providers if providers is not None else sorted(PROVIDERS)}
    return {"name": NAME, "spec": spec, **extra}


WIDE = copy.deepcopy(ISSUED)
WIDE["network_policies"]["evil"] = {"name": "evil", "endpoints": [{"host": "evil.example.com", "port": 443, "protocol": "rest",
                                                                   "enforcement": "enforce", "access": "full"}], "binaries": [{"path": "/usr/bin/curl"}]}
WIDE_JSON = convert.to_json(convert.sandbox_policy(WIDE))


# --- conversion ---------------------------------------------------------------------

def test_compiled_policy_round_trips_through_protobuf_json():
    msg = convert.sandbox_policy(ISSUED)
    assert convert.policy_from_json(convert.to_json(msg)) == msg
    j = convert.to_json(msg)
    assert j["filesystem"]["readWrite"][0] == "/workspace" and j["process"]["runAsUser"] == "sandbox"
    gh = next(r for r in j["networkPolicies"].values() if r["endpoints"][0]["host"] == "github.com")
    assert gh["endpoints"][0]["enforcement"] == "NETWORK_ENFORCEMENT_MODE_ENFORCE" and "access" not in gh["endpoints"][0]


@pytest.mark.parametrize("bad", [{"surprise": 1}, {"network_policies": {"x": {"endpoints": [{"host": "a", "access": "everything"}]}}},
                                 {"network_policies": {"x": {"endpoints": [{"host": "a", "access": "full", "rules": []}]}}}])
def test_conversion_fails_closed_on_unknown_shapes(bad):
    with pytest.raises(convert.ConversionError):
        convert.sandbox_policy({**ISSUED, **bad})


# --- manifest and profiles -------------------------------------------------------------

def test_describe_manifest(api):
    m = run(with_stub(lambda s: s.Describe(gi.DescribeRequest(gateway=GATEWAY_META))))
    rpcs = {b.selector.rpc: list(b.phases) for b in m.bindings}
    assert rpcs["openshell.v1.OpenShell/CreateSandbox"] == [gi.GATEWAY_INTERCEPTOR_PHASE_MODIFY_OPERATION, gi.GATEWAY_INTERCEPTOR_PHASE_VALIDATE]
    for must in ("UpdateConfig", "AttachSandboxProvider", "CreateProvider", "ImportProviderProfiles", "ApproveDraftChunk", "CreateSshSession", "ExposeService"):
        assert f"openshell.v1.OpenShell/{must}" in rpcs
    for teardown in ("DeleteSandbox", "DetachSandboxProvider", "DeleteProvider"):
        assert f"openshell.v1.OpenShell/{teardown}" not in rpcs  # always available to incident response
    assert m.failure_policy == "fail_closed" and all(b.failure_policy == "fail_closed" for b in m.bindings)
    assert m.provider_profiles and m.expected_audience == "urn:test"
    assert m.extension.protocol_version.major == 1 and m.extension.required_capabilities == ["openshell.gateway-interceptor.contract"]


def test_describe_rejects_incompatible_gateway(api):
    bad = extension_pb2.PeerMetadata(protocol_version=extension_pb2.ProtocolVersion(major=2))
    with pytest.raises(grpc.aio.AioRpcError) as e:
        run(with_stub(lambda s: s.Describe(gi.DescribeRequest(gateway=bad))))
    assert e.value.code() == grpc.StatusCode.FAILED_PRECONDITION


def test_vends_only_company_profiles(api):
    snap = run(with_stub(lambda s: s.SnapshotProviderProfiles(gi.ProviderProfileSnapshotRequest())))
    assert [p.id for p in snap.profiles] == ["github-org", "tether-llm", "tether-policy"]
    assert snap.revision.startswith("sha256:")


# --- CreateSandbox ------------------------------------------------------------------------

def test_create_gets_issued_policy_and_providers_whatever_was_sent(api):
    attacker = create_op(policy=WIDE_JSON, providers=sorted(PROVIDERS) + ["stock-github"], annotations={"x": "y"})
    m = evaluate("CreateSandbox", "modify_operation", attacker)
    assert m.allowed
    patched = apply_patches(attacker, m.patches)
    assert convert.policy_from_json(patched["spec"]["policy"]) == convert.sandbox_policy(ISSUED)
    assert patched["spec"]["providers"] == sorted(PROVIDERS)
    assert patched["annotations"]["tether/session-id"] == "sid-1" and patched["annotations"]["x"] == "y"
    assert m.log_annotations["user"] == "kim"
    assert evaluate("CreateSandbox", "validate", patched).allowed


def test_create_patches_missing_spec(api):
    op = {"name": NAME}
    m = evaluate("CreateSandbox", "modify_operation", op)
    patched = apply_patches(op, m.patches)
    assert evaluate("CreateSandbox", "validate", patched).allowed


@pytest.mark.parametrize("op,reason", [
    ({"name": "agent-made-up-00000000-00000000", "spec": {}}, "no active session"),
    ({"spec": {}}, "issued by the Policy API"),
])
def test_create_without_issued_name_denied(api, op, reason):
    r = evaluate("CreateSandbox", "modify_operation", op)
    assert not r.allowed and reason in r.reason and r.status_code == "PERMISSION_DENIED"


@pytest.mark.parametrize("op,reason", [
    (create_op(policy=WIDE_JSON), "policy differs"),
    (create_op(providers=sorted(PROVIDERS) + ["stock-github"]), "providers differ"),
    (create_op(providers=sorted(PROVIDERS)[:1]), "providers differ"),
    (create_op(serviceExposures=[{"name": "web"}]), "exposing services"),
    (create_op(workloadTemplate="permissive"), "workload templates"),
    (create_op(policy={"bogusField": 1}), "unparseable"),
])
def test_create_validate_catches_anything_left_wide(api, op, reason):
    r = evaluate("CreateSandbox", "validate", op)
    assert not r.allowed and reason in r.reason


def test_create_image_allowlist(api):
    op = create_op()
    op["spec"]["template"] = {"image": "docker.io/attacker/agent:latest"}
    assert "not an approved agent image" in evaluate("CreateSandbox", "validate", op).reason
    op["spec"]["template"] = {"image": "registry.company.internal/agent:1"}
    assert evaluate("CreateSandbox", "validate", op).allowed


def test_policy_api_unreachable_fails_closed(api):
    api.status = 500
    with pytest.raises(grpc.aio.AioRpcError) as e:
        evaluate("CreateSandbox", "modify_operation", create_op())
    assert e.value.code() == grpc.StatusCode.UNAVAILABLE


# --- UpdateConfig ------------------------------------------------------------------------------

ISSUED_JSON = convert.to_json(convert.sandbox_policy(ISSUED))


@pytest.mark.parametrize("op,allowed", [
    ({"sandbox": NAME, "policy": ISSUED_JSON}, True),
    ({"sandbox": NAME, "policy": WIDE_JSON}, False),
    ({"sandbox": NAME, "mergeOperations": [{"addRule": {}}]}, False),
    ({"sandbox": "agent-other-1-2", "policy": ISSUED_JSON}, False),
    ({"sandbox": NAME, "settingKey": "some_setting", "settingValue": {"stringValue": "x"}}, False),
    ({"sandbox": NAME, "settingKey": "proposal_approval_mode", "settingValue": {"stringValue": "auto"}}, False),
    ({"global": True, "policy": ISSUED_JSON}, False),
    ({"global": True, "settingKey": "proposal_approval_mode", "settingValue": {"stringValue": "auto"}}, False),
    ({"global": True, "settingKey": "log_level", "settingValue": {"stringValue": "debug"}}, False),
])
def test_update_config(api, op, allowed):
    assert evaluate("UpdateConfig", "validate", op).allowed is allowed


def test_global_settings_for_platform_admins_only(api):
    op = {"global": True, "settingKey": "log_level", "settingValue": {"stringValue": "debug"}}
    assert evaluate("UpdateConfig", "validate", op, principal={"kind": "user", "roles": "openshell-user,openshell-platform-admin"}).allowed
    admin = {"kind": "user", "roles": "openshell-platform-admin"}
    assert not evaluate("UpdateConfig", "validate", {"global": True, "policy": ISSUED_JSON}, principal=admin).allowed


# --- providers -------------------------------------------------------------------------------------

@pytest.mark.parametrize("name,ptype,allowed", [
    (f"{NAME}-github", "github-org", True),
    (f"{NAME}-llm", "tether-llm", True),
    (f"{NAME}-github", "github", False),                   # stock profile: not vended
    (f"{NAME}-llm", "github-org", False),                   # wrong profile for the name
    (f"{NAME}-aws", "tether-aws", False),                  # not issued to this session
    ("agent-made-up-0-0-github", "github-org", False),      # no active session
    ("my-personal-token", "tether-llm", False),
])
def test_create_provider(api, name, ptype, allowed):
    op = {"provider": {"metadata": {"name": name}, "type": ptype}}
    assert evaluate("CreateProvider", "validate", op).allowed is allowed
    assert evaluate("UpdateProvider", "validate", op).allowed is allowed


@pytest.mark.parametrize("provider,allowed", [(f"{NAME}-github", True), ("stock-github", False), ("agent-x-1-2-github", False)])
def test_attach_provider(api, provider, allowed):
    assert evaluate("AttachSandboxProvider", "validate", {"sandbox": NAME, "provider": provider}).allowed is allowed


# --- everything else that could widen or open access ---------------------------------------------------

@pytest.mark.parametrize("method", ["ImportProviderProfiles", "UpdateProviderProfiles", "DeleteProviderProfile", "ApproveDraftChunk",
                                    "ApproveAllDraftChunks", "EditDraftChunk", "UndoDraftChunk", "CreateSshSession", "ExposeService",
                                    "ConfigureProviderRefresh", "RotateProviderCredential", "SomeFutureMethod"])
def test_widening_and_side_doors_denied(api, method):
    assert not evaluate(method, "validate", {"sandbox": NAME}).allowed


def test_policy_analysis(api):
    sandbox = {"kind": "sandbox", "sandbox_id": "x"}
    assert evaluate("SubmitPolicyAnalysis", "validate", {"summaries": []}, principal=sandbox).allowed
    assert not evaluate("SubmitPolicyAnalysis", "validate", {"proposedChunks": [{"x": 1}]}, principal=sandbox).allowed
    assert not evaluate("SubmitPolicyAnalysis", "validate", {}, principal={"kind": "user"}).allowed


# --- gateway authentication -------------------------------------------------------------------------------

KEY = Ed25519PrivateKey.generate()
PUB = KEY.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def token(key=KEY, typ="openshell-ext+jwt", **claims):
    c = {"iss": "openshell-gateway:gw-1", "aud": "urn:test", "exp": int(time.time()) + 60, "caller_kind": "gateway", **claims}
    return jwt.encode(c, key, algorithm="EdDSA", headers={"typ": typ})


@pytest.mark.parametrize("tok,ok", [
    (token(), True),
    (token(aud="urn:other"), False),
    (token(iss="https://gateway.example"), False),
    (token(caller_kind="supervisor"), False),
    (token(typ="JWT"), False),
    (token(exp=int(time.time()) - 600), False),
    (token(key=Ed25519PrivateKey.generate()), False),
    ("", False),
])
def test_gateway_token_required(api, tok, ok):
    verifier = server.gateway_token_verifier(PUB, "gw-1", "urn:test")
    call = lambda: evaluate("CreateSandbox", "modify_operation", create_op(), metadata=(("authorization", f"Bearer {tok}"),), verifier=verifier)
    if ok:
        assert call().allowed
    else:
        with pytest.raises(grpc.aio.AioRpcError) as e:
            call()
        assert e.value.code() == grpc.StatusCode.UNAUTHENTICATED


def test_gateway_config_matches_manifest_exactly():
    import tomllib
    from interceptor.rules import BINDINGS
    cfg = tomllib.loads((ROOT / "infra" / "openshell" / "gateway-interceptor.toml").read_text())
    ic = cfg["openshell"]["gateway"]["interceptors"][0]
    assert (ic["failure_policy"], ic["binding_policy"], ic["name"]) == ("fail_closed", "exact", "tether-governance")
    assert ic["audience"] == "urn:openshell:extension:interceptor:tether-governance"
    configured = {b["rpc"].split("/")[1]: tuple(b["phases"]) for b in ic["bindings"]}
    assert configured == BINDINGS
    assert cfg["openshell"]["gateway"]["provider_profile_sources"] == [{"type": "interceptor", "name": "tether-governance"}]
