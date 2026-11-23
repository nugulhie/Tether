"""Governance decisions for OpenShell gateway writes.

Invariant: a sandbox exists only if the Policy API issued its name to an active session, it
runs exactly that session's compiled policy, and it has exactly that session's providers, all
built from tether-vended profiles. Nothing at the gateway can widen it afterwards.

This holds even for a caller with valid gateway credentials, including stolen orchestrator
credentials, because the authority is the Policy API, not the caller.
"""
from dataclasses import dataclass, field
from typing import Awaitable, Callable

from google.protobuf import json_format

from . import convert

OPENSHELL = "openshell.v1.OpenShell"
SANDBOX_UPDATES = "openshell.v1.SandboxUpdates"
# Filesystem paths the OpenShell v0.1.9 supervisor adds to a policy with network rules and saves back with
# UpdateConfig (openshell-supervisor PROXY_BASELINE_*). Mirrors policy_compiler.compiler (a test keeps them equal).
BASELINE_READ_ONLY = ("/usr", "/lib", "/etc", "/app", "/var/log", "/proc", "/dev/urandom")
BASELINE_READ_WRITE = ("/tmp", "/dev/null")

# Provider instance name suffix -> the only profile it may use (mirrors the Policy API).
PROVIDER_SUFFIX = {"llm": "tether-llm", "policy": "tether-policy", "github": "github-org", "aws": "tether-aws"}
SESSION_ANNOTATION = "tether/session-id"
POLICY_HASH_ANNOTATION = "tether/policy-hash"

Authorize = Callable[[str], Awaitable[dict | None]]


@dataclass
class Result:
    allowed: bool
    reason: str = ""
    status_code: str = ""
    patches: list[dict] = field(default_factory=list)
    log_annotations: dict[str, str] = field(default_factory=dict)


def allow(**annotations) -> Result:
    return Result(True, log_annotations={k: str(v) for k, v in annotations.items()})


def deny(reason: str, code: str = "PERMISSION_DENIED") -> Result:
    return Result(False, reason=reason, status_code=code)


def get(d: dict, *names, default=None):
    """Protobuf JSON uses lowerCamelCase; accept original field names too."""
    for n in names:
        if isinstance(d, dict) and n in d:
            return d[n]
    return default


def authorized_policy(auth: dict):
    return convert.sandbox_policy(auth["openshell_policy"])


def without_added_baseline(got, issued):
    """`got` minus baseline paths the issued policy does not list, each only with its baseline access. What
    remains must equal the issued policy: anything else (another path, other access, other sections) differs."""
    out = type(got)()
    out.CopyFrom(got)
    ro, rw = issued.filesystem.read_only, issued.filesystem.read_write
    out.filesystem.ClearField("read_only")
    out.filesystem.ClearField("read_write")
    out.filesystem.read_only.extend(x for x in got.filesystem.read_only if x in ro or x not in BASELINE_READ_ONLY)
    out.filesystem.read_write.extend(x for x in got.filesystem.read_write if x in rw or x not in BASELINE_READ_WRITE)
    return out


def policy_matches(proposed: dict | None, auth: dict, allow_baseline: bool = False) -> str | None:
    try:
        got = convert.policy_from_json(proposed)
    except json_format.ParseError as e:
        return f"unparseable sandbox policy: {e}"
    issued = authorized_policy(auth)
    if got == issued or (allow_baseline and without_added_baseline(got, issued) == issued):
        return None
    return "sandbox policy differs from the policy the Policy API issued for this session"


class Governance:
    def __init__(self, authorize: Authorize, profile_ids: set[str], allowed_images: set[str] | None = None,
                 admin_role: str = "openshell-platform-admin"):
        self.authorize, self.profile_ids = authorize, profile_ids
        self.allowed_images, self.admin_role = allowed_images or set(), admin_role

    async def evaluate(self, method: str, phase: str, op: dict, principal: dict[str, str], service: str = OPENSHELL) -> Result:
        # Handlers are named after public RPCs (CapitalizedMethod); helpers such as _allow are never selectable.
        prefix = {OPENSHELL: "_", SANDBOX_UPDATES: "_SandboxUpdates_"}.get(service)
        handler = getattr(self, prefix + method, None) if prefix and method[:1].isupper() else None
        if handler is None:
            # Every interceptable write is bound; a method we do not know is not allowed.
            return deny(f"{method} is not permitted by company governance")
        return await handler(phase, op, principal)

    # --- sandboxes -------------------------------------------------------------------

    async def _CreateSandbox(self, phase, op, principal):
        name = get(op, "name", default="")
        if not name:
            return deny("sandboxes must be created with a name issued by the Policy API")
        auth = await self.authorize(name)
        if not auth:
            return deny(f"no active session was issued sandbox {name!r}")
        spec = get(op, "spec", default={}) or {}
        if phase == "modify_operation":
            # Whatever the caller sent, the sandbox gets the issued policy and provider set.
            spec_patch = [{"op": "add", "path": "/spec/policy", "value": convert.to_json(authorized_policy(auth))},
                          {"op": "add", "path": "/spec/providers", "value": sorted(auth["providers"])}]
            patches = spec_patch if isinstance(get(op, "spec"), dict) else [
                {"op": "add", "path": "/spec", "value": {"policy": spec_patch[0]["value"], "providers": spec_patch[1]["value"]}}]
            if not isinstance(get(op, "annotations"), dict):
                patches.append({"op": "add", "path": "/annotations", "value": {}})
            patches += [{"op": "add", "path": "/annotations/" + SESSION_ANNOTATION.replace("~", "~0").replace("/", "~1"), "value": auth["session_id"]},
                        {"op": "add", "path": "/annotations/" + POLICY_HASH_ANNOTATION.replace("~", "~0").replace("/", "~1"), "value": auth.get("policy_hash") or ""}]
            r = allow(session_id=auth["session_id"], user=auth["user_id"], policy_version=auth["policy_version"])
            r.patches = patches
            return r
        problem = policy_matches(get(spec, "policy"), auth)
        if problem:
            return deny(problem)
        if set(get(spec, "providers", default=[]) or []) != set(auth["providers"]):
            return deny("sandbox providers differ from the set issued for this session")
        if get(op, "serviceExposures", "service_exposures"):
            return deny("exposing services from agent sandboxes is not permitted")
        if get(op, "workloadTemplate", "workload_template"):
            return deny("workload templates are not permitted; the Policy API supplies the full sandbox definition")
        # Without --from the CLI sends no spec.template and the driver's default_image would be used: an
        # image must always be named explicitly, and be approved when an allowlist is configured.
        image = get(get(spec, "template", default={}) or {}, "image", default="")
        if not image:
            return deny("sandboxes must be created from an explicit, approved image (spec.template.image)")
        if self.allowed_images and image not in self.allowed_images:
            return deny(f"sandbox image {image!r} is not an approved agent image")
        return allow(session_id=auth["session_id"], user=auth["user_id"])

    async def _UpdateConfig(self, phase, op, principal):
        setting = get(op, "settingKey", "setting_key", default="")
        value = get(op, "settingValue", "setting_value", default={}) or {}
        if setting == "proposal_approval_mode" and get(value, "stringValue", "string_value") == "auto":
            return deny("automatic approval of sandbox policy proposals is not permitted")
        if get(op, "global", default=False):
            # Global policy applies to every sandbox in full: never through the API.
            if get(op, "policy") or get(op, "mergeOperations", "merge_operations"):
                return deny("global sandbox policy is managed by gateway configuration, not the API")
            if self.admin_role not in (principal.get("roles") or "").split(","):
                return deny("global settings require the platform admin role")
            return allow()
        sandbox = get(op, "sandbox", default="")
        if get(op, "mergeOperations", "merge_operations"):
            return deny("incremental sandbox policy merges are not permitted")
        if get(op, "policy") is None:
            return deny("only full, issued sandbox policies may be applied")
        auth = await self.authorize(sandbox)
        if not auth:
            return deny(f"no active session was issued sandbox {sandbox!r}")
        # At startup the supervisor (sandbox principal) saves its baseline-path-enriched policy back. The
        # compiler already lists every baseline path, so this is normally the issued policy unchanged; added
        # baseline paths (with their baseline access, nothing else) are tolerated from the sandbox itself only.
        # The gateway restricts a sandbox principal to its own sandbox (resolve_sandbox_by_name_for_principal).
        problem = policy_matches(get(op, "policy"), auth, allow_baseline=principal.get("kind") == "sandbox")
        return deny(problem) if problem else allow(session_id=auth["session_id"])

    # --- sandbox lifecycle -----------------------------------------------------------

    async def _activate(self, phase, op, principal):
        # Starting or resuming runs the workload again: only for a name issued to a still-active session.
        name = get(op, "name", default="")
        auth = await self.authorize(name)
        if not auth:
            return deny(f"no active session was issued sandbox {name!r}")
        return allow(session_id=auth["session_id"])

    _StartSandbox = _ResumeSandbox = _activate

    async def _SandboxUpdates_UpdateSandbox(self, phase, op, principal):
        return deny("changing a sandbox's image, command, environment or metadata is not permitted; the orchestrator creates a new sandbox")

    async def _AttachSandboxProvider(self, phase, op, principal):
        sandbox, provider = get(op, "sandbox", default=""), get(op, "provider", default="")
        auth = await self.authorize(sandbox)
        if not auth or provider not in auth["providers"]:
            return deny(f"provider {provider!r} was not issued for sandbox {sandbox!r}")
        return allow()

    # --- providers -------------------------------------------------------------------

    async def _provider(self, op):
        p = get(op, "provider", default={}) or {}
        name = get(get(p, "metadata", default={}) or {}, "name", default="")
        ptype = get(p, "type", default="")
        if ptype not in self.profile_ids:
            return deny(f"provider type {ptype!r} is not a company profile")
        sandbox, _, suffix = name.rpartition("-")
        if PROVIDER_SUFFIX.get(suffix) != ptype:
            return deny(f"provider {name!r} does not follow the company naming for {ptype!r}")
        auth = await self.authorize(sandbox)
        if not auth or auth["providers"].get(name) != ptype:
            return deny(f"provider {name!r} was not issued to an active session")
        return allow()

    async def _CreateProvider(self, phase, op, principal):
        return await self._provider(op)

    async def _UpdateProvider(self, phase, op, principal):
        return await self._provider(op)

    async def _deny_profiles(self, phase, op, principal):
        return deny("provider profiles are vended by company governance and cannot be changed through the API")

    _ImportProviderProfiles = _UpdateProviderProfiles = _DeleteProviderProfile = _deny_profiles

    async def _deny_unused(self, phase, op, principal):
        return deny("this operation is not used by the company platform")

    # Gateway-side refresh and rotation would mint credentials outside the broker's records.
    _ConfigureProviderRefresh = _RotateProviderCredential = _deny_unused

    # --- policy proposals ------------------------------------------------------------

    async def _SubmitPolicyAnalysis(self, phase, op, principal):
        if principal.get("kind") != "sandbox":
            return deny("policy analysis requires an authenticated sandbox principal")
        if get(op, "proposedChunks", "proposed_chunks"):
            return deny("sandbox-authored policy proposals are not permitted")
        return allow()

    async def _deny_widening(self, phase, op, principal):
        return deny("approving or editing draft policy would widen an issued policy")

    _ApproveDraftChunk = _ApproveAllDraftChunks = _EditDraftChunk = _UndoDraftChunk = _deny_widening

    # --- access paths that bypass the orchestrator ------------------------------------

    async def _deny_access(self, phase, op, principal):
        return deny("direct access to agent sandboxes goes through the company orchestrator only")

    _CreateSshSession = _ExposeService = _deny_access

    # --- narrowing and teardown are always allowed ----------------------------------------

    async def _allow(self, phase, op, principal):
        return allow()

    _DeleteSandbox = _StopSandbox = _SuspendSandbox = _DetachSandboxProvider = _DeleteProvider = _DeleteProviderRefresh = _allow
    _RevokeSshSession = _DeleteService = _RejectDraftChunk = _ClearDraftChunks = _allow


# Bindings declared in the manifest, keyed by public RPC. Every interceptable write that can create,
# (re)activate, widen or open access to a sandbox is bound (crates/openshell-gateway-interceptors/src/routes.rs
# at OpenShell v0.1.9). Narrowing and teardown (Delete*, Detach*, Revoke*, Reject/Clear draft, and
# StopSandbox/SuspendSandbox, which only halt a workload) are deliberately unbound so that incident response
# can always stop and delete sandboxes, even while this fail-closed service is down. Anyone holding gateway
# credentials can already delete a sandbox; bringing one back (StartSandbox/ResumeSandbox) is bound.
BINDINGS = {
    f"{OPENSHELL}/CreateSandbox": ("modify_operation", "validate"),
    **{f"{OPENSHELL}/{m}": ("validate",) for m in (
        "StartSandbox", "ResumeSandbox",
        "UpdateConfig", "AttachSandboxProvider", "CreateProvider", "UpdateProvider", "ImportProviderProfiles",
        "UpdateProviderProfiles", "DeleteProviderProfile", "ConfigureProviderRefresh", "RotateProviderCredential",
        "SubmitPolicyAnalysis", "ApproveDraftChunk", "ApproveAllDraftChunks", "EditDraftChunk", "UndoDraftChunk",
        "CreateSshSession", "ExposeService")},
    f"{SANDBOX_UPDATES}/UpdateSandbox": ("validate",),
}
