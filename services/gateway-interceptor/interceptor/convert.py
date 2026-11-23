"""YAML-shaped policies and provider profiles -> OpenShell protobuf messages.

Mirrors the gateway's own conversion (openshell-policy / openshell-providers) for the fields
the company platform emits. Unknown keys raise, so nothing is silently dropped from a policy.
"""
from google.protobuf import json_format

from .protos import openshell_pb2, sandbox_pb2

ENFORCEMENT = {"": 0, "enforce": 1, "audit": 2}
ACCESS = {"": 0, "read-only": 1, "read-write": 2, "full": 3}
TLS = {"": 0, "skip": 1}
CATEGORY = {"other": 1, "inference": 2, "agent": 3, "source_control": 4, "messaging": 5, "data": 6, "knowledge": 7}


class ConversionError(ValueError):
    pass


def _only(d, allowed, where):
    extra = set(d) - set(allowed)
    if extra:
        raise ConversionError(f"unsupported keys in {where}: {sorted(extra)}")


def _lookup(table, value, where):
    if value not in table:
        raise ConversionError(f"unsupported {where}: {value!r}")
    return table[value]


def _matchers(d):
    return {k: sandbox_pb2.L7QueryMatcher(glob=v) if isinstance(v, str) else sandbox_pb2.L7QueryMatcher(any=v.get("any", []), glob=v.get("glob", ""))
            for k, v in (d or {}).items()}


def endpoint(e: dict) -> sandbox_pb2.NetworkEndpoint:
    _only(e, {"host", "port", "ports", "protocol", "tls", "enforcement", "access", "rules", "deny_rules", "allowed_ips", "path",
              "allow_encoded_slash", "request_body_credential_rewrite", "websocket_credential_rewrite"}, "endpoint")
    if "access" in e and "rules" in e:
        raise ConversionError("endpoint access and rules are mutually exclusive")
    out = sandbox_pb2.NetworkEndpoint(
        host=e.get("host", ""), port=e.get("port", 0), ports=e.get("ports", []), protocol=e.get("protocol", ""),
        tls=_lookup(TLS, e.get("tls", ""), "tls"), enforcement=_lookup(ENFORCEMENT, e.get("enforcement", ""), "enforcement"),
        access=_lookup(ACCESS, e.get("access", ""), "access"), allowed_ips=e.get("allowed_ips", []), path=e.get("path", ""),
        allow_encoded_slash=e.get("allow_encoded_slash", False),
        request_body_credential_rewrite=e.get("request_body_credential_rewrite", False),
        websocket_credential_rewrite=e.get("websocket_credential_rewrite", False))
    for r in e.get("rules", []):
        _only(r, {"allow"}, "rule")
        a = r["allow"]
        _only(a, {"method", "path", "query"}, "rule.allow")
        out.rules.append(sandbox_pb2.L7Rule(allow=sandbox_pb2.L7Allow(method=a.get("method", ""), path=a.get("path", ""), query=_matchers(a.get("query")))))
    for d in e.get("deny_rules", []):
        _only(d, {"method", "path", "query"}, "deny_rule")
        out.deny_rules.append(sandbox_pb2.L7DenyRule(method=d.get("method", ""), path=d.get("path", ""), query=_matchers(d.get("query"))))
    return out


def binary(b) -> sandbox_pb2.NetworkBinary:
    if isinstance(b, str):
        return sandbox_pb2.NetworkBinary(path=b)
    _only(b, {"path"}, "binary")
    return sandbox_pb2.NetworkBinary(path=b["path"])


def sandbox_policy(p: dict) -> sandbox_pb2.SandboxPolicy:
    """The compiler's OpenShell YAML policy -> SandboxPolicy (YAML `filesystem_policy` is proto `filesystem`)."""
    _only(p, {"version", "filesystem_policy", "landlock", "process", "network_policies"}, "policy")
    fs, ll, pr = p.get("filesystem_policy") or {}, p.get("landlock") or {}, p.get("process") or {}
    _only(fs, {"include_workdir", "read_only", "read_write"}, "filesystem_policy")
    _only(ll, {"compatibility"}, "landlock")
    _only(pr, {"run_as_user", "run_as_group"}, "process")
    out = sandbox_pb2.SandboxPolicy(
        version=p.get("version", 0),
        filesystem=sandbox_pb2.FilesystemPolicy(include_workdir=fs.get("include_workdir", False), read_only=fs.get("read_only", []), read_write=fs.get("read_write", [])),
        landlock=sandbox_pb2.LandlockPolicy(compatibility=ll.get("compatibility", "")),
        process=sandbox_pb2.ProcessPolicy(run_as_user=pr.get("run_as_user", ""), run_as_group=pr.get("run_as_group", "")))
    for key, rule in (p.get("network_policies") or {}).items():
        _only(rule, {"name", "endpoints", "binaries"}, f"network_policies.{key}")
        out.network_policies[key].CopyFrom(sandbox_pb2.NetworkPolicyRule(
            name=rule.get("name", ""), endpoints=[endpoint(e) for e in rule.get("endpoints", [])], binaries=[binary(b) for b in rule.get("binaries", [])]))
    return out


def provider_profile(profile_id: str, y: dict) -> openshell_pb2.ProviderProfile:
    _only(y, {"id", "display_name", "description", "category", "credentials", "endpoints", "binaries", "inference_capable", "discovery"}, "profile")
    if y.get("id", profile_id) != profile_id:
        raise ConversionError(f"profile id {y['id']!r} does not match file name {profile_id!r}")
    out = openshell_pb2.ProviderProfile(
        id=profile_id, display_name=y.get("display_name", ""), description=y.get("description", ""),
        category=_lookup(CATEGORY, y.get("category", "other"), "category"), inference_capable=y.get("inference_capable", False),
        endpoints=[endpoint(e) for e in y.get("endpoints", [])], binaries=[binary(b) for b in y.get("binaries", [])])
    for c in y.get("credentials", []):
        _only(c, {"name", "description", "env_vars", "required", "auth_style", "header_name", "query_param", "path_template"}, "credential")
        out.credentials.append(openshell_pb2.ProviderProfileCredential(**c))
    if y.get("discovery"):
        out.discovery.credentials.extend(y["discovery"].get("credentials", []))
    return out


def to_json(msg) -> dict:
    """Protobuf JSON as the gateway exchanges it with interceptors."""
    return json_format.MessageToDict(msg)


def policy_from_json(d) -> sandbox_pb2.SandboxPolicy:
    return json_format.ParseDict(d or {}, sandbox_pb2.SandboxPolicy())  # unknown fields raise
