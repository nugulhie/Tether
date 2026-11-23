"""Compile a company agent policy document into an OpenShell sandbox policy.

This is the single place where company policy is translated to OpenShell.
The Policy API calls it and hands the result to the launcher; the launcher
must not build OpenShell policy on its own.
"""
import hashlib
import json
import posixpath
import re
import sys
from pathlib import Path

import yaml

DEFAULT_WORKSPACE = "/workspace"
# OpenShell has no per-binary exec allow/deny list; its `process` section only
# sets the identity the agent runs as. Running as the unprivileged `sandbox`
# user is what makes denied tools like sudo ineffective inside the sandbox.
SANDBOX_IDENTITY = "sandbox"


# AI model provider domains. Policies may never allow these in sandboxes: models are reachable
# only through the company LLM gateway.
MODEL_HOSTS = {"anthropic.com", "claude.ai", "claude.com", "openai.com", "chatgpt.com", "oaistatic.com",
               "googleapis.com", "x.ai", "mistral.ai", "cohere.com", "cohere.ai", "deepseek.com", "groq.com", "together.xyz",
               "openrouter.ai", "fireworks.ai", "perplexity.ai"}


# Model grants the LLM gateway understands; "local" is the self-hosted (GPU) inference backend.
LLM_PROVIDERS = ("anthropic", "openai", "local")


class PolicyError(ValueError):
    pass


def _norm(path):
    # posixpath.normpath keeps a leading "//", so collapse it explicitly.
    return posixpath.normpath("/" + path.lstrip("/"))


def _dedupe(paths):
    return list(dict.fromkeys(paths))


def _host_in(host, domains):
    return any(host == d or host.endswith("." + d) for d in domains)


def _platform_list(platform, key):
    v = (platform or {}).get(key) or []
    return [x.strip().lower() for x in (v.split(",") if isinstance(v, str) else v) if x and x.strip()]


def validate(p, platform=None):
    for key in ("filesystem", "network", "process"):
        if key not in p:
            raise PolicyError(f"missing section: {key}")
    if "read_only" not in p["filesystem"]:
        raise PolicyError("missing filesystem.read_only")
    for path in [*p["filesystem"]["read_only"], *p["filesystem"].get("read_write", [])]:
        if not path.startswith("/"):
            raise PolicyError(f"filesystem path must be absolute: {path}")
    for path in p["filesystem"].get("read_write", []):
        if _norm(path) == "/":
            raise PolicyError("read_write must not include /")
    hosts = [_entry(e)[0] for e in p["network"].get("allow", [])]
    for h in hosts:
        if not h or "/" in h or ":" in h or "*" in h:
            raise PolicyError(f"network.allow entries must be bare hostnames: {h!r}")
    # Models are reachable only through the company LLM gateway (platform endpoint).
    direct = {h for h in hosts if _host_in(h, MODEL_HOSTS)}
    if direct:
        raise PolicyError(f"model provider hosts must not be allowed directly: {sorted(direct)}")
    # Self-hosted inference servers (GPU) accept only the LLM gateway; sandboxes never reach them.
    local = {h for h in hosts if _host_in(h.lower(), _platform_list(platform, "local_inference_hosts"))}
    if local:
        raise PolicyError(f"local inference hosts must not be allowed directly: {sorted(local)}")
    # Without an org, github.com would be open for any repository (an exfiltration route).
    if {"github.com", "api.github.com"} & set(hosts) and not (p.get("github") or {}).get("org"):
        raise PolicyError("github.org is required when github.com or api.github.com is allowed")
    for path in p.get("agent_binaries", []):
        if not isinstance(path, str) or not path.startswith("/"):
            raise PolicyError(f"agent_binaries must be absolute paths: {path!r}")
    if hosts and not p.get("network_binaries"):
        raise PolicyError("network.allow is set but network_binaries is empty")
    # Network access in OpenShell is granted per binary. A denied tool must
    # never be one of the binaries that can open connections.
    denied = set(p["process"].get("deny", []))
    for b in p.get("network_binaries", []):
        if posixpath.basename(b) in denied:
            raise PolicyError(f"denied process {posixpath.basename(b)!r} is listed in network_binaries")
    _validate_grants(p)


def _validate_grants(p):
    aws = p.get("aws") or {}
    role = aws.get("role")
    if role is not None and not re.fullmatch(r"arn:aws[a-z-]*:iam::\d{12}:role/[\w+=,.@/-]{1,512}", role):
        raise PolicyError(f"aws.role must be an IAM role ARN: {role!r}")
    # STS AssumeRole accepts 900..43200; the role's MaxSessionDuration may be lower.
    if not 900 <= aws.get("duration_seconds", 3600) <= 43200:
        raise PolicyError("aws.duration_seconds must be between 900 and 43200")
    perms = (p.get("github") or {}).get("permissions") or {}
    for name, level in perms.items():
        if level not in ("read", "write"):
            raise PolicyError(f"github.permissions.{name} must be read or write")
        if name == "administration":
            raise PolicyError("github.permissions.administration must not be granted to agents")
    org = (p.get("github") or {}).get("org")
    if org is not None and not (isinstance(org, str) and re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})", org)):
        raise PolicyError(f"github.org must be a GitHub organization login: {org!r}")
    llm = p.get("llm") or {}
    unknown = set(llm) - {*LLM_PROVIDERS, "max_requests_per_minute"}
    if unknown:
        raise PolicyError(f"unknown llm keys: {sorted(unknown)}")
    for provider in LLM_PROVIDERS:
        models = (llm.get(provider) or {}).get("models")
        if provider in llm and (not isinstance(models, list) or not models or not all(isinstance(m, str) and m for m in models)):
            raise PolicyError(f"llm.{provider}.models must be a non-empty list of model ids or globs")
    rpm = llm.get("max_requests_per_minute")
    if rpm is not None and (not isinstance(rpm, int) or rpm < 1):
        raise PolicyError("llm.max_requests_per_minute must be a positive integer")
    _validate_guardrails(p.get("guardrails"))


GUARDRAIL_DIRECTIONS = ("input", "output")
GUARDRAIL_DETECTORS = ("secrets", "pii")
MAX_DENY_PATTERNS = 100


def _validate_guardrails(g):
    """Guardrails run in the LLM gateway, not in OpenShell, so they are validated here but not
    compiled into the sandbox policy. Failure handling is fixed: a guardrail error denies the
    request. Only an administrator's time-limited bypass (Policy API) lifts it."""
    if g is None:
        return
    if not isinstance(g, dict):
        raise PolicyError("guardrails must be a mapping")
    unknown = set(g) - {*GUARDRAIL_DIRECTIONS, "on_error"}
    if unknown:
        raise PolicyError(f"unknown guardrails keys: {sorted(unknown)}")
    if g.get("on_error", "deny") != "deny":
        raise PolicyError("guardrails.on_error must be deny (bypass is an audited administrator action)")
    for d in GUARDRAIL_DIRECTIONS:
        rules = g.get(d)
        if rules is None:
            continue
        if not isinstance(rules, dict):
            raise PolicyError(f"guardrails.{d} must be a mapping")
        unknown = set(rules) - {*GUARDRAIL_DETECTORS, "deny_patterns"}
        if unknown:
            raise PolicyError(f"unknown guardrails.{d} keys: {sorted(unknown)}")
        for det in GUARDRAIL_DETECTORS:
            if det in rules and not isinstance(rules[det], bool):
                raise PolicyError(f"guardrails.{d}.{det} must be true or false")
        pats = rules.get("deny_patterns", [])
        if not isinstance(pats, list) or len(pats) > MAX_DENY_PATTERNS:
            raise PolicyError(f"guardrails.{d}.deny_patterns must be a list of at most {MAX_DENY_PATTERNS} regexes")
        for pat in pats:
            if not isinstance(pat, str) or not pat or len(pat) > 500:
                raise PolicyError(f"guardrails.{d}.deny_patterns entries must be non-empty strings: {pat!r}")
            try:
                re.compile(pat)
            except re.error as e:
                raise PolicyError(f"guardrails.{d}.deny_patterns: invalid regex {pat!r}: {e}")


ACCESS = ("read-only", "read-write")
# OpenShell matches binaries by the kernel-reported real path (symlinks resolved) of the connecting
# process or any ancestor. npm installs /usr/local/bin/claude and /usr/local/bin/codex as symlinks to
# JavaScript run by node, so the process that matches is node: list its real path (`readlink -f
# /usr/local/bin/node` inside the image). /usr/local/bin/python is a symlink in python images and never
# matches; a native agent executable must be listed by its real path. Binaries gate network admission
# only: credential placeholders are scoped to endpoints, not binaries (docs/threat-model.md).
DEFAULT_AGENT_BINARIES = ["/usr/local/bin/node"]

# Paths the OpenShell v0.1.9 supervisor adds to a policy with network rules (PROXY_BASELINE_READ_ONLY /
# _READ_WRITE in openshell-supervisor) and then saves back to the gateway with UpdateConfig. Listing all
# of them makes that enrichment a no-op, so the stored policy stays exactly the issued one (the gateway
# interceptor only accepts the issued policy, and the gateway may refuse a later replacement that drops
# paths). Like OpenShell, a path the policy already lists keeps its access; missing paths are skipped
# by Landlock at runtime.
BASELINE_READ_ONLY = ("/usr", "/lib", "/etc", "/app", "/var/log", "/proc", "/dev/urandom")
BASELINE_READ_WRITE = ("/tmp", "/dev/null")


def _with_baseline(read_only, read_write):
    ro, rw = list(read_only), list(read_write)
    ro += [x for x in BASELINE_READ_ONLY if x not in ro and x not in rw]
    rw += [x for x in BASELINE_READ_WRITE if x not in rw and x not in ro]
    return ro, rw


def _entry(e):
    """network.allow entry -> (host, access). Plain hostnames are read-only (GET/HEAD/OPTIONS):
    package registries need nothing more, and upload endpoints would be exfiltration routes."""
    if isinstance(e, str):
        return e, "read-only"
    if not isinstance(e, dict) or set(e) - {"host", "access"} or e.get("access", "read-only") not in ACCESS:
        raise PolicyError(f"network.allow entries are hostnames or {{host, access: read-only|read-write}}: {e!r}")
    return e.get("host", ""), e.get("access", "read-only")


def _github_rules(host, org):
    """Org-scoped L7 rules: clone/fetch/push and API calls only inside the company organization."""
    if host == "github.com":
        return [{"allow": {"method": "GET", "path": f"/{org}/**"}},
                {"allow": {"method": "POST", "path": f"/{org}/*/git-upload-pack"}},
                {"allow": {"method": "POST", "path": f"/{org}/*/git-receive-pack"}}]
    return [{"allow": {"method": m, "path": f"/repos/{org}/**"}} for m in ("GET", "POST", "PATCH")]


def compile_policy(p, workspace=DEFAULT_WORKSPACE, platform=None):
    """platform: deployment endpoints every sandbox needs, e.g.
    {"llm_gateway_host": "llm.company.internal", "policy_api_host": "policy.company.internal",
     "local_inference_hosts": ["gpu.company.internal"]}."""
    validate(p, platform)
    bins = [{"path": x} for x in p.get("network_binaries", [])]
    org = (p.get("github") or {}).get("org")
    rules = {}
    for i, e in enumerate(p["network"].get("allow", [])):
        h, access = _entry(e)
        endpoint = {"host": h, "port": 443, "protocol": "rest", "enforcement": "enforce"}
        if org and h in ("github.com", "api.github.com"):
            endpoint["rules"] = _github_rules(h, org)
        else:
            endpoint["access"] = access
        rules[f"tether_{i}"] = {"name": f"tether-{h}", "endpoints": [endpoint], "binaries": bins}
    agent_bins = [{"path": x} for x in p.get("agent_binaries", DEFAULT_AGENT_BINARIES)]
    read_only, read_write = _with_baseline(_dedupe(p["filesystem"]["read_only"]), _dedupe([workspace, *p["filesystem"].get("read_write", [])]))
    for key, host, path in (("llm_gateway_host", "tether_llm_gateway", None), ("policy_api_host", "tether_policy_api", "/v1/**")):
        target = (platform or {}).get(key)
        if target:
            # The tether-llm / tether-policy profiles contribute `_provider_*` rules for the same host:port.
            # OpenShell rejects a policy whose endpoints on one host:port disagree on `tls` or `allowed_ips`,
            # so neither side sets them (a test keeps openshell/profiles in step with this).
            endpoint = {"host": target, "port": 443, "protocol": "rest", "enforcement": "enforce"}
            # Model traffic needs POST; the Permission MCP only calls /v1/ on the Policy API.
            endpoint["rules" if path else "access"] = [{"allow": {"method": m, "path": path}} for m in ("GET", "POST")] if path else "read-write"
            rules[host] = {"name": host.replace("_", "-"), "endpoints": [endpoint], "binaries": agent_bins}
    return {
        "version": 1,
        "filesystem_policy": {
            "include_workdir": False,
            "read_only": read_only,
            "read_write": read_write,
        },
        "landlock": {"compatibility": "hard_requirement"},
        "process": {"run_as_user": SANDBOX_IDENTITY, "run_as_group": SANDBOX_IDENTITY},
        "network_policies": rules,
    }


STATIC_SECTIONS = ("filesystem_policy", "landlock", "process")


def static_part(compiled):
    """Sections OpenShell locks at sandbox creation; network_policies can be set live."""
    return {k: compiled[k] for k in STATIC_SECTIONS if k in compiled}


def policy_hash(compiled):
    return hashlib.sha256(json.dumps(compiled, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def main():
    out = Path(sys.argv[2])
    out.write_text(yaml.safe_dump(compile_policy(yaml.safe_load(Path(sys.argv[1]).read_text())), sort_keys=False))
    print(out)


if __name__ == "__main__":
    main()
