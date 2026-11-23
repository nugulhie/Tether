import copy
from pathlib import Path

import pytest
import yaml

from policy_compiler import PolicyError, compile_policy, policy_hash
from policy_compiler.bundle import document

BASE = document(yaml.safe_load((Path(__file__).parents[3] / "policies" / "backend-dev.yaml").read_text()))


def policy(**changes):
    p = copy.deepcopy(BASE)
    p.update(changes)
    return p


def test_compiles_filesystem_with_workspace_first_and_deduped():
    p = policy(filesystem={"read_only": ["/usr", "/usr"], "read_write": ["/workspace", "/tmp"]})
    fs = compile_policy(p)["filesystem_policy"]
    assert fs["read_only"] == ["/usr"]
    assert fs["read_write"] == ["/workspace", "/tmp"]
    assert fs["include_workdir"] is False


def test_runs_as_unprivileged_sandbox_user():
    assert compile_policy(BASE)["process"] == {"run_as_user": "sandbox", "run_as_group": "sandbox"}


@pytest.mark.parametrize("host", ["api.anthropic.com", "claude.ai", "api.openai.com", "chatgpt.com", "generativelanguage.googleapis.com", "openrouter.ai"])
def test_rejects_direct_model_hosts(host):
    with pytest.raises(PolicyError, match="model provider"):
        compile_policy(policy(network={"allow": [host]}))


def test_github_requires_org():
    with pytest.raises(PolicyError, match="github.org"):
        compile_policy(policy(github={"permissions": {"contents": "read"}}))


def test_network_rule_per_host_with_binaries():
    rules = compile_policy(BASE)["network_policies"]
    assert [r["endpoints"][0]["host"] for r in rules.values()] == BASE["network"]["allow"]
    assert all(r["binaries"] == [{"path": b} for b in BASE["network_binaries"]] for r in rules.values())


def test_rejects_denied_process_in_network_binaries():
    with pytest.raises(PolicyError, match="kubectl"):
        compile_policy(policy(network_binaries=["/usr/bin/git", "/usr/local/bin/kubectl"]))


def test_rejects_hosts_without_binaries():
    with pytest.raises(PolicyError, match="network_binaries"):
        compile_policy(policy(network_binaries=[]))


@pytest.mark.parametrize("host", ["https://github.com", "github.com:443", "*.github.com", ""])
def test_rejects_non_hostname_entries(host):
    with pytest.raises(PolicyError):
        compile_policy(policy(network={"allow": [host]}))


@pytest.mark.parametrize("rw", ["/", "//", "relative/path"])
def test_rejects_bad_read_write(rw):
    with pytest.raises(PolicyError):
        compile_policy(policy(filesystem={"read_only": ["/usr"], "read_write": [rw]}))


def test_hash_is_stable_and_policy_sensitive():
    a = compile_policy(BASE)
    assert policy_hash(a) == policy_hash(compile_policy(copy.deepcopy(BASE)))
    assert policy_hash(a) != policy_hash(compile_policy(policy(network={"allow": ["github.com"]})))


@pytest.mark.parametrize("aws", [
    {"role": "AIAgentDevelopmentRole"},
    {"role": "arn:aws:iam::123:role/x"},
    {"role": None, "duration_seconds": 60},
])
def test_rejects_bad_aws_grant(aws):
    with pytest.raises(PolicyError):
        compile_policy(policy(aws=aws))


def test_accepts_role_arn():
    compile_policy(policy(aws={"role": "arn:aws:iam::123456789012:role/AIAgentDevelopmentRole", "duration_seconds": 3600}))


@pytest.mark.parametrize("perms", [{"contents": "admin"}, {"administration": "read"}])
def test_rejects_bad_github_grant(perms):
    with pytest.raises(PolicyError):
        compile_policy(policy(github={"permissions": perms}))


@pytest.mark.parametrize("llm", [
    {"anthropic": {"models": []}},
    {"anthropic": {}},
    {"openai": {"models": [""]}},
    {"gemini": {"models": ["x"]}},
    {"max_requests_per_minute": 0},
])
def test_rejects_bad_llm_grant(llm):
    with pytest.raises(PolicyError):
        compile_policy(policy(llm=llm))


def test_registries_default_to_read_only():
    eps = [r["endpoints"][0] for r in compile_policy(BASE)["network_policies"].values()]
    assert {e["host"]: e.get("access") for e in eps}["registry.npmjs.org"] == "read-only"


def test_read_write_must_be_explicit():
    p = policy(network={"allow": [{"host": "uploads.example.com", "access": "read-write"}, "pypi.org"]}, github=None)
    eps = {r["endpoints"][0]["host"]: r["endpoints"][0] for r in compile_policy(p)["network_policies"].values()}
    assert eps["uploads.example.com"]["access"] == "read-write" and eps["pypi.org"]["access"] == "read-only"


@pytest.mark.parametrize("entry", [{"host": "x.com", "access": "full"}, {"host": "x.com", "path": "/"}, 42])
def test_rejects_bad_network_entries(entry):
    with pytest.raises(PolicyError):
        compile_policy(policy(network={"allow": [entry]}))


def test_github_restricted_to_org():
    p = policy(github={"org": "acme", "permissions": {"contents": "write"}})
    eps = {r["endpoints"][0]["host"]: r["endpoints"][0] for r in compile_policy(p)["network_policies"].values()}
    gh = eps["github.com"]
    assert "access" not in gh and gh["enforcement"] == "enforce"
    assert {(r["allow"]["method"], r["allow"]["path"]) for r in gh["rules"]} == {
        ("GET", "/acme/**"), ("POST", "/acme/*/git-upload-pack"), ("POST", "/acme/*/git-receive-pack")}
    assert all(r["allow"]["path"].startswith("/repos/acme/") for r in eps["api.github.com"]["rules"])


@pytest.mark.parametrize("org", ["", "acme/evil", "-acme", "a" * 40, "acme*"])
def test_rejects_bad_github_org(org):
    with pytest.raises(PolicyError):
        compile_policy(policy(github={"org": org}))


def test_platform_endpoints_only_for_agent_binaries():
    c = compile_policy(BASE, platform={"llm_gateway_host": "llm.company.internal", "policy_api_host": "policy.company.internal"})
    gw, api = c["network_policies"]["tether_llm_gateway"], c["network_policies"]["tether_policy_api"]
    assert gw["endpoints"][0]["host"] == "llm.company.internal" and gw["endpoints"][0]["access"] == "read-write"
    assert {r["allow"]["path"] for r in api["endpoints"][0]["rules"]} == {"/v1/**"}
    assert [b["path"] for b in gw["binaries"]] == BASE.get("agent_binaries", ["/usr/local/bin/claude", "/usr/local/bin/codex", "/usr/local/bin/node", "/usr/local/bin/python"])
    assert "tether_llm_gateway" not in compile_policy(BASE)["network_policies"]


def test_model_provider_hosts_never_reachable_directly():
    hosts = {r["endpoints"][0]["host"] for r in compile_policy(BASE)["network_policies"].values()}
    assert not hosts & {"api.anthropic.com", "api.openai.com", "claude.ai", "chatgpt.com"}


GPU = {"local_inference_hosts": "gpu.company.internal, vllm.ml.internal"}


@pytest.mark.parametrize("host", ["gpu.company.internal", "node1.gpu.company.internal", "VLLM.ml.internal"])
def test_rejects_local_inference_hosts(host):
    with pytest.raises(PolicyError, match="local inference"):
        compile_policy(policy(network={"allow": [host]}), platform=GPU)


def test_local_inference_hosts_list_form_and_unrelated_hosts_pass():
    compile_policy(policy(network={"allow": ["notgpu.company.internal", "pypi.org"]}, github=None),
                   platform={"local_inference_hosts": ["gpu.company.internal"]})


def test_local_model_grant():
    compile_policy(policy(llm={"local": {"models": ["company-coder-*"]}}))
    with pytest.raises(PolicyError):
        compile_policy(policy(llm={"local": {"models": []}}))


def test_guardrails_are_not_compiled_into_the_sandbox():
    g = {"input": {"secrets": True, "pii": True, "deny_patterns": ["(?i)drop table"]}, "output": {"secrets": True}, "on_error": "deny"}
    assert compile_policy(policy(guardrails=g)) == compile_policy(BASE)


@pytest.mark.parametrize("g", [
    {"on_error": "allow"},
    {"input": {"secrets": "yes"}},
    {"input": {"deny_patterns": ["("]}},
    {"input": {"deny_patterns": [""]}},
    {"input": {"deny_patterns": ["x"] * 101}},
    {"input": {"classifier": True}},
    {"inputs": {}},
    ["secrets"],
])
def test_rejects_bad_guardrails(g):
    with pytest.raises(PolicyError, match="guardrails"):
        compile_policy(policy(guardrails=g))
