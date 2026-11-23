import copy
import ipaddress
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT))
import generate as g  # noqa: E402

RAW = yaml.safe_load((ROOT / "config.yaml").read_text())
CFG = g.load_config(RAW)
FILES = g.render(CFG)
GATEWAY = {"10.20.0.10/32", "10.20.0.11/32"}
BASTION = {"10.10.0.5/32"}


def raw(**patch):
    """Copy of the example config with dotted-path overrides, e.g. raw(**{"gateway.source_cidrs": [...]})."""
    r = copy.deepcopy(RAW)
    for path, value in patch.items():
        *parents, last = path.split(".")
        d = r
        for p in parents:
            d = d[int(p)] if isinstance(d, list) else d[p]
        if isinstance(d, list):
            d[int(last)] = value
        else:
            d[last] = value
    return r


def chain(nft, name):
    m = re.search(rf"\tchain {name} {{\n(.*?)\n\t}}", nft, re.S)
    assert m, name
    return [line.strip() for line in m.group(1).splitlines() if line.strip() and not line.strip().startswith("#")]


def saddrs(rule):
    m = re.search(r"ip6? [sd]addr \{ ([^}]*) \}", rule)
    return set(m.group(1).split(", ")) if m else set()


# ---------------------------------------------------------------- outputs

def test_outputs_and_checked_in_copy_match(tmp_path):
    names = g.generate(RAW, tmp_path)
    assert names == sorted(FILES) and "kubernetes/networkpolicy.yaml" in names
    # out/ is committed for review: it must be exactly what config.yaml renders.
    for n in names:
        assert (ROOT / "out" / n).read_text() == (tmp_path / n).read_text(), f"out/{n} is stale: run generate.py"


def test_gateway_env_consistent_with_compose_and_compiler():
    env = dict(line.split("=", 1) for line in FILES["gateway.env"].splitlines() if line and not line.startswith("#"))
    assert set(env) == {"PLATFORM_LOCAL_INFERENCE_HOSTS", "LOCAL_UPSTREAM"}
    compose = (ROOT.parents[2] / "infra/docker-compose.yml").read_text()
    for k in env:
        assert f"{k}: ${{{k}:-" in compose  # the variables the services actually read
    assert env["LOCAL_UPSTREAM"].startswith("https://")  # gateway refuses plaintext without LOCAL_ALLOW_PLAINTEXT
    # Every name the gateway or an admin could use is covered by the policy compiler's suffix rule.
    suffixes = env["PLATFORM_LOCAL_INFERENCE_HOSTS"].split(",")
    for host in [CFG["upstream_host"], *(h["fqdn"] for h in CFG["hosts"])]:
        assert any(host == s or host.endswith("." + s) for s in suffixes), host


# ---------------------------------------------------------------- nftables

def test_nft_default_drop_everywhere():
    nft = FILES["nftables/gpu-inference.nft"]
    for name in ("input", "forward", "output"):
        rules = chain(nft, name)
        assert f"type filter hook {name} priority filter; policy drop;" in rules
        assert any(r.startswith("limit rate") and " log prefix " in r for r in rules), "drops are logged, rate limited"
        assert rules[-1] == "counter drop"
    assert "flush ruleset" not in nft  # never wipes other tables
    assert not any("accept" in r for r in chain(nft, "forward"))


def test_nft_no_wildcard_allow():
    nft = FILES["nftables/gpu-inference.nft"]
    stateful = {'iif "lo" accept', 'oif "lo" accept', "ct state established,related accept"}
    for name, addr in (("input", "saddr"), ("output", "daddr")):
        for r in chain(nft, name):
            if "accept" not in r or r in stateful:
                continue
            if r.startswith("icmpv6 type { nd-"):
                assert "ip6 hoplimit 255" in r  # neighbour discovery, link-local only
                continue
            assert f" {addr} {{" in r or r.startswith(("ip ", "ip6 ")), f"unscoped accept: {r}"
            assert saddrs(r), f"accept without an address set: {r}"
            assert not any(ipaddress.ip_network(a).prefixlen == 0 for a in saddrs(r))
    assert "0.0.0.0/0" not in nft and "::/0" not in nft


def test_nft_serving_port_only_from_gateway():
    inp = chain(FILES["nftables/gpu-inference.nft"], "input")
    proxy = [r for r in inp if f"dport {CFG['proxy_port']} " in r]
    assert len(proxy) == 1 and saddrs(proxy[0]) == GATEWAY
    # The engine port is never opened, and loopback is not reachable from outside.
    assert not any(str(CFG["engine_port"]) in r for r in inp)
    assert 'iif != "lo" ip daddr 127.0.0.0/8 drop comment "engine is loopback-only"' in inp


def test_nft_ssh_only_from_bastion():
    inp = chain(FILES["nftables/gpu-inference.nft"], "input")
    ssh = [r for r in inp if "dport 22 " in r]
    assert len(ssh) == 1 and saddrs(ssh[0]) == BASTION


def test_nft_egress_only_listed():
    out = chain(FILES["nftables/gpu-inference.nft"], "output")
    allowed = [r for r in out if "daddr" in r]
    listed = {(str(n), p) for e in CFG["egress"] for n in e["cidrs"] for p in e["proto"]}
    got = {(a, re.search(r"\} (tcp|udp) dport", r).group(1)) for r in allowed for a in saddrs(r)}
    assert got == listed
    assert all("dport {" in r for r in allowed)  # never all ports


def test_nft_ipv6_rules_rendered_per_family():
    c = g.load_config(raw(**{"gateway.source_cidrs": ["10.20.0.10/32", "fd00:20::10/128"]}))
    inp = chain(g.render_nftables(c), "input")
    assert "ip saddr { 10.20.0.10/32 } tcp dport 8443 accept" in " ".join(inp)
    assert any(r.startswith("ip6 saddr { fd00:20::10/128 } tcp dport 8443") for r in inp)


# ---------------------------------------------------------------- envoy

def envoy():
    return yaml.safe_load(FILES["envoy/envoy.yaml"])


def test_envoy_requires_pinned_gateway_cert():
    lst = envoy()["static_resources"]["listeners"][0]
    assert lst["address"]["socket_address"]["port_value"] == CFG["proxy_port"]
    tls = lst["filter_chains"][0]["transport_socket"]["typed_config"]
    assert tls["require_client_certificate"] is True
    vc = tls["common_tls_context"]["validation_context"]
    assert vc["trusted_ca"]["filename"] == CFG["tls"]["client_ca"]
    assert vc["match_typed_subject_alt_names"] == [{"san_type": "DNS", "matcher": {"exact": "llm-gateway.company.internal"}}]


def test_envoy_source_rbac_and_engine_on_loopback():
    e = envoy()
    lst = e["static_resources"]["listeners"][0]
    rbac = lst["filter_chains"][0]["filters"][0]
    assert rbac["name"] == "envoy.filters.network.rbac"
    principals = rbac["typed_config"]["rules"]["policies"]["gateway-sources"]["principals"]
    assert {f"{p['direct_remote_ip']['address_prefix']}/{p['direct_remote_ip']['prefix_len']}" for p in principals} == GATEWAY
    engine = e["static_resources"]["clusters"][0]["load_assignment"]["endpoints"][0]["lb_endpoints"][0]["endpoint"]
    assert engine["address"]["socket_address"] == {"address": "127.0.0.1", "port_value": CFG["engine_port"]}
    assert e["admin"]["address"]["socket_address"]["address"] == "127.0.0.1"


def test_envoy_path_allowlist_ends_in_404():
    hcm = envoy()["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][1]["typed_config"]
    routes = hcm["route_config"]["virtual_hosts"][0]["routes"]
    assert [r["match"]["path"] for r in routes[:-1]] == CFG["allowed_paths"]
    assert routes[-1] == {"match": {"prefix": "/"}, "direct_response": {"status": 404}}
    assert hcm["forward_client_cert_details"] == "SANITIZE" and hcm["normalize_path"] is True


def test_envoy_metrics_listener_is_get_metrics_from_monitoring_only():
    m = envoy()["static_resources"]["listeners"][1]
    assert m["address"]["socket_address"]["port_value"] == CFG["metrics_port"]
    rbac, hcm = m["filter_chains"][0]["filters"]
    assert [p["direct_remote_ip"]["address_prefix"] for p in rbac["typed_config"]["rules"]["policies"]["monitoring-sources"]["principals"]] == ["10.30.0.5"]
    routes = hcm["typed_config"]["route_config"]["virtual_hosts"][0]["routes"]
    assert routes[0]["match"]["path"] == "/metrics" and routes[-1]["direct_response"]["status"] == 404


def test_no_monitoring_means_no_metrics_port():
    c = g.load_config(raw(monitoring={"source_cidrs": []}))
    assert len(g.envoy_config(c)["static_resources"]["listeners"]) == 1
    assert "9443" not in g.render_nftables(c)


# ---------------------------------------------------------------- kubernetes

def test_networkpolicy_default_deny_and_gateway_only_ingress():
    deny, allow = yaml.safe_load_all(FILES["kubernetes/networkpolicy.yaml"])
    assert deny["spec"] == {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]}
    spec = allow["spec"]
    assert spec["policyTypes"] == ["Ingress", "Egress"]
    serving = [r for r in spec["ingress"] if r["ports"] == [{"protocol": "TCP", "port": CFG["proxy_port"]}]]
    assert len(serving) == 1 and {f["ipBlock"]["cidr"] for f in serving[0]["from"]} == GATEWAY
    for rule in spec["ingress"] + spec["egress"]:
        peers = rule.get("from", rule.get("to"))
        assert peers and rule.get("ports"), "an empty peer or port list allows everything"
        for p in peers:
            assert "except" not in p.get("ipBlock", {}) and p.get("ipBlock", {}).get("cidr") not in ("0.0.0.0/0", "::/0")
    assert not any(r["ports"][0]["port"] in (CFG["engine_port"], 22) for r in spec["ingress"])


def test_networkpolicy_pod_egress_is_dns_unless_opted_in():
    _, allow = yaml.safe_load_all(FILES["kubernetes/networkpolicy.yaml"])
    assert len(allow["spec"]["egress"]) == 1 and allow["spec"]["egress"][0]["to"][0]["podSelector"]["matchLabels"] == {"k8s-app": "kube-dns"}
    r = raw()
    r["egress"][3]["applies_to"] = ["host", "pod"]  # registry
    _, allow = g.kubernetes_policies(g.load_config(r))
    assert allow["spec"]["egress"][1] == {"to": [{"ipBlock": {"cidr": "10.50.0.20/32"}}], "ports": [{"protocol": "TCP", "port": 443}]}


# ---------------------------------------------------------------- ssh

def directives(text):
    return [line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")]


def test_sshd_gpu_host():
    d = directives(FILES["ssh/gpu-host/sshd_config.d/10-gpu-inference.conf"])
    for want in ("PasswordAuthentication no", "KbdInteractiveAuthentication no", "AuthenticationMethods publickey",
                 "PermitRootLogin no", "AllowGroups gpu-admins", "AllowAgentForwarding no", "DisableForwarding yes",
                 "AllowTcpForwarding no", "LogLevel VERBOSE"):
        assert want in d
    assert d[-2:] == ["Match Address *,!10.10.0.5/32", "DenyUsers *"]


def test_sshd_bastion_jump_only_to_gpu_hosts():
    d = directives(FILES["ssh/bastion/sshd_config.d/10-gpu-bastion.conf"])
    i = d.index("Match Group gpu-admins")
    glob, match = d[:i], d[i:]
    assert {"AllowTcpForwarding no", "PermitOpen none", "AllowAgentForwarding no", "PasswordAuthentication no"} <= set(glob)
    assert "AllowTcpForwarding local" in match and "ForceCommand /usr/sbin/nologin" in match and "PermitTTY no" in match
    permit = next(x for x in match if x.startswith("PermitOpen "))
    assert set(permit.split()[1:]) == {"gpu-01.gpu.company.internal:22", "10.40.0.11:22", "gpu-02.gpu.company.internal:22", "10.40.0.12:22"}


def test_admin_client_uses_bastion_without_agent():
    d = directives(FILES["ssh/admin-client/ssh_config"])
    assert d[0] == "Host *.gpu.company.internal 10.40.0.11 10.40.0.12"
    assert "ProxyJump bastion.company.internal" in d and "ForwardAgent no" in d


def test_session_recording_and_audit():
    assert "groups = gpu-admins" in FILES["ssh/gpu-host/sssd.conf.d/50-session-recording.conf"]
    tlog = yaml.safe_load(FILES["ssh/gpu-host/tlog-rec-session.conf"])
    assert tlog["writer"] == "journal" and tlog["log"]["output"] is True and tlog["log"]["input"] is False
    rules = FILES["ssh/gpu-host/audit.rules.d/50-gpu-inference.rules"]
    assert "-w /etc/gpu-inference/ -p wa -k gpu-serving-config" in rules and "-S execve" in rules


@pytest.mark.skipif(not (Path("/usr/sbin/sshd").exists() and shutil.which("ssh-keygen")), reason="needs OpenSSH sshd")
@pytest.mark.parametrize("name", ["ssh/gpu-host/sshd_config.d/10-gpu-inference.conf", "ssh/bastion/sshd_config.d/10-gpu-bastion.conf"])
def test_sshd_accepts_config(tmp_path, name):
    # Syntax and Match semantics as sshd itself evaluates them (sshd -T).
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(tmp_path / "hk")], check=True)
    (tmp_path / "c").write_text(FILES[name])
    def effective(addr):
        out = subprocess.run(["/usr/sbin/sshd", "-T", "-f", str(tmp_path / "c"), "-h", str(tmp_path / "hk"),
                              "-C", f"user=nobody,host=x,addr={addr}"], capture_output=True, text=True)
        assert out.returncode == 0, out.stderr
        return out.stdout.lower().splitlines()
    if "gpu-host" in name:
        assert "denyusers *" not in effective("10.10.0.5")
        assert "denyusers *" in effective("10.20.0.10")
    else:
        assert {"allowtcpforwarding no", "permitopen none"} <= set(effective("10.10.0.99"))


# ---------------------------------------------------------------- invalid configs

@pytest.mark.parametrize("patch, msg", [
    ({"gateway.source_cidrs": ["0.0.0.0/0"]}, "every address"),
    ({"gateway.source_cidrs": ["10.20.0.10/32", "::/0"]}, "every address"),
    ({"gateway.source_cidrs": ["10.0.0.0/8"]}, "too broad"),
    ({"gateway.source_cidrs": []}, "non-empty"),
    ({"gateway.source_cidrs": ["10.20.0.10/33"]}, "invalid"),
    ({"gateway.source_cidrs": ["10.20.0.10/24"]}, "invalid"),          # host bits set
    ({"gateway.source_cidrs": ["10.40.0.0/28"]}, "inference host"),
    ({"gateway.source_cidrs": ["127.0.0.1/32"]}, "routable"),
    ({"ssh.bastion_cidrs": ["0.0.0.0/0"]}, "every address"),
    ({"ssh.bastion_cidrs": []}, "non-empty"),
    ({"monitoring.source_cidrs": ["10.0.0.0/16"]}, "too broad"),
    ({"egress.0.cidrs": ["0.0.0.0/0"]}, "every address"),
    ({"egress.2.cidrs": ["10.50.0.0/16"]}, "too broad"),
    ({"egress.2.ports": []}, "ports"),
    ({"egress.2.proto": ["icmp"]}, "proto"),
    ({"egress.2.ports": [0]}, "port"),
    ({"inference.upstream": "http://inference.gpu.company.internal:8443"}, "https"),
    ({"inference.upstream": "https://inference.other.internal:8443"}, "not under"),
    ({"inference.upstream": "https://inference.gpu.company.internal:9000"}, "proxy_port"),
    ({"inference.upstream": "https://inference.gpu.company.internal:8443/v1"}, "https"),
    ({"inference.hosts.0.fqdn": "gpu-01.other.internal"}, "not under"),
    ({"inference.hosts.1.address": "10.40.0.11"}, "duplicate"),
    ({"inference.engine_port": 8443}, "must differ"),
    ({"ssh.port": 8000}, "must differ"),
    ({"inference.allowed_paths": ["/"]}, "allowed_paths"),
    ({"inference.allowed_paths": ["/v1/../admin"]}, "allowed_paths"),
    ({"gateway.client_san_dns": "*.company.internal"}, "client_san_dns"),
    ({"ssh.admin_group": "gpu admins; rm"}, "admin_group"),
    ({"tls.client_ca": "ca.pem"}, "absolute"),
    ({"kubernetes.pod_labels": {}}, "pod_labels"),
])
def test_invalid_config_rejected(tmp_path, patch, msg):
    with pytest.raises(g.ConfigError, match=msg):
        g.generate(raw(**patch), tmp_path)
    assert not any(tmp_path.iterdir()), "nothing is written for an invalid config"


def test_unknown_key_and_fqdn_only_egress_rejected():
    with pytest.raises(g.ConfigError, match="unknown top-level"):
        g.load_config({**RAW, "gatway": {}})
    r = raw()
    del r["egress"][2]["cidrs"]
    r["egress"][2]["fqdn"] = "mirror.company.internal"
    with pytest.raises(g.ConfigError, match="pinned to addresses"):
        g.load_config(r)


def test_kubernetes_optional():
    r = raw()
    del r["kubernetes"]
    assert "kubernetes/networkpolicy.yaml" not in g.render(g.load_config(r))
