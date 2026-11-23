import shutil
import socket
import ssl
import subprocess
import sys
import threading
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT))
import generate as g  # noqa: E402
import verify as v  # noqa: E402

CFG = g.load_config(yaml.safe_load((ROOT / "config.yaml").read_text()))
GW = v.Opts(cert="gw.crt", key="gw.key", ca="ca.pem")


class FakeNet:
    """Simulates the network as seen from one vantage point.

    open_ports: {(host, port)} that accept TCP. https(host, port, path, cert) -> v.Http."""

    def __init__(self, open_ports=(), https=None):
        self.open_ports, self.https, self.calls = set(open_ports), https, []

    def connect(self, host, port, timeout):
        self.calls.append(("connect", host, port))
        return v.OPEN if (host, port) in self.open_ports else v.TIMEOUT

    def https_get(self, host, port, path, server_name, ca=None, cert=None, key=None, timeout=5.0):
        self.calls.append(("https", host, port, path, cert, ca))
        if (host, port) not in self.open_ports:
            return v.Http(error="TimeoutError: timed out")
        return self.https(host, port, path, cert)


def enforced_proxy(host, port, path, cert):
    """A correctly configured proxy: gateway cert only, path allow-list."""
    if cert != "gw.crt":
        return v.Http(error="SSLError: tlsv13 alert certificate required")
    return v.Http(status=200 if path in CFG["allowed_paths"] else 404)


ADDRS = [h["address"].compressed for h in CFG["hosts"]]
GATEWAY_VIEW = {(a, 8443) for a in ADDRS} | {(CFG["upstream_host"], 8443)}


def by_id(results):
    return {r.check.id: r for r in results}


# ---------------------------------------------------------------- plans

def test_sandbox_plan_is_all_negative():
    checks = v.plan(CFG, "sandbox", v.Opts())
    assert all(c.kind == "closed" for c in checks)
    for a in ADDRS:
        assert {(c.port) for c in checks if c.host == a} == {8443, 8000, 22, 9443}
    assert any(c.host == "inference.gpu.company.internal" for c in checks)


def test_sandbox_plan_with_stolen_cert():
    checks = [c for c in v.plan(CFG, "sandbox", GW) if c.kind == "https"]
    assert len(checks) == 2 and all(c.expect == "rejected" and c.cert == "gw.crt" for c in checks)
    assert all(c.ca is None for c in checks), "refusal probes must not depend on local server verification"


def test_gateway_plan_has_negative_and_positive_paths():
    ids = {c.id for c in v.plan(CFG, "gateway", GW)}
    for n in ("gpu-01", "gpu-02"):
        assert {f"{n}:proxy-open", f"{n}:no-cert-refused", f"{n}:path-allowlist", f"{n}:gateway-cert-ok",
                f"{n}:engine-closed", f"{n}:ssh-closed", f"{n}:metrics-closed"} <= ids
        assert f"{n}:proxy-closed" not in ids
    assert "upstream:gateway-cert-ok" in ids
    other = {c.id for c in v.plan(CFG, "gateway", v.Opts("gw.crt", "gw.key", "ca.pem", "o.crt", "o.key"))}
    assert "gpu-01:other-cert-refused" in other


def test_host_filter():
    checks = v.plan(CFG, "gateway", v.Opts("gw.crt", "gw.key", "ca.pem", targets=["gpu-02"]))
    assert {c.host for c in checks} == {"10.40.0.12"}


# ---------------------------------------------------------------- evaluation

def test_sandbox_all_pass_when_enforced():
    results = v.run(CFG, "sandbox", GW, FakeNet())
    assert results and all(r.passed for r in results)


def test_sandbox_fails_when_proxy_reachable():
    net = FakeNet({("10.40.0.11", 8443)}, enforced_proxy)
    r = by_id(v.run(CFG, "sandbox", v.Opts(), net))
    assert not r["gpu-01:proxy-closed"].passed and r["gpu-02:proxy-closed"].passed


def test_sandbox_stolen_cert_fails_without_source_pinning():
    # Network and envoy RBAC both missing: the cert alone gets an answer -> must be reported.
    net = FakeNet(GATEWAY_VIEW, enforced_proxy)
    r = by_id(v.run(CFG, "sandbox", GW, net))
    assert not r["gpu-01:stolen-cert-refused"].passed and r["gpu-01:stolen-cert-refused"].detail == "HTTP 200"


def test_sandbox_refused_is_pass_with_note():
    class Refusing(FakeNet):
        def connect(self, host, port, timeout):
            return v.REFUSED
    r = v.run(CFG, "sandbox", v.Opts(), Refusing())
    assert all(x.passed for x in r) and "drops silently" in r[0].detail


def test_gateway_all_pass_when_enforced():
    results = v.run(CFG, "gateway", v.Opts("gw.crt", "gw.key", "ca.pem", "o.crt", "o.key"), FakeNet(GATEWAY_VIEW, enforced_proxy))
    assert all(r.passed for r in results), v.report(results, "gateway")


@pytest.mark.parametrize("broken, failing", [
    (lambda h, p, path, cert: v.Http(status=200), {"no-cert-refused", "path-allowlist", "other-cert-refused"}),  # no mTLS
    (lambda h, p, path, cert: v.Http(status=200) if cert else v.Http(error="alert"), {"path-allowlist", "other-cert-refused"}),  # CA only, no SAN pin
    (lambda h, p, path, cert: v.Http(error="alert"), {"gateway-cert-ok", "path-allowlist"}),  # gateway itself locked out
])
def test_gateway_detects_misconfiguration(broken, failing):
    r = v.run(CFG, "gateway", v.Opts("gw.crt", "gw.key", "ca.pem", "o.crt", "o.key"), FakeNet(GATEWAY_VIEW, broken))
    failed = {x.check.id.split(":", 1)[1] for x in r if not x.passed and x.check.id.startswith("gpu-01:")}
    assert failed == failing


def test_gateway_detects_engine_and_ssh_exposed():
    net = FakeNet(GATEWAY_VIEW | {("10.40.0.12", 8000), ("10.40.0.12", 22)}, enforced_proxy)
    r = by_id(v.run(CFG, "gateway", GW, net))
    assert not r["gpu-02:engine-closed"].passed and not r["gpu-02:ssh-closed"].passed and r["gpu-01:engine-closed"].passed


def test_report_and_exit_code(capsys):
    assert v.main(["--from", "sandbox"], net=FakeNet()) == 0
    out = capsys.readouterr().out
    assert "PASS  G-1" in out and "PASS  G-7" in out and "0 failed -- OK" in out
    assert v.main(["--from", "sandbox"], net=FakeNet({("10.40.0.11", 22)})) == 1
    assert "FAIL  G-7   gpu-01:ssh-closed" in capsys.readouterr().out


def test_control_endpoint_guards_vacuous_pass(capsys):
    # No route at all: every negative check "passes", but the control check exposes it.
    assert v.main(["--from", "sandbox", "--control", "10.10.0.5:22"], net=FakeNet()) == 1
    assert "FAIL  -     control:reachable" in capsys.readouterr().out
    assert v.main(["--from", "sandbox", "--control", "10.10.0.5:22"], net=FakeNet({("10.10.0.5", 22)})) == 0
    with pytest.raises(SystemExit):
        v.main(["--from", "sandbox", "--control", "10.10.0.5"], net=FakeNet())


def test_gateway_requires_cert_args():
    with pytest.raises(SystemExit):
        v.main(["--from", "gateway"], net=FakeNet())
    with pytest.raises(SystemExit):
        v.main(["--from", "sandbox", "--cert", "x"], net=FakeNet())
    with pytest.raises(SystemExit):
        v.main(["--from", "sandbox", "--host", "gpu-99"], net=FakeNet())


# ---------------------------------------------------------------- real TLS (Net)

def openssl(*args, cwd):
    subprocess.run(["openssl", *args], cwd=cwd, check=True, capture_output=True)


def leaf(d, name, san, usage):
    openssl("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-subj", f"/CN={name}",
            "-keyout", f"{name}.key", "-out", f"{name}.csr", cwd=d)
    (d / f"{name}.ext").write_text(f"subjectAltName=DNS:{san}\nextendedKeyUsage={usage}\nbasicConstraints=CA:FALSE\n"
                                   "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n")
    openssl("x509", "-req", "-in", f"{name}.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-days", "1",
            "-extfile", f"{name}.ext", "-out", f"{name}.crt", cwd=d)


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    if not shutil.which("openssl"):
        pytest.skip("needs openssl")
    d = tmp_path_factory.mktemp("pki")
    openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-subj", "/CN=test-ca",
            "-days", "1", "-keyout", "ca.key", "-out", "ca.pem",
            "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign", cwd=d)
    leaf(d, "server", CFG["upstream_host"], "serverAuth")
    leaf(d, "gw", CFG["client_san_dns"], "clientAuth")
    leaf(d, "other", "laptop.company.internal", "clientAuth")
    return d


@pytest.fixture
def mtls_server(pki):
    """Stands in for envoy: client cert from the CA required, SAN pinned, path allow-list."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(pki / "server.crt", pki / "server.key")
    ctx.load_verify_locations(pki / "ca.pem")
    ctx.verify_mode = ssl.CERT_REQUIRED
    srv = socket.create_server(("127.0.0.1", 0))
    stop = threading.Event()

    def serve():
        srv.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except OSError:
                continue
            try:
                with ctx.wrap_socket(conn, server_side=True) as s:
                    sans = [x[1] for x in s.getpeercert().get("subjectAltName", ())]
                    req = s.recv(1024).decode()
                    if sans != [CFG["client_san_dns"]]:
                        continue  # envoy closes the connection
                    path = req.split(" ")[1]
                    status = 200 if path in CFG["allowed_paths"] else 404
                    s.sendall(f"HTTP/1.1 {status} X\r\ncontent-length: 0\r\n\r\n".encode())
            except (OSError, ssl.SSLError):
                pass

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    yield srv.getsockname()[1]
    stop.set()
    t.join()
    srv.close()


def test_net_against_real_mtls(pki, mtls_server):
    net, port, sn = v.Net(), mtls_server, CFG["upstream_host"]
    get = lambda path="/v1/models", **kw: net.https_get("127.0.0.1", port, path, sn, timeout=3, **kw)  # noqa: E731
    gw = {"cert": str(pki / "gw.crt"), "key": str(pki / "gw.key")}
    assert get(ca=str(pki / "ca.pem"), **gw).status == 200
    assert get("/metrics", ca=str(pki / "ca.pem"), **gw).status == 404
    assert get().status is None                                               # no client cert
    assert get(cert=str(pki / "other.crt"), key=str(pki / "other.key")).status is None   # wrong SAN
    assert net.connect("127.0.0.1", port, 3) == v.OPEN
    closed = socket.create_server(("127.0.0.1", 0)); p = closed.getsockname()[1]; closed.close()
    assert net.connect("127.0.0.1", p, 3) == v.REFUSED
    assert net.connect("nonexistent.invalid", 443, 3) == v.DNS


def test_full_gateway_run_against_real_mtls(pki, mtls_server, monkeypatch):
    # The whole gateway plan for one host, with the host address rewritten to the local server.
    class Local(v.Net):
        def connect(self, host, port, timeout):
            return super().connect("127.0.0.1", mtls_server if port == CFG["proxy_port"] else 1, timeout)

        def https_get(self, host, port, *a, **kw):
            return super().https_get("127.0.0.1", mtls_server, *a, **kw)

    o = v.Opts(str(pki / "gw.crt"), str(pki / "gw.key"), str(pki / "ca.pem"), str(pki / "other.crt"), str(pki / "other.key"),
               targets=["gpu-01"])
    results = v.run(CFG, "gateway", o, Local(), timeout=3)
    assert all(r.passed for r in results), v.report(results, "gateway")
