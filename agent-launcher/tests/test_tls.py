"""Real TLS handshakes (no mocked client): the company CA is trusted and the client certificate is sent."""
import http.server
import shutil
import ssl
import subprocess
import threading

import httpx
import pytest

import tether_launcher.cli as cli

pytestmark = pytest.mark.skipif(not shutil.which("openssl"), reason="needs the openssl CLI")


def sh(*args, cwd):
    subprocess.run(["openssl", *args], cwd=cwd, check=True, capture_output=True)


@pytest.fixture
def pki(tmp_path):
    d = tmp_path
    for ca in ("server-ca", "user-ca"):
        sh("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", f"{ca}.key",
           "-out", f"{ca}.crt", "-days", "1", "-subj", f"/CN={ca}",
           "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign", cwd=d)
    # Python 3.13 verifies strictly (VERIFY_X509_STRICT): leaf certificates need an Authority Key Identifier.
    (d / "server.ext").write_text("subjectAltName=IP:127.0.0.1\nauthorityKeyIdentifier=keyid\nextendedKeyUsage=serverAuth\n")
    (d / "kim.ext").write_text("authorityKeyIdentifier=keyid\nextendedKeyUsage=clientAuth\n")
    for name, ca, ext in (("server", "server-ca", ["-extfile", "server.ext"]), ("kim", "user-ca", ["-extfile", "kim.ext"])):
        sh("req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", f"{name}.key", "-out", f"{name}.csr",
           "-subj", f"/O=Tether/CN={name}", cwd=d)
        sh("x509", "-req", "-in", f"{name}.csr", "-CA", f"{ca}.crt", "-CAkey", f"{ca}.key", "-CAcreateserial", "-days", "1",
           "-out", f"{name}.crt", *ext, cwd=d)
    return d


@pytest.fixture
def server(pki):
    seen = []

    class H(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            seen.append(dict(x[0] for x in self.connection.getpeercert()["subject"])["commonName"])
            self.send_response(200); self.send_header("content-type", "application/json"); self.end_headers()
            self.wfile.write(b'{"token":"t","expires_at":9999999999,"user_id":"kim"}')

        def log_message(self, *a):
            pass

    httpd = http.server.HTTPServer(("127.0.0.1", 0), H)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(pki / "server.crt", pki / "server.key")
    ctx.load_verify_locations(pki / "user-ca.crt")
    ctx.verify_mode = ssl.CERT_REQUIRED  # like the people listener: no certificate, no connection
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"https://127.0.0.1:{httpd.server_port}", seen
    httpd.shutdown()


def configure(monkeypatch, tmp_path, pki, url, cert=True):
    monkeypatch.setattr(cli, "MANAGED_CONFIG", tmp_path / "none.json")
    monkeypatch.setattr(cli, "HOME", tmp_path)
    monkeypatch.setattr(cli, "TOKEN_FILE", tmp_path / "token.json")
    monkeypatch.delenv("TETHER_TOKEN", raising=False)
    monkeypatch.setenv("TETHER_ORCHESTRATOR", url)
    monkeypatch.setenv("TETHER_CA_BUNDLE", str(pki / "server-ca.crt"))
    if cert:
        monkeypatch.setenv("TETHER_CLIENT_CERT", str(pki / "kim.crt"))
        monkeypatch.setenv("TETHER_CLIENT_KEY", str(pki / "kim.key"))


def test_certificate_login_over_real_tls(monkeypatch, tmp_path, pki, server):
    url, seen = server
    configure(monkeypatch, tmp_path, pki, url)
    assert cli.mtls_token()["user_id"] == "kim"
    assert seen == ["kim"]  # the server saw the person's certificate


def test_server_outside_the_company_ca_is_refused(monkeypatch, tmp_path, pki, server):
    url, _ = server
    configure(monkeypatch, tmp_path, pki, url)
    monkeypatch.setenv("TETHER_CA_BUNDLE", str(pki / "user-ca.crt"))  # wrong CA for the server
    with pytest.raises(cli.click.ClickException, match="cannot reach"):
        cli.mtls_token()


def test_websocket_context_carries_the_same_trust_and_certificate(monkeypatch, tmp_path, pki):
    configure(monkeypatch, tmp_path, pki, "https://x")
    ctx = cli.tls_context()
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname
    assert any(c["subject"] == ((("commonName", "server-ca"),),) for c in ctx.get_ca_certs())
