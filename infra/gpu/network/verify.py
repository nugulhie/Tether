#!/usr/bin/env python3
"""Check GPU inference network enforcement from where you stand (ADR 0001 D2; G-1, G-7).

Run it twice, from two networks:

  # 1. any non-gateway network (developer laptop, office network, an agent sandbox)
  python verify.py --from sandbox [--cert gw.crt --key gw.key --ca ca.pem]
  # 2. the LLM gateway's network (same egress address as the gateway)
  python verify.py --from gateway --cert gw.crt --key gw.key --ca ca.pem [--other-cert c --other-key k]

From a sandbox everything must be unreachable: proxy, engine, SSH and metrics ports. If you pass
the gateway certificate there, it must still be refused (a stolen certificate is not enough).
From the gateway, the proxy must refuse connections without a client certificate (and with a
certificate that is not the gateway's), refuse paths outside the allow-list, and serve
GET /v1/models with the gateway certificate. Exit code 0 only when every check passes.
"""
import argparse
import json
import socket
import ssl
import sys
from dataclasses import dataclass, field
from pathlib import Path

import generate

OPEN, REFUSED, TIMEOUT, NO_ROUTE, DNS = "open", "refused", "timeout", "unreachable", "dns-error"


@dataclass
class Http:
    status: int | None = None   # HTTP status, None when no HTTP response came back
    error: str | None = None    # TLS / socket error, if any


class Net:
    """Real network calls. Tests substitute an object with the same two methods."""

    def connect(self, host, port, timeout):
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return OPEN
        except socket.gaierror:
            return DNS
        except ConnectionRefusedError:
            return REFUSED
        except (TimeoutError, socket.timeout):
            return TIMEOUT
        except OSError as e:
            return f"{NO_ROUTE}: {e.strerror or e}"

    def https_get(self, host, port, path, server_name, ca=None, cert=None, key=None, timeout=5.0):
        if ca:
            ctx = ssl.create_default_context(cafile=ca)
        else:  # negative probes only: the server certificate is not what is being tested
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        if cert:
            ctx.load_cert_chain(cert, key)
        try:
            with socket.create_connection((host, port), timeout=timeout) as raw, \
                    ctx.wrap_socket(raw, server_hostname=server_name) as s:
                # With TLS 1.3 the server rejects a missing or wrong client certificate after the
                # client considers the handshake done, so the refusal shows up on the first read.
                s.sendall(f"GET {path} HTTP/1.1\r\nHost: {server_name}\r\nConnection: close\r\n\r\n".encode())
                head = s.recv(64)
        except (OSError, ssl.SSLError) as e:
            return Http(error=f"{type(e).__name__}: {e}")
        parts = head.split(b" ", 2)
        if len(parts) >= 2 and parts[0].startswith(b"HTTP/") and parts[1].isdigit():
            return Http(status=int(parts[1]))
        return Http(error="connection closed without an HTTP response")


@dataclass
class Check:
    id: str
    threat: str          # G-1 / G-7
    desc: str
    kind: str            # "closed" | "open" | "https"
    host: str
    port: int
    expect: str = ""     # https: "rejected" | "200" | "404"
    path: str = "/v1/models"
    cert: str | None = None
    key: str | None = None
    ca: str | None = None
    server_name: str = ""


@dataclass
class Result:
    check: Check
    passed: bool
    detail: str


@dataclass
class Opts:
    cert: str | None = None
    key: str | None = None
    ca: str | None = None
    other_cert: str | None = None
    other_key: str | None = None
    targets: list = field(default_factory=list)   # restrict to these host names (empty: all)
    control: tuple | None = None                   # (host, port) that must be reachable from here


def plan(c, vantage, o: Opts):
    """The checks to run from `vantage` ("sandbox" or "gateway") for config `c`. Probes that expect a
    refusal skip server verification, so a wrong --ca cannot make them pass by failing locally."""
    hosts = [h for h in c["hosts"] if not o.targets or h["name"] in o.targets]
    sn, checks = c["upstream_host"], []
    if o.control:
        # Negative checks only mean something if this network has a route to the GPU subnet.
        checks.append(Check("control:reachable", "-", f"control endpoint {o.control[0]}:{o.control[1]} is reachable "
                            "(this network routes to the GPU subnet)", "open", o.control[0], o.control[1]))
    for h in hosts:
        a, n = h["address"].compressed, h["name"]
        closed = [("engine", c["engine_port"], "G-1", "engine port is not reachable (loopback only)"),
                  ("ssh", c["ssh_port"], "G-7", "SSH is not reachable except from the bastion")]
        if c["metrics_port"]:
            closed.append(("metrics", c["metrics_port"], "G-1", "metrics port is not reachable outside monitoring"))
        if vantage == "sandbox":
            closed.insert(0, ("proxy", c["proxy_port"], "G-1", "serving port is not reachable from a non-gateway source"))
        for what, port, g, desc in closed:
            checks.append(Check(f"{n}:{what}-closed", g, desc, "closed", a, port))
        if vantage == "sandbox" and o.cert:
            checks.append(Check(f"{n}:stolen-cert-refused", "G-1", "gateway certificate from a non-gateway source is refused",
                                "https", a, c["proxy_port"], "rejected", cert=o.cert, key=o.key, server_name=sn))
        if vantage == "gateway":
            p = c["proxy_port"]
            checks += [
                Check(f"{n}:proxy-open", "G-1", "serving port is reachable from the gateway", "open", a, p),
                Check(f"{n}:no-cert-refused", "G-1", "TLS without a client certificate is refused", "https", a, p,
                      "rejected", server_name=sn),
                Check(f"{n}:path-allowlist", "G-1", "paths outside the allow-list get 404 at the proxy", "https", a, p,
                      "404", path="/metrics", cert=o.cert, key=o.key, ca=o.ca, server_name=sn),
                Check(f"{n}:gateway-cert-ok", "G-1", "gateway certificate gets GET /v1/models 200", "https", a, p,
                      "200", cert=o.cert, key=o.key, ca=o.ca, server_name=sn),
            ]
            if o.other_cert:
                checks.append(Check(f"{n}:other-cert-refused", "G-1", "a certificate without the gateway SAN is refused",
                                    "https", a, p, "rejected", cert=o.other_cert, key=o.other_key, server_name=sn))
    # Through the name the gateway actually uses (LOCAL_UPSTREAM).
    if vantage == "sandbox":
        checks.append(Check("upstream:proxy-closed", "G-1", f"{sn} is not reachable from a non-gateway source",
                            "closed", sn, c["proxy_port"]))
    elif not o.targets:
        checks.append(Check("upstream:gateway-cert-ok", "G-1", f"LOCAL_UPSTREAM ({c['upstream']}) serves the gateway",
                            "https", sn, c["proxy_port"], "200", cert=o.cert, key=o.key, ca=o.ca, server_name=sn))
    return checks


def evaluate(ch: Check, net, timeout=5.0) -> Result:
    if ch.kind == "closed":
        r = net.connect(ch.host, ch.port, timeout)
        note = "" if r != REFUSED else " (host answered with RST; the nftables ruleset drops silently)"
        return Result(ch, r != OPEN, r + note)
    if ch.kind == "open":
        r = net.connect(ch.host, ch.port, timeout)
        return Result(ch, r == OPEN, r)
    r = net.https_get(ch.host, ch.port, ch.path, ch.server_name, ca=ch.ca, cert=ch.cert, key=ch.key, timeout=timeout)
    got = f"HTTP {r.status}" if r.status is not None else (r.error or "no response")
    if ch.expect == "rejected":
        # Refused at TCP, TLS or by envoy RBAC: anything but an HTTP response from behind the proxy.
        return Result(ch, r.status is None, got)
    return Result(ch, r.status == int(ch.expect), got)


def run(c, vantage, o: Opts, net=None, timeout=5.0):
    net = net or Net()
    return [evaluate(ch, net, timeout) for ch in plan(c, vantage, o)]


def report(results, vantage):
    lines = [f"GPU inference network checks from: {vantage}", ""]
    for r in results:
        lines.append(f"{'PASS' if r.passed else 'FAIL'}  {r.check.threat:4}  {r.check.id:32} {r.check.desc}  [{r.detail}]")
    failed = sum(not r.passed for r in results)
    lines += ["", f"{len(results) - failed} passed, {failed} failed" + ("" if failed else " -- OK")]
    return "\n".join(lines)


def main(argv=None, net=None):
    ap = argparse.ArgumentParser(description="Verify GPU inference network enforcement (ADR 0001 G-1, G-7).")
    ap.add_argument("--from", dest="vantage", required=True, choices=["sandbox", "gateway"],
                    help="where this runs: sandbox = any non-gateway network")
    ap.add_argument("--config", default=str(Path(__file__).parent / "config.yaml"))
    ap.add_argument("--cert", help="gateway client certificate (LOCAL_CLIENT_CERT)")
    ap.add_argument("--key", help="gateway client key (LOCAL_CLIENT_KEY)")
    ap.add_argument("--ca", help="CA bundle for the inference server certificate (LOCAL_CA_BUNDLE)")
    ap.add_argument("--other-cert", help="a valid client certificate that is NOT the gateway's (optional)")
    ap.add_argument("--other-key")
    ap.add_argument("--host", action="append", default=[], help="limit to these inference host names")
    ap.add_argument("--control", metavar="HOST:PORT",
                    help="an endpoint next to the GPU hosts that IS reachable from here (e.g. the bastion's SSH); "
                         "proves the negative checks are not passing only for lack of a route")
    ap.add_argument("--timeout", type=float, default=5.0)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    if a.vantage == "gateway" and not (a.cert and a.key and a.ca):
        ap.error("--from gateway needs --cert, --key and --ca")
    if bool(a.cert) != bool(a.key) or bool(a.other_cert) != bool(a.other_key):
        ap.error("a certificate needs its key")
    c = generate.load_config(generate.read_config(a.config))
    unknown = set(a.host) - {h["name"] for h in c["hosts"]}
    if unknown:
        ap.error(f"unknown hosts: {sorted(unknown)}")
    control = None
    if a.control:
        host, _, port = a.control.rpartition(":")
        if not host or not port.isdigit():
            ap.error("--control must be HOST:PORT")
        control = (host.strip("[]"), int(port))
    o = Opts(a.cert, a.key, a.ca, a.other_cert, a.other_key, a.host, control)
    results = run(c, a.vantage, o, net, a.timeout)
    if a.json:
        print(json.dumps([{"id": r.check.id, "threat": r.check.threat, "passed": r.passed, "detail": r.detail,
                           "desc": r.check.desc} for r in results], indent=2))
    else:
        print(report(results, a.vantage))
    return 0 if results and all(r.passed for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
