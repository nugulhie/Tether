"""A test OpenID Connect provider for the clean-VM install test with AUTH_MODE=oidc (infra/testvm/install-test.sh).
Never for a real install: it signs whatever /issue is asked for.

Serves, on 0.0.0.0:9000, as the issuer in $ISSUER (e.g. http://10.0.2.15:9000):
  GET  /.well-known/openid-configuration   discovery (jwks_uri, device_authorization_endpoint, token_endpoint)
  GET  /jwks                               the RS256 public key
  POST /device, POST /token                device authorization grant (RFC 8628), approved at once for $DEVICE_USER;
                                           refresh_token grant
  GET  /issue?email=&groups=&hd=&aud=&email_verified=&exp_in=
                                           an ID token for the e2e checks. hd defaults to the e-mail's domain ("" leaves
                                           it out), aud to $CLIENT_ID, exp_in (seconds) to 600.
Needs PyJWT[crypto]. A new key on every start.
"""
import json
import os
import secrets
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

ISSUER = os.environ["ISSUER"].rstrip("/")
CLIENT_ID = os.environ.get("CLIENT_ID", "tether-test")
DEVICE_USER = os.environ.get("DEVICE_USER", "device-user@test.example")
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
KID = secrets.token_hex(4)
JWK = {**json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(KEY.public_key())), "kid": KID, "use": "sig", "alg": "RS256"}


def id_token(email, groups=(), hd=None, aud=None, email_verified=True, exp_in=600):
    now = int(time.time())
    claims = {"iss": ISSUER, "aud": aud or CLIENT_ID, "sub": "sub-" + email, "email": email, "email_verified": email_verified,
              "iat": now, "exp": now + exp_in}
    hd = email.rsplit("@", 1)[-1] if hd is None else hd
    if hd:
        claims["hd"] = hd
    if groups:
        claims["groups"] = list(groups)
    return jwt.encode(claims, KEY, algorithm="RS256", headers={"kid": KID})


class Handler(BaseHTTPRequestHandler):
    def reply(self, status, body, ctype="application/json"):
        data = (json.dumps(body) if ctype == "application/json" else body).encode()
        self.send_response(status)
        self.send_header("content-type", ctype)
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        url = urllib.parse.urlsplit(self.path)
        q = dict(urllib.parse.parse_qsl(url.query, keep_blank_values=True))
        if url.path == "/.well-known/openid-configuration":
            return self.reply(200, {"issuer": ISSUER, "jwks_uri": ISSUER + "/jwks", "token_endpoint": ISSUER + "/token",
                                    "device_authorization_endpoint": ISSUER + "/device", "id_token_signing_alg_values_supported": ["RS256"]})
        if url.path == "/jwks":
            return self.reply(200, {"keys": [JWK]})
        if url.path == "/issue":
            groups = [g for g in q.get("groups", "").split(",") if g]
            verified = q.get("email_verified", "true") != "false"
            token = id_token(q["email"], groups, q.get("hd"), q.get("aud") or None, verified, int(q.get("exp_in", "600")))
            return self.reply(200, token, "text/plain")
        self.reply(404, {"error": "not_found"})

    def do_POST(self):
        form = dict(urllib.parse.parse_qsl(self.rfile.read(int(self.headers.get("content-length") or 0)).decode()))
        if form.get("client_id") != CLIENT_ID:
            return self.reply(401, {"error": "invalid_client"})
        if self.path == "/device":
            return self.reply(200, {"device_code": secrets.token_urlsafe(16), "user_code": "TEST-CODE", "interval": 1, "expires_in": 60,
                                    "verification_uri": ISSUER + "/activate"})
        if self.path == "/token" and form.get("grant_type") in ("urn:ietf:params:oauth:grant-type:device_code", "refresh_token"):
            return self.reply(200, {"id_token": id_token(DEVICE_USER), "refresh_token": secrets.token_urlsafe(16), "token_type": "Bearer",
                                    "expires_in": 600})
        self.reply(400, {"error": "unsupported_grant_type"})

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 9000), Handler).serve_forever()
