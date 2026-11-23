"""Policy bundles: the unit published from the GitOps policy repository.

CI validates every policy file on pull requests, then on the protected branch builds
a bundle, signs it with Ed25519 and publishes it to the Policy API. The API verifies
the signature and refuses bundles whose serial is not newer than the last one, so an
old signed bundle cannot be replayed.
"""
import argparse
import base64
import fnmatch
import hashlib
import json
import re
import sys
from pathlib import Path

import yaml
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .compiler import PolicyError, compile_policy

BUNDLE_FORMAT = 1
POLICY_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,127}")
ENVIRONMENTS = {"development", "staging", "production"}
# Keys that describe how a policy is selected rather than what it allows.
META_KEYS = {"policy_id", "version", "priority", "match", "description"}


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256(obj) -> str:
    return hashlib.sha256(canonical(obj)).hexdigest()


def document(policy):
    """The part of a policy file that the compiler and permission checks use."""
    return {k: v for k, v in policy.items() if k not in META_KEYS}


def validate_policy(p, source="policy"):
    def fail(msg):
        raise PolicyError(f"{source}: {msg}")
    if not isinstance(p.get("policy_id"), str) or not POLICY_ID.fullmatch(p["policy_id"]):
        fail("policy_id must be lowercase letters, digits and dashes")
    if not isinstance(p.get("version"), int) or p["version"] < 1:
        fail("version must be a positive integer")
    if not isinstance(p.get("priority"), int):
        fail("priority must be an integer")
    m = p.get("match")
    if not isinstance(m, dict) or not m.get("repos"):
        fail("match.repos is required (use ['*'] to match every repository)")
    unknown = set(m) - {"repos", "environments", "groups"}
    if unknown:
        fail(f"unknown match keys: {sorted(unknown)}")
    bad_env = set(m.get("environments", [])) - ENVIRONMENTS
    if bad_env:
        fail(f"unknown environments: {sorted(bad_env)}")
    try:
        compile_policy(document(p))
    except PolicyError as e:
        fail(str(e))


def load_dir(path):
    policies, ids, priorities = [], {}, {}
    files = sorted(Path(path).glob("*.yaml")) + sorted(Path(path).glob("*.yml"))
    if not files:
        raise PolicyError(f"no policy files in {path}")
    for f in files:
        p = yaml.safe_load(f.read_text())
        validate_policy(p, f.name)
        if p["policy_id"] in ids:
            raise PolicyError(f"{f.name}: duplicate policy_id {p['policy_id']!r} (also in {ids[p['policy_id']]})")
        # Selection takes the highest-priority match, so priorities must be unambiguous.
        if p["priority"] in priorities:
            raise PolicyError(f"{f.name}: priority {p['priority']} already used by {priorities[p['priority']]}")
        ids[p["policy_id"]] = priorities[p["priority"]] = f.name
        policies.append(p)
    return sorted(policies, key=lambda p: p["policy_id"])


def build(path, serial, git_commit):
    if serial < 1:
        raise PolicyError("serial must be positive")
    return {"format": BUNDLE_FORMAT, "serial": serial, "git_commit": git_commit, "policies": load_dir(path)}


def sign(bundle, private_key_pem: bytes, key_id: str):
    key = serialization.load_pem_private_key(private_key_pem, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise PolicyError("signing key must be Ed25519")
    return {"bundle": bundle, "key_id": key_id, "signature": base64.b64encode(key.sign(canonical(bundle))).decode()}


def verify(envelope, public_key_pem: bytes):
    key = serialization.load_pem_public_key(public_key_pem)
    if not isinstance(key, Ed25519PublicKey):
        raise PolicyError("verification key must be Ed25519")
    try:
        key.verify(base64.b64decode(envelope["signature"], validate=True), canonical(envelope["bundle"]))
    except (InvalidSignature, ValueError, KeyError, TypeError):
        raise PolicyError("bundle signature is invalid")
    return envelope["bundle"]


def validate_bundle(bundle):
    if bundle.get("format") != BUNDLE_FORMAT:
        raise PolicyError(f"unsupported bundle format {bundle.get('format')!r}")
    if not isinstance(bundle.get("serial"), int) or bundle["serial"] < 1:
        raise PolicyError("bundle serial must be a positive integer")
    seen_ids, seen_prio = set(), set()
    for p in bundle.get("policies") or []:
        validate_policy(p, p.get("policy_id", "policy"))
        if p["policy_id"] in seen_ids or p["priority"] in seen_prio:
            raise PolicyError(f"duplicate policy_id or priority: {p['policy_id']}")
        seen_ids.add(p["policy_id"]); seen_prio.add(p["priority"])
    if not seen_ids:
        raise PolicyError("bundle has no policies")


def normalize_repo(repo: str) -> str:
    """git@github.com:co/r.git, https://github.com/co/r -> github.com/co/r; local paths -> local:<path>."""
    m = re.fullmatch(r"(?:[\w.-]+@)?([\w.-]+):(?!//)([^\s]+?)(?:\.git)?/?", repo) or \
        re.fullmatch(r"(?:https?|ssh|git)://(?:[^@/]+@)?([\w.-]+)(?::\d+)?/([^\s]+?)(?:\.git)?/?", repo)
    if m and not repo.startswith("/"):
        return f"{m.group(1).lower()}/{m.group(2)}"
    return f"local:{repo}"


def matches(policy, repo: str, environment: str, groups=()):
    m = policy.get("match") or {}
    if not m.get("repos"):
        return False
    r = normalize_repo(repo)
    if not any(fnmatch.fnmatchcase(r, pat) for pat in m["repos"]):
        return False
    if m.get("environments") and environment not in m["environments"]:
        return False
    if m.get("groups") and not set(m["groups"]) & set(groups):
        return False
    return True


def main():
    ap = argparse.ArgumentParser(prog="company-policy")
    sub = ap.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("validate", help="validate every policy file in a directory")
    v.add_argument("dir")
    b = sub.add_parser("bundle", help="build and sign a policy bundle")
    b.add_argument("dir"); b.add_argument("--serial", type=int, required=True); b.add_argument("--commit", required=True)
    b.add_argument("--key", required=True, help="Ed25519 private key PEM file"); b.add_argument("--key-id", required=True)
    b.add_argument("--out", required=True)
    k = sub.add_parser("keygen", help="generate an Ed25519 signing key pair")
    k.add_argument("private"); k.add_argument("public")
    a = ap.parse_args()
    try:
        if a.cmd == "validate":
            for p in load_dir(a.dir):
                print(f"ok {p['policy_id']} v{p['version']} priority={p['priority']}")
        elif a.cmd == "bundle":
            env = sign(build(a.dir, a.serial, a.commit), Path(a.key).read_bytes(), a.key_id)
            Path(a.out).write_text(json.dumps(env, indent=2, ensure_ascii=False))
            print(f"{a.out}: serial {a.serial}, {len(env['bundle']['policies'])} policies, sha256 {sha256(env['bundle'])}")
        else:
            key = Ed25519PrivateKey.generate()
            Path(a.private).write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            Path(a.private).chmod(0o600)
            Path(a.public).write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
            print(f"wrote {a.private} (keep secret) and {a.public}")
    except PolicyError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
