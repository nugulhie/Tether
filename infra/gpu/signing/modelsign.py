#!/usr/bin/env python3
"""Sign and verify model weights and serving images for the GPU inference servers (ADR 0001, G-6).

The inference server loads only weights and runs only images that the company signed. Every
check fails closed: any doubt (unknown key, extra or missing file, symlink, unreadable file,
cosign missing) is a failure, and there is deliberately no flag or variable that skips a check.

  modelsign.py keygen PRIVATE PUBLIC
  modelsign.py manifest DIR --model NAME --version VERSION [--out DIR/model-manifest.json]
  modelsign.py sign MANIFEST (--key FILE | --key-env VAR) --key-id ID [--out MANIFEST.sig]
  modelsign.py verify --dir DIR --keys KEYDIR [--manifest M] [--signature S] [--expect-model N] [--expect-version V]
  modelsign.py verify-image --image REGISTRY/REPO@sha256:DIGEST --keys KEYDIR [--cosign PATH]

`verify` and `verify-image` print exactly one JSON event line (`model.verify` / `image.verify`)
on stdout for log shipping and exit non-zero on failure. Human-readable messages go to stderr.

Signing follows services/policy-compiler (policy bundles): Ed25519 over canonical JSON
(sorted keys, compact separators, UTF-8), base64 signature in a small envelope with a key id.
"""
import argparse
import base64
import hashlib
import json
import os
import re
import socket
import stat
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

MANIFEST_FORMAT = 1
SIGNATURE_FORMAT = 1
MANIFEST_NAME = "model-manifest.json"
SIGNATURE_NAME = MANIFEST_NAME + ".sig"
CHUNK = 8 * 1024 * 1024  # read size for streaming hashes; multi-GB shards never sit in memory
KEY_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}")
SHA256_HEX = re.compile(r"[a-f0-9]{64}")
# Image references must be pinned by digest; tags (even tag@digest) are refused.
DIGEST_REF = re.compile(r"[a-z0-9.-]+(?::[0-9]+)?/[a-z0-9._/-]+@sha256:[a-f0-9]{64}")
# ADR 0001 G-6: safetensors only. These formats can carry pickle and execute code on load.
PICKLE_SUFFIXES = {".bin", ".pt", ".pth", ".pkl", ".pickle", ".ckpt", ".joblib"}
COSIGN_TIMEOUT = 300


class SignError(Exception):
    """Errors from manifest/sign (operator mistakes); never carries key material."""


class VerifyError(Exception):
    def __init__(self, reason: str, detail: str = ""):
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason, self.detail = reason, detail


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256(obj) -> str:
    return hashlib.sha256(canonical(obj)).hexdigest()


def strict_json(data: bytes, what: str):
    def no_duplicates(pairs):
        keys = [k for k, _ in pairs]
        if len(keys) != len(set(keys)):
            raise ValueError("duplicate key")
        return dict(pairs)

    def no_constants(name):
        raise ValueError(f"non-standard constant {name}")
    try:
        return json.loads(data, object_pairs_hook=no_duplicates, parse_constant=no_constants)
    except (ValueError, UnicodeDecodeError) as e:
        raise VerifyError("invalid_" + what, f"not valid JSON ({e})")


# ---- files -------------------------------------------------------------------------------

def check_path(rel: str):
    """A manifest path: relative POSIX path inside the model dir, no tricks."""
    if not isinstance(rel, str) or not rel or rel.startswith("/") or "\\" in rel:
        raise VerifyError("invalid_manifest", f"bad path {rel!r}")
    if any(part in ("", ".", "..") for part in rel.split("/")):
        raise VerifyError("invalid_manifest", f"bad path {rel!r}")
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in rel):
        raise VerifyError("invalid_manifest", f"control character in path {rel!r}")
    try:
        rel.encode()
    except UnicodeEncodeError:
        raise VerifyError("invalid_manifest", f"path is not valid UTF-8: {rel!r}")
    if rel in (MANIFEST_NAME, SIGNATURE_NAME):
        raise VerifyError("invalid_manifest", f"{rel} cannot list itself")
    if Path(rel).suffix.lower() in PICKLE_SUFFIXES:
        raise VerifyError("forbidden_format", f"{rel}: pickle-capable format, only safetensors weights are allowed")


def scan(root) -> dict:
    """Every regular file under root -> size. Any symlink or special file is a failure."""
    root = Path(root)
    try:
        st = os.lstat(root)
    except OSError as e:
        raise VerifyError("unreadable", f"{root}: {e.strerror}")
    if stat.S_ISLNK(st.st_mode):
        raise VerifyError("symlink", f"model directory {root} is a symlink")
    if not stat.S_ISDIR(st.st_mode):
        raise VerifyError("unreadable", f"{root} is not a directory")

    def fail(e):  # os.walk silently skips unreadable directories unless told otherwise
        raise VerifyError("unreadable", f"{e.filename}: {e.strerror}")
    files = {}
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False, onerror=fail):
        for name in sorted(dirnames + filenames):
            full = os.path.join(dirpath, name)
            rel = Path(full).relative_to(root).as_posix()
            st = os.lstat(full)
            if stat.S_ISLNK(st.st_mode):
                raise VerifyError("symlink", rel)
            if stat.S_ISDIR(st.st_mode):
                continue
            if not stat.S_ISREG(st.st_mode):
                raise VerifyError("special_file", rel)
            if rel in (MANIFEST_NAME, SIGNATURE_NAME):
                continue  # the manifest and its signature may ship inside the model dir
            files[rel] = st.st_size
    return files


def hash_file(path) -> tuple[str, int]:
    """Streaming sha256. O_NOFOLLOW so a file swapped for a symlink after the scan is refused."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as e:
        raise VerifyError("symlink" if os.path.islink(path) else "unreadable", f"{path}: {e.strerror}")
    with open(fd, "rb", buffering=0) as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            raise VerifyError("special_file", str(path))
        h, size = hashlib.sha256(), 0
        buf = bytearray(CHUNK)
        view = memoryview(buf)
        while n := f.readinto(buf):
            h.update(view[:n])
            size += n
    return h.hexdigest(), size


# ---- manifest and signature ----------------------------------------------------------------

def check_name(value, field):
    if not isinstance(value, str) or not NAME.fullmatch(value):
        raise VerifyError("invalid_manifest", f"{field} must match {NAME.pattern}: {value!r}")


def build_manifest(root, model: str, version: str) -> dict:
    check_name(model, "model"); check_name(version, "version")
    files = scan(root)
    if not files:
        raise VerifyError("invalid_manifest", f"{root} contains no files")
    entries = []
    for rel in sorted(files):
        check_path(rel)
        digest, size = hash_file(Path(root) / rel)
        entries.append({"path": rel, "size": size, "sha256": digest})
    return {"format": MANIFEST_FORMAT, "model": model, "version": version, "files": entries}


def validate_manifest(m) -> dict:
    if not isinstance(m, dict) or set(m) != {"format", "model", "version", "files"}:
        raise VerifyError("invalid_manifest", "expected keys format, model, version, files")
    if m["format"] != MANIFEST_FORMAT:
        raise VerifyError("invalid_manifest", f"unsupported manifest format {m['format']!r}")
    check_name(m["model"], "model"); check_name(m["version"], "version")
    files = m["files"]
    if not isinstance(files, list) or not files:
        raise VerifyError("invalid_manifest", "files must be a non-empty list")
    prev = None
    for e in files:
        if not isinstance(e, dict) or set(e) != {"path", "size", "sha256"}:
            raise VerifyError("invalid_manifest", "file entries need exactly path, size, sha256")
        check_path(e["path"])
        if type(e["size"]) is not int or e["size"] < 0:
            raise VerifyError("invalid_manifest", f"{e['path']}: bad size")
        if not isinstance(e["sha256"], str) or not SHA256_HEX.fullmatch(e["sha256"]):
            raise VerifyError("invalid_manifest", f"{e['path']}: bad sha256")
        if prev is not None and e["path"] <= prev:
            raise VerifyError("invalid_manifest", "paths must be unique and sorted")
        prev = e["path"]
    return m


def load_private_key(key_file=None, key_env=None, password_env=None) -> Ed25519PrivateKey:
    """Key from a 0600 file or an environment variable. Error messages never include key bytes."""
    if bool(key_file) == bool(key_env):
        raise SignError("give exactly one of --key or --key-env")
    if key_file:
        st = os.stat(key_file)
        if st.st_mode & 0o077:
            raise SignError(f"{key_file} is accessible by group/others; chmod 600 it")
        data = Path(key_file).read_bytes()
    else:
        value = os.environ.get(key_env)
        if not value:
            raise SignError(f"environment variable {key_env} is empty or unset")
        data = value.encode()
    password = None
    if password_env:
        password = (os.environ.get(password_env) or "").encode() or None
    try:
        key = serialization.load_pem_private_key(data, password=password)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        raise SignError("could not load the private key (not PEM, or wrong password)") from None
    if not isinstance(key, Ed25519PrivateKey):
        raise SignError("signing key must be Ed25519")
    return key


def sign(manifest: dict, key: Ed25519PrivateKey, key_id: str) -> dict:
    if not KEY_ID.fullmatch(key_id):
        raise SignError(f"key id must match {KEY_ID.pattern}")
    try:
        validate_manifest(manifest)
    except VerifyError as e:
        raise SignError(f"refusing to sign: {e}") from None
    return {"format": SIGNATURE_FORMAT, "key_id": key_id, "manifest_sha256": sha256(manifest),
            "signature": base64.b64encode(key.sign(canonical(manifest))).decode()}


def _check_store(path: Path):
    """A trusted key store that the service user (or anyone) could write to is not trusted."""
    try:
        if os.statvfs(path).f_flag & os.ST_RDONLY:
            return  # read-only mount (e.g. a Kubernetes ConfigMap volume)
    except OSError:
        pass
    for p in [path, *path.iterdir()]:
        if os.stat(p).st_mode & 0o022:
            raise VerifyError("untrusted_key_store", f"{p} is writable by group/others")


def trusted_key_files(keys_dir) -> dict:
    """<key_id>.pub files in keys_dir -> path. Removing a file revokes that key."""
    d = Path(keys_dir)
    if not d.is_dir():
        raise VerifyError("no_trusted_keys", f"{d} is not a directory")
    _check_store(d)
    out = {}
    for p in sorted(d.glob("*.pub")):
        if not KEY_ID.fullmatch(p.stem):
            raise VerifyError("untrusted_key_store", f"{p.name}: key id must match {KEY_ID.pattern}")
        out[p.stem] = p
    if not out:
        raise VerifyError("no_trusted_keys", f"no *.pub keys in {d}")
    return out


def load_trusted_keys(keys_dir) -> dict:
    keys = {}
    for key_id, p in trusted_key_files(keys_dir).items():
        try:
            key = serialization.load_pem_public_key(p.read_bytes())
        except (ValueError, UnsupportedAlgorithm):
            raise VerifyError("untrusted_key_store", f"{p.name} is not a PEM public key")
        if not isinstance(key, Ed25519PublicKey):
            raise VerifyError("untrusted_key_store", f"{p.name} is not an Ed25519 key")
        keys[key_id] = key
    return keys


def verify(model_dir, keys_dir, manifest_path=None, signature_path=None,
           expect_model=None, expect_version=None, ctx=None) -> dict:
    """Raises VerifyError on any mismatch. `ctx` is filled in as facts are learned (for the event)."""
    ctx = {} if ctx is None else ctx
    model_dir = Path(model_dir)
    manifest_path = Path(manifest_path or model_dir / MANIFEST_NAME)
    signature_path = Path(signature_path or model_dir / SIGNATURE_NAME)
    keys = load_trusted_keys(keys_dir)

    def read(p, what):
        try:
            return p.read_bytes()
        except OSError as e:
            raise VerifyError(f"missing_{what}", f"{p}: {e.strerror}")
    manifest = strict_json(read(manifest_path, "manifest"), "manifest")
    if isinstance(manifest, dict):  # unverified until the signature checks out; for the event only
        ctx.update(model=manifest.get("model"), version=manifest.get("version"))
    ctx["manifest_sha256"] = sha256(manifest)
    env = strict_json(read(signature_path, "signature"), "signature")
    if not isinstance(env, dict) or set(env) != {"format", "key_id", "manifest_sha256", "signature"} \
            or env["format"] != SIGNATURE_FORMAT:
        raise VerifyError("invalid_signature", "unexpected signature envelope")
    ctx["key_id"] = env["key_id"]
    if env["key_id"] not in keys:
        raise VerifyError("unknown_key", f"key id {env['key_id']!r} is not in {keys_dir}")
    if env["manifest_sha256"] != ctx["manifest_sha256"]:
        raise VerifyError("manifest_modified", "manifest does not match the signed digest")
    try:
        keys[env["key_id"]].verify(base64.b64decode(env["signature"], validate=True), canonical(manifest))
    except (InvalidSignature, ValueError, TypeError):
        raise VerifyError("bad_signature", f"signature does not verify with key {env['key_id']!r}")

    validate_manifest(manifest)
    if expect_model is not None and manifest["model"] != expect_model:
        raise VerifyError("unexpected_model", f"signed model is {manifest['model']!r}, expected {expect_model!r}")
    if expect_version is not None and manifest["version"] != expect_version:
        raise VerifyError("unexpected_version", f"signed version is {manifest['version']!r}, expected {expect_version!r}")

    on_disk = scan(model_dir)
    listed = {e["path"]: e for e in manifest["files"]}
    if missing := sorted(set(listed) - set(on_disk)):
        raise VerifyError("missing_file", ", ".join(missing[:10]))
    if extra := sorted(set(on_disk) - set(listed)):
        raise VerifyError("extra_file", ", ".join(extra[:10]))
    for rel, e in listed.items():
        if on_disk[rel] != e["size"]:
            raise VerifyError("size_mismatch", f"{rel}: {on_disk[rel]} bytes, signed {e['size']}")
    for rel, e in listed.items():
        digest, size = hash_file(model_dir / rel)
        if size != e["size"] or digest != e["sha256"]:
            raise VerifyError("hash_mismatch", rel)
    return manifest


def verify_image(image: str, keys_dir, cosign="cosign", ctx=None) -> str:
    """cosign verify --key against each trusted image key (rotation); returns the key id that verified."""
    ctx = {} if ctx is None else ctx
    if not isinstance(image, str) or not DIGEST_REF.fullmatch(image):
        raise VerifyError("image_not_pinned", f"{image!r}: use registry/repo@sha256:<digest>, not a tag")
    ctx["digest"] = image.rsplit("@", 1)[1]
    failures = []
    for key_id, path in trusted_key_files(keys_dir).items():
        # Key-based, offline: the pinned key is the trust anchor, so no public Rekor lookup
        # (GPU servers have no route to it). cosign still checks the signed digest claim.
        cmd = [cosign, "verify", "--key", str(path), "--insecure-ignore-tlog=true", "--output", "json", image]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=COSIGN_TIMEOUT, check=False)
        except FileNotFoundError:
            raise VerifyError("cosign_unavailable", f"{cosign} not found")
        except subprocess.TimeoutExpired:
            raise VerifyError("cosign_unavailable", f"cosign timed out after {COSIGN_TIMEOUT}s")
        if proc.returncode == 0:
            ctx["key_id"] = key_id
            return key_id
        failures.append(f"{key_id}: {(proc.stderr or '').strip().splitlines()[-1:] or ['failed']}")
    raise VerifyError("bad_signature", "no trusted key verified the image; " + "; ".join(failures))


# ---- CLI ---------------------------------------------------------------------------------------

def emit(event: str, result: dict):
    line = {"event": event, "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "host": socket.gethostname(), **result}
    print(json.dumps(line, sort_keys=True, ensure_ascii=False), flush=True)


def _run_check(event, fields, fn):
    ctx = {}
    try:
        try:
            fn(ctx)
        except OSError as e:  # anything unexpected on disk is a failure, never a pass
            raise VerifyError("unreadable", f"{e.filename}: {e.strerror}")
    except VerifyError as e:
        emit(event, {**{k: ctx.get(k) for k in fields}, "result": "failure", "reason": e.reason, "detail": e.detail})
        print(f"{event} FAILED: {e}", file=sys.stderr)
        return 1
    emit(event, {**{k: ctx.get(k) for k in fields}, "result": "success", "reason": None, "detail": ""})
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="modelsign", description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("keygen", help="generate an Ed25519 key pair (signing host only)")
    k.add_argument("private"); k.add_argument("public")
    m = sub.add_parser("manifest", help="hash a weights directory into a manifest")
    m.add_argument("dir"); m.add_argument("--model", required=True); m.add_argument("--version", required=True)
    m.add_argument("--out", help=f"default: DIR/{MANIFEST_NAME}")
    s = sub.add_parser("sign", help="write a detached Ed25519 signature for a manifest")
    s.add_argument("manifest"); s.add_argument("--key", help="private key PEM file (mode 0600)")
    s.add_argument("--key-env", help="environment variable holding the private key PEM")
    s.add_argument("--key-password-env", help="environment variable holding the key's PEM password")
    s.add_argument("--key-id", required=True); s.add_argument("--out", help="default: MANIFEST.sig")
    v = sub.add_parser("verify", help="verify a weights directory against its signed manifest")
    v.add_argument("--dir", required=True); v.add_argument("--keys", required=True, help="directory of <key_id>.pub")
    v.add_argument("--manifest"); v.add_argument("--signature")
    v.add_argument("--expect-model"); v.add_argument("--expect-version")
    i = sub.add_parser("verify-image", help="verify a serving image signature with cosign")
    i.add_argument("--image", required=True); i.add_argument("--keys", required=True, help="directory of <key_id>.pub (cosign)")
    i.add_argument("--cosign", default=os.environ.get("COSIGN", "cosign"))
    a = ap.parse_args(argv)

    if a.cmd == "verify":
        def check(ctx):
            ctx["model"], ctx["version"] = a.expect_model, a.expect_version
            verify(a.dir, a.keys, a.manifest, a.signature, a.expect_model, a.expect_version, ctx)
        return _run_check("model.verify", ["model", "version", "manifest_sha256", "key_id"], check)
    if a.cmd == "verify-image":
        def check(ctx):
            ctx["image"] = a.image
            verify_image(a.image, a.keys, a.cosign, ctx)
        return _run_check("image.verify", ["image", "digest", "key_id"], check)
    try:
        if a.cmd == "keygen":
            key = Ed25519PrivateKey.generate()
            fd = os.open(a.private, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with open(fd, "wb") as f:
                f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
            Path(a.public).write_bytes(key.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
            print(f"wrote {a.private} (keep secret, offline) and {a.public}")
        elif a.cmd == "manifest":
            manifest = build_manifest(a.dir, a.model, a.version)
            out = Path(a.out or Path(a.dir) / MANIFEST_NAME)
            out.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
            total = sum(e["size"] for e in manifest["files"])
            print(f"{out}: {a.model} {a.version}, {len(manifest['files'])} files, {total} bytes, sha256 {sha256(manifest)}")
        else:  # sign
            try:
                manifest = strict_json(Path(a.manifest).read_bytes(), "manifest")
            except VerifyError as e:
                raise SignError(str(e))
            env = sign(manifest, load_private_key(a.key, a.key_env, a.key_password_env), a.key_id)
            out = Path(a.out or a.manifest + ".sig")
            out.write_text(json.dumps(env, indent=2) + "\n")
            print(f"{out}: {manifest['model']} {manifest['version']} signed with {a.key_id}, sha256 {env['manifest_sha256']}")
    except (SignError, VerifyError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
