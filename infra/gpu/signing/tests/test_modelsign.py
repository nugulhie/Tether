import hashlib
import json
import os
import subprocess
import sys
import tracemalloc
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = Path(__file__).parents[1]
sys.path.insert(0, str(HERE))
import modelsign as ms  # noqa: E402

KEY = Ed25519PrivateKey.generate()
OTHER = Ed25519PrivateKey.generate()


def pem_private(k):
    return k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def pem_public(k):
    return k.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


@pytest.fixture
def keys(tmp_path):
    d = tmp_path / "keys"
    d.mkdir(mode=0o755)
    (d / "model-2026a.pub").write_bytes(pem_public(KEY))
    (d / "model-2025b.pub").write_bytes(pem_public(OTHER))
    for p in [d, *d.iterdir()]:
        p.chmod(0o755 if p.is_dir() else 0o644)
    return d


@pytest.fixture
def model(tmp_path):
    d = tmp_path / "qwen"
    (d / "tokenizer").mkdir(parents=True)
    (d / "config.json").write_text('{"architectures": ["Qwen3ForCausalLM"]}')
    (d / "model-00001-of-00002.safetensors").write_bytes(os.urandom(4096))
    (d / "model-00002-of-00002.safetensors").write_bytes(os.urandom(1000))
    (d / "tokenizer" / "tokenizer.json").write_text("{}")
    return d


def sign_dir(d, key=KEY, key_id="model-2026a", version="2026-11-01"):
    manifest = ms.build_manifest(d, "qwen3-32b", version)
    (d / ms.MANIFEST_NAME).write_text(json.dumps(manifest, indent=2))
    (d / ms.SIGNATURE_NAME).write_text(json.dumps(ms.sign(manifest, key, key_id)))
    return manifest


def run(argv, capsys):
    code = ms.main(argv)
    out = capsys.readouterr()
    lines = out.out.strip().splitlines()
    assert len(lines) == 1, out.out
    return code, json.loads(lines[0]), out.err


def verify_cli(model, keys, capsys, *extra):
    return run(["verify", "--dir", str(model), "--keys", str(keys), *extra], capsys)


def expect_fail(model, keys, reason, capsys, *extra):
    code, ev, err = verify_cli(model, keys, capsys, *extra)
    assert code == 1 and ev["result"] == "failure" and ev["reason"] == reason, ev
    assert ev["event"] == "model.verify" and "FAILED" in err
    return ev


# ---- happy path ----------------------------------------------------------------------------

def test_sign_then_verify_ok(model, keys, capsys):
    manifest = sign_dir(model)
    assert [e["path"] for e in manifest["files"]] == sorted(e["path"] for e in manifest["files"])
    assert "tokenizer/tokenizer.json" in {e["path"] for e in manifest["files"]}
    code, ev, _ = verify_cli(model, keys, capsys, "--expect-model", "qwen3-32b", "--expect-version", "2026-11-01")
    assert code == 0
    assert ev["event"] == "model.verify" and ev["result"] == "success" and ev["reason"] is None
    assert ev["model"] == "qwen3-32b" and ev["version"] == "2026-11-01" and ev["key_id"] == "model-2026a"
    assert ev["manifest_sha256"] == ms.sha256(manifest)


def test_cli_manifest_and_sign(model, keys, tmp_path, capsys, monkeypatch):
    priv = tmp_path / "signing.pem"
    priv.write_bytes(pem_private(KEY)); priv.chmod(0o600)
    assert ms.main(["manifest", str(model), "--model", "qwen3-32b", "--version", "v1"]) == 0
    assert ms.main(["sign", str(model / ms.MANIFEST_NAME), "--key", str(priv), "--key-id", "model-2026a"]) == 0
    capsys.readouterr()
    assert verify_cli(model, keys, capsys)[0] == 0
    # key from the environment; the key material is never printed
    monkeypatch.setenv("MODELSIGN_KEY", pem_private(KEY).decode())
    assert ms.main(["sign", str(model / ms.MANIFEST_NAME), "--key-env", "MODELSIGN_KEY", "--key-id", "model-2026a"]) == 0
    out = capsys.readouterr()
    body = pem_private(KEY).decode().splitlines()[1]
    assert body not in out.out and body not in out.err


def test_private_key_file_must_be_0600(model, tmp_path, capsys):
    priv = tmp_path / "signing.pem"
    priv.write_bytes(pem_private(KEY)); priv.chmod(0o644)
    sign_dir(model)
    assert ms.main(["sign", str(model / ms.MANIFEST_NAME), "--key", str(priv), "--key-id", "model-2026a"]) == 1
    err = capsys.readouterr().err
    assert "chmod 600" in err and pem_private(KEY).decode().splitlines()[1] not in err


def test_bad_key_error_does_not_echo_key(monkeypatch):
    monkeypatch.setenv("K", "-----BEGIN PRIVATE KEY-----\nc2VjcmV0LWJ5dGVz\n-----END PRIVATE KEY-----\n")
    with pytest.raises(ms.SignError) as e:
        ms.load_private_key(key_env="K")
    assert "c2VjcmV0" not in str(e.value)


# ---- tampering ---------------------------------------------------------------------------------

def test_tampered_byte(model, keys, capsys):
    sign_dir(model)
    p = model / "model-00001-of-00002.safetensors"
    data = bytearray(p.read_bytes()); data[100] ^= 1; p.write_bytes(bytes(data))
    ev = expect_fail(model, keys, "hash_mismatch", capsys)
    assert "model-00001" in ev["detail"]


def test_truncated_or_grown_file(model, keys, capsys):
    sign_dir(model)
    with open(model / "config.json", "ab") as f:
        f.write(b" ")
    expect_fail(model, keys, "size_mismatch", capsys)


@pytest.mark.parametrize("rel", ["extra.safetensors", "tokenizer/added.json", ".cache/huggingface/x"])
def test_added_file(model, keys, capsys, rel):
    sign_dir(model)
    (model / rel).parent.mkdir(parents=True, exist_ok=True)
    (model / rel).write_text("x")
    assert expect_fail(model, keys, "extra_file", capsys)["detail"] == rel


def test_removed_file(model, keys, capsys):
    sign_dir(model)
    (model / "tokenizer" / "tokenizer.json").unlink()
    expect_fail(model, keys, "missing_file", capsys)


@pytest.mark.parametrize("make", [
    lambda d, t: (d / "link.safetensors").symlink_to(t / "outside"),                   # escapes the dir
    lambda d, t: (d / "alias.json").symlink_to(d / "config.json"),                    # stays inside
    lambda d, t: (d / "tokenizer" / "tokenizer.json").unlink() or (d / "tokenizer" / "tokenizer.json").symlink_to(t / "outside"),
    lambda d, t: (d / "linked-dir").symlink_to(t / "outside-dir", target_is_directory=True),
])
def test_symlink_rejected(model, keys, tmp_path, capsys, make):
    (tmp_path / "outside").write_text("{}")
    (tmp_path / "outside-dir").mkdir()
    sign_dir(model)
    make(model, tmp_path)
    expect_fail(model, keys, "symlink", capsys)


def test_model_dir_itself_a_symlink(model, keys, tmp_path, capsys):
    sign_dir(model)
    link = tmp_path / "current"
    link.symlink_to(model, target_is_directory=True)
    expect_fail(link, keys, "symlink", capsys)


def test_manifest_refuses_symlinks_and_pickle(model, tmp_path):
    (model / "pytorch_model.bin").write_bytes(b"\x80\x04")
    with pytest.raises(ms.VerifyError, match="forbidden_format"):
        ms.build_manifest(model, "m", "v1")
    (model / "pytorch_model.bin").unlink()
    (model / "l").symlink_to(tmp_path)
    with pytest.raises(ms.VerifyError, match="symlink"):
        ms.build_manifest(model, "m", "v1")


def test_wrong_key(model, keys, capsys):
    # signed by another private key but claiming the trusted key id
    sign_dir(model, key=Ed25519PrivateKey.generate(), key_id="model-2026a")
    expect_fail(model, keys, "bad_signature", capsys)


def test_unknown_key_id(model, keys, capsys):
    sign_dir(model, key_id="attacker-1")
    assert expect_fail(model, keys, "unknown_key", capsys)["key_id"] == "attacker-1"


def test_revoked_key(model, keys, capsys):
    sign_dir(model, key=OTHER, key_id="model-2025b")
    assert verify_cli(model, keys, capsys)[0] == 0
    (keys / "model-2025b.pub").unlink()
    expect_fail(model, keys, "unknown_key", capsys)


@pytest.mark.parametrize("edit", [
    lambda m: m["files"][0].update(sha256="0" * 64),
    lambda m: m.update(version="2026-12-01"),
    lambda m: m["files"].pop(),
])
def test_manifest_edited_after_signing(model, keys, capsys, edit):
    sign_dir(model)
    mp = model / ms.MANIFEST_NAME
    m = json.loads(mp.read_text()); edit(m); mp.write_text(json.dumps(m))
    expect_fail(model, keys, "manifest_modified", capsys)
    # also updating the digest in the envelope does not help: the signature no longer verifies
    sp = model / ms.SIGNATURE_NAME
    env = json.loads(sp.read_text()); env["manifest_sha256"] = ms.sha256(m); sp.write_text(json.dumps(env))
    expect_fail(model, keys, "bad_signature", capsys)


def test_manifest_with_duplicate_keys_rejected(model, keys, capsys):
    sign_dir(model)
    mp = model / ms.MANIFEST_NAME
    mp.write_text(mp.read_text().replace('"format": 1,', '"format": 1, "format": 1,', 1))
    expect_fail(model, keys, "invalid_manifest", capsys)


def test_reformatting_manifest_is_harmless(model, keys, capsys):
    sign_dir(model)
    mp = model / ms.MANIFEST_NAME
    mp.write_text(json.dumps(json.loads(mp.read_text())))  # whitespace only; canonical bytes unchanged
    assert verify_cli(model, keys, capsys)[0] == 0


def test_expected_version_pins_against_rollback(model, keys, capsys):
    sign_dir(model, version="2026-10-01")  # an older, validly signed release
    expect_fail(model, keys, "unexpected_version", capsys, "--expect-version", "2026-11-01")
    expect_fail(model, keys, "unexpected_model", capsys, "--expect-model", "other")


def test_missing_signature_and_manifest(model, keys, capsys):
    sign_dir(model)
    (model / ms.SIGNATURE_NAME).unlink()
    expect_fail(model, keys, "missing_signature", capsys)
    (model / ms.MANIFEST_NAME).unlink()
    expect_fail(model, keys, "missing_manifest", capsys)


def test_key_store_problems(model, keys, tmp_path, capsys):
    sign_dir(model)
    expect_fail(model, tmp_path / "nope", "no_trusted_keys", capsys)
    empty = tmp_path / "empty"; empty.mkdir(mode=0o755)
    expect_fail(model, empty, "no_trusted_keys", capsys)
    (keys / "model-2026a.pub").chmod(0o666)
    expect_fail(model, keys, "untrusted_key_store", capsys)
    (keys / "model-2026a.pub").chmod(0o644)
    (keys / "Bad Id.pub").write_bytes(pem_public(KEY)); (keys / "Bad Id.pub").chmod(0o644)
    expect_fail(model, keys, "untrusted_key_store", capsys)


def test_unreadable_file_fails_closed(model, keys, capsys):
    if os.geteuid() == 0:
        pytest.skip("root reads everything")
    sign_dir(model)
    (model / "config.json").chmod(0)
    try:
        expect_fail(model, keys, "unreadable", capsys)
    finally:
        (model / "config.json").chmod(0o644)


# ---- large files ---------------------------------------------------------------------------------

def test_large_file_is_streamed(model, keys, capsys, monkeypatch):
    """A sparse 64 MiB shard hashed in 1 MiB chunks: correct digest, bounded memory, tamper detected."""
    monkeypatch.setattr(ms, "CHUNK", 1024 * 1024)
    size = 64 * 1024 * 1024
    big = model / "model-big.safetensors"
    with open(big, "wb") as f:
        f.truncate(size - 4)
        f.seek(size - 4); f.write(b"tail")
    expected = hashlib.sha256()
    expected.update(bytes(size - 4)); expected.update(b"tail")

    tracemalloc.start()
    digest, n = ms.hash_file(big)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert (digest, n) == (expected.hexdigest(), size)
    assert peak < 4 * 1024 * 1024  # never the whole file

    sign_dir(model)
    assert verify_cli(model, keys, capsys)[0] == 0
    with open(big, "r+b") as f:
        f.seek(size - 1); f.write(b"!")
    expect_fail(model, keys, "hash_mismatch", capsys)


# ---- images (cosign mocked) ------------------------------------------------------------------------

DIGEST = "sha256:" + "ab" * 32
IMAGE = f"registry.company.internal:5000/gpu/vllm@{DIGEST}"


@pytest.fixture
def image_keys(tmp_path):
    d = tmp_path / "image-keys"; d.mkdir(mode=0o755)
    for kid in ("image-2025b", "image-2026a"):
        (d / f"{kid}.pub").write_text("cosign public key"); (d / f"{kid}.pub").chmod(0o644)
    return d


class FakeCosign:
    def __init__(self, ok_keys=(), exc=None):
        self.ok_keys, self.exc, self.calls = set(ok_keys), exc, []

    def __call__(self, cmd, **kw):
        self.calls.append(cmd)
        if self.exc:
            raise self.exc
        ok = Path(cmd[cmd.index("--key") + 1]).stem in self.ok_keys
        return subprocess.CompletedProcess(cmd, 0 if ok else 1, "[]" if ok else "", "" if ok else "Error: no matching signatures")


def image_cli(capsys, image, keys):
    return run(["verify-image", "--image", image, "--keys", str(keys), "--cosign", "/usr/local/bin/cosign"], capsys)


def test_image_verified_by_current_key(monkeypatch, image_keys, capsys):
    fake = FakeCosign(ok_keys={"image-2026a"})
    monkeypatch.setattr(ms.subprocess, "run", fake)
    code, ev, _ = image_cli(capsys, IMAGE, image_keys)
    assert code == 0 and ev["event"] == "image.verify" and ev["result"] == "success"
    assert ev["key_id"] == "image-2026a" and ev["digest"] == DIGEST and ev["image"] == IMAGE
    cmd = fake.calls[-1]
    assert cmd[:2] == ["/usr/local/bin/cosign", "verify"] and cmd[-1] == IMAGE
    assert "--insecure-ignore-tlog=true" in cmd and str(image_keys / "image-2026a.pub") in cmd


@pytest.mark.parametrize("image", [
    "registry.company.internal/gpu/vllm:v0.11.0",
    "registry.company.internal/gpu/vllm:latest@" + DIGEST,
    "registry.company.internal/gpu/vllm@sha256:short",
    "vllm",
])
def test_image_tags_refused_without_calling_cosign(monkeypatch, image_keys, capsys, image):
    fake = FakeCosign(ok_keys={"image-2026a"})
    monkeypatch.setattr(ms.subprocess, "run", fake)
    code, ev, _ = image_cli(capsys, image, image_keys)
    assert code == 1 and ev["reason"] == "image_not_pinned" and fake.calls == []


def test_image_unsigned(monkeypatch, image_keys, capsys):
    fake = FakeCosign()
    monkeypatch.setattr(ms.subprocess, "run", fake)
    code, ev, _ = image_cli(capsys, IMAGE, image_keys)
    assert code == 1 and ev["reason"] == "bad_signature" and len(fake.calls) == 2


@pytest.mark.parametrize("exc,reason", [
    (FileNotFoundError(), "cosign_unavailable"),
    (subprocess.TimeoutExpired("cosign", 1), "cosign_unavailable"),
])
def test_cosign_problems_fail_closed(monkeypatch, image_keys, capsys, exc, reason):
    monkeypatch.setattr(ms.subprocess, "run", FakeCosign(exc=exc))
    code, ev, _ = image_cli(capsys, IMAGE, image_keys)
    assert code == 1 and ev["reason"] == reason


def test_image_no_keys(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(ms.subprocess, "run", FakeCosign(ok_keys={"x"}))
    d = tmp_path / "k"; d.mkdir(mode=0o755)
    assert image_cli(capsys, IMAGE, d)[1]["reason"] == "no_trusted_keys"


def test_real_subprocess_with_fake_cosign_binary(tmp_path, image_keys, capsys):
    fake = tmp_path / "cosign"
    fake.write_text('#!/bin/sh\necho "$@" > "$(dirname "$0")/args"\nexit 0\n'); fake.chmod(0o755)
    code, ev, _ = run(["verify-image", "--image", IMAGE, "--keys", str(image_keys), "--cosign", str(fake)], capsys)
    assert code == 0 and ev["key_id"] == "image-2025b"
    assert (tmp_path / "args").read_text().split()[-1] == IMAGE


# ---- deployment files --------------------------------------------------------------------------

def test_systemd_dropin_fails_closed():
    text = (HERE / "systemd/gpu-inference.service.d/10-verify-signatures.conf").read_text()
    pre = [l.split("=", 1)[1] for l in text.splitlines() if l.startswith("ExecStartPre=")]
    assert len(pre) == 2 and not any(p.startswith(("-", "+", "!")) for p in pre)  # "-" would ignore failure
    assert "verify-image" in pre[0] and "--image ${SERVING_IMAGE}" in pre[0]
    assert " verify " in pre[1] and "--expect-version ${MODEL_VERSION}" in pre[1]
    assert "EnvironmentFile=/" in text  # without "-": a missing env file stops the unit


def test_k8s_policies_require_digest_and_signature():
    cip = (HERE / "k8s/cluster-image-policy.yaml").read_text()
    assert "kind: ClusterImagePolicy" in cip and "mode: enforce" in cip and 'glob: "**"' in cip
    vap = (HERE / "k8s/require-digest.yaml").read_text()
    assert "failurePolicy: Fail" in vap and "Deny" in vap and "@sha256:[a-f0-9]{64}" in vap
