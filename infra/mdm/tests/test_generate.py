import json
import plistlib
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).parents[1]))
import generate as g  # noqa: E402

CFG = yaml.safe_load((Path(__file__).parents[1] / "config.yaml").read_text())
EXPECTED = {"allowedProviders": ["customEndpoint"], "env": {"ANTHROPIC_BASE_URL": "https://llm-gateway.company.internal/anthropic"}}


@pytest.fixture
def out(tmp_path):
    g.generate(CFG, tmp_path)
    return tmp_path


def test_outputs(out):
    assert sorted(p.relative_to(out).as_posix() for p in out.rglob("*") if p.is_file()) == [
        "claude-code.mobileconfig", "managed-settings.json", "sandbox/managed-settings.json"]


def test_claude_code_pinned_to_gateway(out):
    assert json.loads((out / "managed-settings.json").read_text()) == EXPECTED
    assert json.loads((out / "sandbox/managed-settings.json").read_text()) == EXPECTED
    p = plistlib.loads((out / "claude-code.mobileconfig").read_bytes())
    assert p["PayloadType"] == "Configuration" and p["PayloadRemovalDisallowed"] is True and p["PayloadScope"] == "System"
    payload = p["PayloadContent"][0]
    assert payload["PayloadType"] == "com.anthropic.claudecode"
    assert payload["allowedProviders"] == ["customEndpoint"] and payload["env"] == EXPECTED["env"]


def test_profile_is_reproducible(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    g.generate(CFG, a); g.generate(CFG, b)
    assert (a / "claude-code.mobileconfig").read_bytes() == (b / "claude-code.mobileconfig").read_bytes()
    p = plistlib.loads((a / "claude-code.mobileconfig").read_bytes())
    assert p["PayloadUUID"] != p["PayloadContent"][0]["PayloadUUID"]


@pytest.mark.parametrize("url", ["http://llm.company.internal", "llm.company.internal", ""])
def test_gateway_must_be_https(tmp_path, url):
    with pytest.raises(g.ConfigError):
        g.generate({**CFG, "llm_gateway_url": url}, tmp_path)
