#!/usr/bin/env python3
"""Generate Claude Code managed settings for laptops (MDM profile and file) and for the sandbox
image from infra/mdm/config.yaml.

  python generate.py [--config config.yaml] [--out out]
"""
import argparse
import json
import plistlib
import uuid
from pathlib import Path
from urllib.parse import urlsplit

import yaml

HERE = Path(__file__).parent


class ConfigError(ValueError):
    pass


def https_url(value, field):
    u = urlsplit(value or "")
    if u.scheme != "https" or not u.hostname:
        raise ConfigError(f"{field} must be an https:// URL: {value!r}")
    return value.rstrip("/")


def claude_code_settings(gateway):
    # Claude Code accepts only this gateway (v2.1.285+): with ANTHROPIC_BASE_URL in managed env
    # and allowedProviders = customEndpoint, it refuses Anthropic directly, other URLs, Bedrock,
    # Vertex and Foundry. Personal claude.ai logins and API keys therefore have nowhere to go.
    return {"allowedProviders": ["customEndpoint"], "env": {"ANTHROPIC_BASE_URL": f"{gateway}/anthropic"}}


def payload_uuid(prefix, name):
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{prefix}.{name}")).upper()


def claude_code_profile(cfg):
    prefix, name = cfg["profile_prefix"], "claudecode"
    payload = {"PayloadType": "com.anthropic.claudecode", "PayloadDisplayName": "Claude Code managed settings",
               "PayloadIdentifier": f"{prefix}.{name}.0", "PayloadUUID": payload_uuid(prefix, f"{name}.0"), "PayloadVersion": 1,
               **claude_code_settings(https_url(cfg["llm_gateway_url"], "llm_gateway_url"))}
    return {
        "PayloadDisplayName": "Claude Code (company gateway only)",
        "PayloadDescription": "Pins Claude Code to the company LLM gateway, which serves managed sandboxes only.",
        "PayloadIdentifier": f"{prefix}.{name}", "PayloadOrganization": cfg["organization"], "PayloadType": "Configuration",
        "PayloadUUID": payload_uuid(prefix, name), "PayloadVersion": 1, "PayloadScope": "System",
        # Users cannot remove MDM-installed profiles; local administrators can still tamper with the
        # machine, which the platform does not rely on (see docs/threat-model.md).
        "PayloadRemovalDisallowed": True,
        "PayloadContent": [payload],
    }


def generate(cfg, out: Path):
    out.mkdir(parents=True, exist_ok=True)
    (out / "sandbox").mkdir(exist_ok=True)
    gateway = https_url(cfg["llm_gateway_url"], "llm_gateway_url")
    settings = json.dumps(claude_code_settings(gateway), indent=2).encode() + b"\n"
    files = {
        "claude-code.mobileconfig": plistlib.dumps(claude_code_profile(cfg)),
        # File-based alternative for laptops: /Library/Application Support/ClaudeCode/managed-settings.json
        "managed-settings.json": settings,
        # Sandbox image: /etc/claude-code/managed-settings.json (Linux path).
        "sandbox/managed-settings.json": settings,
    }
    for name, data in files.items():
        (out / name).write_bytes(data)
    return sorted(files)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=str(HERE / "config.yaml"))
    ap.add_argument("--out", default=str(HERE / "out"))
    a = ap.parse_args(argv)
    cfg = yaml.safe_load(Path(a.config).read_text())
    for name in generate(cfg, Path(a.out)):
        print(Path(a.out) / name)


if __name__ == "__main__":
    main()
