# Laptop control (MDM)

Needs no Apple entitlements and no Apple Developer account. It deters personal use of Claude Code on laptops. A local administrator can remove it, so the platform's guarantees do not rely on it; see `docs/threat-model.md`.

`make mdm` reads `config.yaml` and writes `out/`:

| File | Deploy to | Effect |
|---|---|---|
| `claude-code.mobileconfig` | MDM (device channel), preference domain `com.anthropic.claudecode` | Claude Code accepts only the company LLM gateway (`allowedProviders: ["customEndpoint"]` plus a managed `ANTHROPIC_BASE_URL`). The gateway serves sandbox egress only, so on a laptop Claude Code cannot reach any model, personal claude.ai login included. Needs Claude Code ≥ 2.1.285. |
| `managed-settings.json` | `/Library/Application Support/ClaudeCode/managed-settings.json` (root-owned) | Same as above, for MDMs that deploy files instead of profiles. The profile takes precedence when both exist. |
| `sandbox/managed-settings.json` | Sandbox image: `/etc/claude-code/managed-settings.json` | Pins Claude Code inside sandboxes to the same gateway. |

**Verify on a pilot Mac:** `/status` in Claude Code names the plist source, and a session started on the laptop fails against the gateway.

## What this does not cover
- Other AI tools (Codex, IDE assistants, browsers), which do not read Claude Code settings.
- A local administrator deleting the profile or the file.

Laptops keep GitHub access (remote work), so code on laptops can reach personal AI tools. This is an accepted residual risk; see `docs/threat-model.md`.
