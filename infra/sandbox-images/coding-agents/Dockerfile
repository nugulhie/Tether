# Sandbox image for interactive agents on external models: Claude Code and Codex (ADR 0002, P2).
# Build from the repository root:
#   docker build -f infra/sandbox-images/coding-agents/Dockerfile -t tether/sandbox-coding-agents:0.1.0 .
#
# Both agents are native executables. They are copied out of their npm packages to /usr/local/libexec/tether as
# real files, because OpenShell admits a connection by the real path of the connecting executable (or an
# ancestor): the tether-llm profile and the policy's agent_binaries name /usr/local/libexec/tether/{claude,codex}.
# /usr/local/bin/{claude,codex} are symlinks for PATH only and never match. Under /usr, not /opt: the compiled
# policy's Landlock rules grant /usr read-only (execute included) and nothing under /opt.
#
# No model endpoint or key is in the image. The orchestrator sets ANTHROPIC_BASE_URL and Codex's provider
# to the company LLM gateway; the bearer is an OpenShell placeholder substituted for the gateway host only.
# Pinned versions: bump CLAUDE_CODE_VERSION / CODEX_VERSION deliberately, rebuild, and re-pin the digest.

ARG NODE=node:22-bookworm-slim@sha256:be979e5523c76fa4d5ca4ebd3099078f220aa47ec39c48ad5b5df9314debd6eb

FROM ${NODE} AS build
ARG CLAUDE_CODE_VERSION=2.1.332
ARG CODEX_VERSION=0.172.0
RUN npm install -g --no-fund --no-audit @anthropic-ai/claude-code@${CLAUDE_CODE_VERSION} @openai/codex@${CODEX_VERSION} \
 && mkdir -p /out \
 && install -m 0755 /usr/local/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe /out/claude \
 && install -m 0755 "$(find /usr/local/lib/node_modules/@openai -type f -path '*/vendor/*/bin/codex' | head -1)" /out/codex \
 && /out/claude --version && /out/codex --version

FROM ${NODE}
# git: clone and commit; ripgrep: both agents search with rg; ca-certificates: the sandbox proxy's CA.
# node stays at /usr/local/bin/node (repositories' own tooling); no compiler toolchain is installed.
# The base image's "node" account (uid 1000) is removed so the only unprivileged account is sandbox.
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates ripgrep \
 && apt-get clean && find /var/lib/apt/lists -type f -delete \
 && userdel node \
 && groupadd --gid 10001 sandbox && useradd --uid 10001 --gid sandbox --create-home --shell /bin/sh sandbox \
 && mkdir -p /workspace && chown sandbox:sandbox /workspace
COPY --from=build --chown=root:root --chmod=0755 /out/claude /out/codex /usr/local/libexec/tether/
# The directory first: COPY --chmod would also apply 0644 to a parent it creates, and sandbox could not enter it.
RUN ln -s /usr/local/libexec/tether/claude /usr/local/bin/claude && ln -s /usr/local/libexec/tether/codex /usr/local/bin/codex \
 && install -d -m 0755 /etc/claude-code
# Claude Code's managed settings: no auto-update, no non-essential traffic. No allowedProviders: Claude Code
# then demands the endpoint pinned in the same file, which would tie the image to one install's gateway URL.
# The pin is not needed here: the sandbox network policy admits no model host but the gateway, and the
# gateway holds the only keys (the MDM profile for laptops, infra/mdm, is where allowedProviders belongs).
COPY --chown=root:root --chmod=0644 infra/sandbox-images/coding-agents/managed-settings.json /etc/claude-code/managed-settings.json
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt NODE_EXTRA_CA_CERTS=/etc/ssl/certs/ca-certificates.crt
USER sandbox
# Must stay /workspace: OpenShell's Docker driver makes the image WORKDIR the workspace (see local-agent).
WORKDIR /workspace
