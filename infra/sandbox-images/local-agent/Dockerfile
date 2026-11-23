# Sandbox image for local-LLM agent jobs (ADR 0001, D1). Build from the repository root:
#   docker build -f infra/sandbox-images/local-agent/Dockerfile -t company/sandbox-local-agent:0.1.0 .
#
# The agent is a self-contained executable (PyInstaller) at /usr/local/bin/company-local-agent, so the
# process that talks to the LLM gateway *is* that file, not a Python interpreter. That is the path the
# policy's agent_binaries and the company-llm profile's binaries name; a pip console script would be a
# shim whose running executable is /usr/local/bin/python3.13.

ARG BASE=python:3.13.18-slim-bookworm@sha256:a5a7017efc5969e00ae2b91c8eb0631049a569652aa4ffc4501769049ae45c72

FROM ${BASE} AS build
# binutils: PyInstaller needs objdump to collect shared libraries. Build stage only.
RUN apt-get update && apt-get install -y --no-install-recommends binutils && rm -rf /var/lib/apt/lists/*
COPY infra/sandbox-images/local-agent/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --require-hashes --only-binary=:all: -r /tmp/requirements.txt
COPY local-agent/company_local_agent /src/company_local_agent
RUN cd /src && pyinstaller --noconfirm --clean --onefile --name company-local-agent --paths /src \
        --distpath /out --workpath /tmp/pyi --specpath /tmp/pyi company_local_agent/__main__.py \
 && /out/company-local-agent; test $? -eq 2  # starts and refuses: no configuration

FROM ${BASE}
# git for clone/commit/push (github-org provider); ca-certificates for the sandbox proxy's CA.
# Python stays (repositories' own tests); no compiler toolchain is installed.
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --gid 10001 sandbox && useradd --uid 10001 --gid sandbox --create-home --shell /bin/sh sandbox \
 && mkdir -p /workspace && chown sandbox:sandbox /workspace
COPY --from=build --chown=root:root --chmod=0755 /out/company-local-agent /usr/local/bin/company-local-agent
# The proxy's CA is trusted via the system store; the agent also honors SSL_CERT_FILE.
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
USER sandbox
WORKDIR /workspace
