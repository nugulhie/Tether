# Local-agent sandbox image

Image for OpenShell sandboxes that run administrator-approved local-LLM jobs (ADR 0001, D1). It holds the agent from `local-agent/` and git. Repositories' own tests can use the base image's Python. It has no compiler toolchain.

```bash
docker build -f infra/sandbox-images/local-agent/Dockerfile -t tether/sandbox-local-agent:0.1.0 .   # from the repo root
```

- **Agent:** `/usr/local/bin/tether-agent` is a self-contained PyInstaller executable, built in a separate stage. The process that calls the LLM gateway is therefore that file, not `python3.13`. The policy's `agent_binaries` and the `tether-llm` profile's `binaries` must both list this path.
- **User:** non-root `sandbox` (uid/gid 10001), the identity the policy compiler sets as `run_as_user`. `/workspace` belongs to it.
- **Pins:**
  - the base image, by tag and digest (`ARG BASE`);
  - the build dependencies (httpx and PyInstaller), hash-locked in `requirements.txt`. Its header shows how to regenerate it.
- **Network:** the agent trusts the system CA store (`SSL_CERT_FILE`), because the OpenShell proxy terminates TLS to enforce L7 rules and to swap the `TETHER_LLM_TOKEN` placeholder for the session token.
- **Platform:** the build is for the builder's architecture. Use `--platform linux/amd64` for x86 gateways.

The build stage runs the executable once and expects exit code 2 (configuration error), as a smoke test. The orchestrator invokes the agent as described in `services/sandbox-orchestrator/README.md`.
