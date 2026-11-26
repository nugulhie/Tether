"""Interactive agents in the sandbox: how the orchestrator starts them (stdlib only, also used by infra/staging/50-e2e.py)."""

AGENTS = {"claude": ["claude"], "codex": ["codex"]}
# The policy grants /workspace and /tmp read-write, not the home directory, so agent state goes to /tmp.
AGENT_STATE = {"CLAUDE_CONFIG_DIR": "/tmp/.claude", "CODEX_HOME": "/tmp/.codex"}
# Codex refuses a CODEX_HOME that does not exist. The shell execs the agent, so the process that connects
# is still the agent binary itself (what the tether-llm profile admits), not sh.
PREPARE = 'mkdir -p "$CLAUDE_CONFIG_DIR" "$CODEX_HOME" && exec "$0" "$@"'


def agent_command(agent: str, gateway: str, policy_api: str = "") -> tuple[list[str], dict[str, str]]:
    """argv and non-secret environment for an interactive agent in the sandbox (image infra/sandbox-images/coding-agents).

    Both agents reach only the company LLM gateway. The bearer each one sends is an OpenShell placeholder
    (provider tether-llm: ANTHROPIC_AUTH_TOKEN, TETHER_LLM_TOKEN) that the proxy substitutes for the gateway
    host alone. Codex is pointed at it by command-line config, so no file in the image or home is needed."""
    agent_env = {"ANTHROPIC_BASE_URL": f"{gateway}/anthropic", "OPENAI_BASE_URL": f"{gateway}/openai/v1",
                 "TETHER_POLICY_API": policy_api, **AGENT_STATE}
    argv = list(AGENTS[agent])
    if agent == "codex":
        provider = "model_providers.tether"
        argv += ["-c", 'model_provider="tether"', "-c", f'{provider}.name="Tether LLM gateway"',
                 "-c", f'{provider}.base_url="{gateway}/openai/v1"', "-c", f'{provider}.env_key="TETHER_LLM_TOKEN"',
                 "-c", f'{provider}.wire_api="responses"']
    return ["sh", "-c", PREPARE, *argv], agent_env
