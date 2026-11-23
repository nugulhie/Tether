"""Non-interactive tool-calling loop against the company LLM gateway's `local` provider.

The orchestrator runs this inside the job's OpenShell sandbox with cwd = the cloned repository and:
  OPENAI_BASE_URL          <llm-gateway>/local/v1 (OpenAI-compatible chat/completions)
  COMPANY_AGENT_MODEL      model id (the policy's llm.local.models must allow it)
  COMPANY_AGENT_TASK_FILE  file holding the approved task (COMPANY_AGENT_TASK is a fallback)
  COMPANY_AGENT_JOB        job id, for logs
  COMPANY_LLM_TOKEN        an OpenShell placeholder from the `company-llm` provider. The sandbox
                           proxy swaps in the session token only on requests to the gateway host,
                           so the real token never exists in this process.

Exit codes: 0 the model called finish; 2 configuration error; 3 step limit reached;
4 refused by the gateway (403 guardrail block / policy, 401); 5 gateway unavailable (503:
guardrail or audit-store outage, fail-closed); 6 any other failure.
Logs are JSON lines on stderr with tool names and sizes only; the gateway audits content.
"""
import json
import os
import ssl
import sys
import time

import httpx

from .tools import SCHEMAS, ToolError, Tools, truncate

EXIT_OK, EXIT_CONFIG, EXIT_STEPS, EXIT_REFUSED, EXIT_UNAVAILABLE, EXIT_ERROR = 0, 2, 3, 4, 5, 6
MAX_TASK_BYTES = 256 * 1024
RETRY_STATUSES = (429, 502, 504)  # transient; 403 and 503 are verdicts and never retried
MAX_RETRIES = 3

SYSTEM_PROMPT = """You are an autonomous software engineering agent running a pre-approved task, non-interactively, \
in a sandbox. Nobody will answer questions. Your working directory is the root of a git repository.
Use the tools to inspect and change the repository and to run commands. Paths are relative to the repository root and \
cannot leave it. Shell commands have no terminal and no stdin, and are time-limited.
Network access is limited by the sandbox policy; a refused connection is not a bug to work around.
When the task is complete (or cannot be completed), call `finish` once with a short summary."""


class ConfigError(Exception):
    pass


class Stop(Exception):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code


def log(event: str, **fields):
    print(json.dumps({"ts": round(time.time(), 3), "event": event, **fields}, separators=(",", ":")), file=sys.stderr, flush=True)


def bounded(environ, name: str, default, lo, hi, cast=int):
    raw = environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = cast(raw)
    except ValueError:
        raise ConfigError(f"{name} must be a number, got {raw!r}")
    if not lo <= value <= hi:
        raise ConfigError(f"{name} must be between {lo} and {hi}, got {value}")
    return value


def load_config(environ) -> dict:
    base = environ.get("OPENAI_BASE_URL", "").strip().rstrip("/")
    model = environ.get("COMPANY_AGENT_MODEL", "").strip()
    token = environ.get("COMPANY_LLM_TOKEN", "").strip()
    if not base:
        raise ConfigError("OPENAI_BASE_URL is not set")
    if not model:
        raise ConfigError("COMPANY_AGENT_MODEL is not set")
    if not token:
        raise ConfigError("COMPANY_LLM_TOKEN is not set: the sandbox has no company-llm provider attached")
    task_file = environ.get("COMPANY_AGENT_TASK_FILE", "").strip()
    if task_file:
        try:
            with open(task_file, "rb") as f:
                raw = f.read(MAX_TASK_BYTES + 1)
        except OSError as e:
            raise ConfigError(f"cannot read COMPANY_AGENT_TASK_FILE: {e.strerror}")
        if len(raw) > MAX_TASK_BYTES:
            raise ConfigError(f"task file exceeds {MAX_TASK_BYTES} bytes")
        task = raw.decode("utf-8", errors="replace").strip()
    else:
        task = environ.get("COMPANY_AGENT_TASK", "").strip()
    if not task:
        raise ConfigError("no task: set COMPANY_AGENT_TASK_FILE (or COMPANY_AGENT_TASK)")
    return {
        "url": f"{base}/chat/completions", "model": model, "token": token, "task": task, "job": environ.get("COMPANY_AGENT_JOB", ""),
        "max_steps": bounded(environ, "COMPANY_AGENT_MAX_STEPS", 40, 1, 500),
        "max_output": bounded(environ, "COMPANY_AGENT_MAX_OUTPUT_BYTES", 32 * 1024, 1024, 1024 * 1024),
        "shell_timeout": bounded(environ, "COMPANY_AGENT_SHELL_TIMEOUT", 300.0, 1, 3600, float),
        "http_timeout": bounded(environ, "COMPANY_AGENT_HTTP_TIMEOUT", 600.0, 5, 3600, float),
    }


def error_message(r: httpx.Response) -> str:
    try:
        body = r.json()
    except ValueError:
        return r.text[:300]
    err = body.get("error") if isinstance(body, dict) else None
    if isinstance(err, dict) and err.get("message"):
        return str(err["message"])[:300]
    if isinstance(body, dict) and body.get("detail"):
        return str(body["detail"])[:300]
    return r.text[:300]


def complete(client: httpx.Client, cfg: dict, messages: list, sleep) -> dict:
    body = {"model": cfg["model"], "messages": messages, "tools": SCHEMAS, "tool_choice": "auto"}
    headers = {"Authorization": f"Bearer {cfg['token']}"}
    for attempt in range(MAX_RETRIES + 1):
        try:
            r = client.post(cfg["url"], json=body, headers=headers)
        except httpx.TransportError as e:
            if attempt == MAX_RETRIES:
                raise Stop(EXIT_ERROR, f"cannot reach the LLM gateway: {type(e).__name__}")
            log("retry", reason=type(e).__name__, attempt=attempt + 1)
            sleep(min(2 ** attempt, 30))
            continue
        if r.status_code == 200:
            try:
                return r.json()["choices"][0]["message"]
            except (ValueError, KeyError, IndexError, TypeError):
                raise Stop(EXIT_ERROR, "the LLM gateway returned a response without choices[0].message")
        if r.status_code == 403:
            raise Stop(EXIT_REFUSED, f"refused by the LLM gateway (403, guardrail or policy): {error_message(r)}")
        if r.status_code == 401:
            raise Stop(EXIT_REFUSED, f"the LLM gateway rejected the session (401): {error_message(r)}")
        if r.status_code == 503:
            raise Stop(EXIT_UNAVAILABLE, f"the LLM gateway refused to serve (503, guardrail or audit store unavailable): {error_message(r)}")
        if r.status_code in RETRY_STATUSES and attempt < MAX_RETRIES:
            try:
                wait = float(r.headers.get("retry-after", ""))
            except ValueError:
                wait = 2 ** attempt
            log("retry", status=r.status_code, attempt=attempt + 1)
            sleep(min(max(wait, 0), 30))
            continue
        raise Stop(EXIT_ERROR, f"LLM gateway error {r.status_code}: {error_message(r)}")
    raise AssertionError("unreachable")


def loop(cfg: dict, tools: Tools, client: httpx.Client, sleep) -> int:
    messages = [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": cfg["task"]}]
    for step in range(1, cfg["max_steps"] + 1):
        msg = complete(client, cfg, messages, sleep)
        calls = msg.get("tool_calls") or []
        log("step", step=step, tools=[(c.get("function") or {}).get("name") for c in calls])
        assistant = {"role": "assistant", "content": msg.get("content")}
        if calls:
            assistant["tool_calls"] = calls
        messages.append(assistant)
        if not calls:
            messages.append({"role": "user", "content": "Continue using the tools. Call `finish` when the task is complete."})
            continue
        for c in calls:
            fn = c.get("function") or {}
            name, call_id = fn.get("name"), c.get("id", "")
            if name == "finish":
                try:
                    args = json.loads(fn.get("arguments") or "{}")
                    summary = args.get("summary") if isinstance(args, dict) else None
                except json.JSONDecodeError:
                    summary = None
                if isinstance(summary, str):
                    log("finish", step=step, summary_bytes=len(summary.encode()))
                    print(summary)
                    return EXIT_OK
                result, ok = "error: finish needs a string `summary`", False
            else:
                started = time.monotonic()
                try:
                    result, ok = tools.call(name, fn.get("arguments")), True
                except ToolError as e:
                    result, ok = f"error: {e}", False
                except OSError as e:
                    result, ok = f"error: {e.strerror or e}", False
                log("tool", step=step, tool=name, ok=ok, output_bytes=len(result.encode()), seconds=round(time.monotonic() - started, 3))
            messages.append({"role": "tool", "tool_call_id": call_id, "content": truncate(result, cfg["max_output"])})
    raise Stop(EXIT_STEPS, f"step limit reached ({cfg['max_steps']}) without finish")


SYSTEM_CA_BUNDLE = "/etc/ssl/certs/ca-certificates.crt"


def tls_verify(environ):
    """The sandbox proxy terminates TLS to enforce L7 rules and inject credentials; its CA is trusted
    through the system store (or SSL_CERT_FILE), not certifi's bundle that httpx uses by default."""
    cafile = environ.get("SSL_CERT_FILE") or (SYSTEM_CA_BUNDLE if os.path.exists(SYSTEM_CA_BUNDLE) else None)
    try:
        return ssl.create_default_context(cafile=cafile) if cafile else True
    except (OSError, ssl.SSLError) as e:
        raise ConfigError(f"cannot load CA bundle {cafile}: {e}")


def main(environ=None, transport: httpx.BaseTransport | None = None, sleep=time.sleep, workdir: str | None = None) -> int:
    environ = os.environ if environ is None else environ
    try:
        cfg = load_config(environ)
        verify = tls_verify(environ)
    except ConfigError as e:
        log("error", reason="config", message=str(e))
        print(f"company-local-agent: {e}", file=sys.stderr)
        return EXIT_CONFIG
    tools = Tools(workdir or os.getcwd(), cfg["max_output"], cfg["shell_timeout"])
    log("start", job=cfg["job"], model=cfg["model"], max_steps=cfg["max_steps"])
    try:
        with httpx.Client(timeout=cfg["http_timeout"], transport=transport, verify=verify, follow_redirects=False) as client:
            return loop(cfg, tools, client, sleep)
    except Stop as e:
        log("error", reason="exit", code=e.code, message=str(e))
        print(f"company-local-agent: {e}", file=sys.stderr)
        return e.code


def run():
    sys.exit(main())
