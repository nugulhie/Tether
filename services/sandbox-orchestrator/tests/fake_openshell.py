#!/usr/bin/env python3
"""Stand-in for the OpenShell CLI: records calls (argv + credential env) and keeps sandbox state on disk."""
import json, os, sys
state, log = os.environ["FAKE_STATE"], os.environ["FAKE_LOG"]
argv = sys.argv[1:]
secret_env = {k: os.environ[k] for k in ("ANTHROPIC_AUTH_TOKEN", "TETHER_LLM_TOKEN", "TETHER_SESSION_TOKEN", "GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY") if k in os.environ}
# Non-interactive execs get stdin (the orchestrator passes data or /dev/null, never its own stdin).
stdin = sys.stdin.read() if argv[:2] == ["sandbox", "exec"] and "--no-tty" in argv else None
with open(log, "a") as f:
    f.write(json.dumps({"argv": argv, "env": secret_env, **({"stdin": stdin} if stdin else {})}) + "\n")
mark = lambda kind, name: os.path.join(state, f"{kind}-{name}")
sandbox_file = lambda name, path: mark("file", name + path.replace("/", "_"))
cmd = argv[:2]
if cmd in (["sandbox", "get"], ["provider", "get"]):
    sys.exit(0 if os.path.exists(mark(argv[0], argv[2])) else 1)
if cmd in (["provider", "create"], ["sandbox", "create"]):
    open(mark(argv[0], argv[argv.index("--name") + 1]), "w").close(); sys.exit(0)
if cmd == ["provider", "update"]:
    sys.exit(0)
if cmd == ["policy", "set"]:
    sys.exit(int(os.environ.get("FAKE_POLICY_RC", "0")))
if cmd == ["sandbox", "delete"]:
    for n in argv[2:]:
        if os.path.exists(mark("sandbox", n)): os.remove(mark("sandbox", n))
    sys.exit(0)
if cmd == ["sandbox", "exec"]:
    cmdline = argv[argv.index("--") + 1:]
    if cmdline[:2] == ["git", "clone"]:
        sys.exit(int(os.environ.get("FAKE_CLONE_RC", "0")))
    name = argv[argv.index("-n") + 1]
    if cmdline[:2] == ["sh", "-c"] and "cat >" in cmdline[2]:  # OpenShell.write_file: sh -c SCRIPT sh PATH
        if os.environ.get("FAKE_WRITE_RC"):
            sys.exit(int(os.environ["FAKE_WRITE_RC"]))
        with open(sandbox_file(name, cmdline[4]), "w") as f:
            f.write(stdin)
        sys.exit(0)
    if cmdline[:2] == ["sh", "-c"] and "git" in cmdline[2] and "diff" in cmdline[2]:  # job result: workspace patch
        sys.stdout.write(os.environ.get("FAKE_DIFF", ""))
        sys.exit(int(os.environ.get("FAKE_DIFF_RC", "0")))
    if "--no-tty" in argv:  # a non-interactive local agent run
        import time
        envs = dict(argv[i + 1].split("=", 1) for i, a in enumerate(argv) if a == "--env")
        if "TETHER_TASK_FILE" in envs and not os.path.exists(sandbox_file(name, envs["TETHER_TASK_FILE"])):
            sys.exit(66)  # like the real agent: no task file, no run
        sys.stdout.write(os.environ.get("FAKE_AGENT_OUTPUT", "")); sys.stdout.flush()
        sys.stderr.write(os.environ.get("FAKE_AGENT_LOG", "")); sys.stderr.flush()
        time.sleep(float(os.environ.get("FAKE_AGENT_SLEEP", "0")))
        sys.exit(int(os.environ.get("FAKE_AGENT_RC", "0")))
    envs = dict(a.split("=", 1) for a in argv[argv.index("--tty"):argv.index("--")] if "=" in a)
    cols, rows = os.get_terminal_size(0)
    print(f"agent={cmdline[0]} tty={os.isatty(0)} size={cols}x{rows} base={envs.get('ANTHROPIC_BASE_URL')}", flush=True)
    line = sys.stdin.readline().strip()
    print(f"got:{line}", flush=True)
    sys.exit(3)
sys.exit(2)
