"""Thin async wrapper around the OpenShell CLI, run with the orchestrator's own gateway identity.

The orchestrator is the only holder of gateway credentials (OPENSHELL_GATEWAY / mTLS / OIDC
client credentials in its environment). OpenShell has no per-sandbox ACL, so developers are
never given gateway access: anyone who can exec into a sandbox can also create one.
Secret values are passed through the child environment (`--credential KEY`), never argv.
"""
import asyncio
import os


class OpenShellError(RuntimeError):
    pass


class OpenShell:
    def __init__(self, binary: str = "openshell"):
        self.binary = binary

    async def run(self, *args: str, env: dict | None = None, check: bool = True) -> tuple[int, str, str]:
        try:
            proc = await asyncio.create_subprocess_exec(self.binary, *args, env={**os.environ, **(env or {})},
                                                        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        except OSError as e:
            raise OpenShellError(f"cannot run {self.binary}: {e}")
        try:
            out, err = await proc.communicate()
        except asyncio.CancelledError:
            # e.g. a job run hit its runtime limit: do not leave the CLI process behind.
            proc.kill()
            await proc.wait()
            raise
        if check and proc.returncode != 0:
            raise OpenShellError(f"openshell {' '.join(args[:2])} failed ({proc.returncode}): {err.decode(errors='replace').strip()}")
        return proc.returncode, out.decode(errors="replace"), err.decode(errors="replace")

    async def sandbox_exists(self, name: str) -> bool:
        return (await self.run("sandbox", "get", name, check=False))[0] == 0

    async def upsert_provider(self, name: str, profile: str, credentials: dict[str, str]):
        flags = [a for k in credentials for a in ("--credential", k)]
        if (await self.run("provider", "get", name, check=False))[0] == 0:
            await self.run("provider", "update", name, *flags, env=credentials)
        else:
            await self.run("provider", "create", "--name", name, "--type", profile, *flags, env=credentials)

    async def create_sandbox(self, name: str, policy_file: str, providers: list[str], labels: dict[str, str]):
        await self.run("sandbox", "create", "--name", name, "--policy", policy_file, "--workdir", "/workspace",
                       *[a for p in providers for a in ("--provider", p)],
                       *[a for k, v in labels.items() for a in ("--label", f"{k}={v}")])

    async def set_policy(self, name: str, policy_file: str):
        # Only network_policies can change on a running sandbox; static sections are part of the name.
        rc, _, err = await self.run("policy", "set", name, "--policy", policy_file, "--wait", check=False)
        if rc == 124:
            raise OpenShellError(f"timed out applying network policy to {name}")
        if rc != 0:
            raise OpenShellError(f"network policy rejected for {name}: {err.strip()}")

    async def exec(self, name: str, argv: list[str], workdir: str | None = None, env: dict[str, str] | None = None) -> tuple[int, str, str]:
        # env here is non-secret configuration only (base URLs, the approved task); secrets come from providers.
        return await self.run("sandbox", "exec", "-n", name, "--no-tty", *(["--workdir", workdir] if workdir else []),
                              *[a for k, v in (env or {}).items() for a in ("--env", f"{k}={v}")], "--", *argv, check=False)

    async def delete_sandboxes(self, names: list[str]):
        if names:
            await self.run("sandbox", "delete", *names)

    def exec_tty_argv(self, name: str, argv: list[str], workdir: str, env: dict[str, str]) -> list[str]:
        # env here is non-secret configuration only (base URLs); secrets come from providers.
        return [self.binary, "sandbox", "exec", "-n", name, "--tty", "--workdir", workdir,
                *[a for k, v in env.items() for a in ("--env", f"{k}={v}")], "--", *argv]
