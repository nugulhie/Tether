"""Thin async wrapper around the OpenShell CLI, run with the orchestrator's own gateway identity.

The orchestrator is the only holder of gateway credentials (OPENSHELL_GATEWAY / mTLS / OIDC
client credentials in its environment). OpenShell has no per-sandbox ACL, so developers are
never given gateway access: anyone who can exec into a sandbox can also create one.
Secret values are passed through the child environment (`--credential KEY`), never argv.
"""
import asyncio
import os

# `openshell sandbox exec` caps piped stdin at 4 MiB (MAX_EXEC_STDIN_BYTES in the v0.1.9 CLI).
MAX_EXEC_STDIN_BYTES = 4 * 1024 * 1024


class OpenShellError(RuntimeError):
    pass


class OpenShell:
    def __init__(self, binary: str = "openshell"):
        self.binary = binary

    async def run(self, *args: str, env: dict | None = None, check: bool = True, input: bytes | None = None) -> tuple[int, str, str]:
        # stdin is never the orchestrator's own: either the given bytes or nothing.
        try:
            proc = await asyncio.create_subprocess_exec(self.binary, *args, env={**os.environ, **(env or {})},
                                                        stdin=asyncio.subprocess.PIPE if input is not None else asyncio.subprocess.DEVNULL,
                                                        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        except OSError as e:
            raise OpenShellError(f"cannot run {self.binary}: {e}")
        try:
            out, err = await proc.communicate(input)
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

    async def create_sandbox(self, name: str, image: str, policy_file: str, providers: list[str], labels: dict[str, str]):
        # `sandbox create` has no --workdir: on Docker the image's WORKDIR is the workspace, so approved
        # images declare `WORKDIR /workspace` (writable by the sandbox user). The image is always given
        # explicitly; the gateway interceptor denies creates without one (no driver default_image).
        # --detach: never attach to the main process; --no-auto-providers: never create providers from
        # the orchestrator's own environment, only the ones it upserted.
        await self.run("sandbox", "create", "--name", name, "--from", image, "--policy", policy_file, "--detach", "--no-auto-providers",
                       *[a for p in providers for a in ("--provider", p)],
                       *[a for k, v in labels.items() for a in ("--label", f"{k}={v}")])

    async def set_policy(self, name: str, policy_file: str):
        # Only network_policies can change on a running sandbox; static sections are part of the name.
        rc, _, err = await self.run("policy", "set", name, "--policy", policy_file, "--wait", check=False)
        if rc == 124:
            raise OpenShellError(f"timed out applying network policy to {name}")
        if rc != 0:
            raise OpenShellError(f"network policy rejected for {name}: {err.strip()}")

    async def exec(self, name: str, argv: list[str], workdir: str | None = None, env: dict[str, str] | None = None,
                   input: bytes | None = None) -> tuple[int, str, str]:
        # env here is non-secret configuration only (base URLs, file paths); it is visible in process
        # listings. Secrets come from providers; anything else sensitive goes through stdin (`input`).
        # --no-login-shell: sandbox-user profile files must not run before (or alter) automation.
        if input is not None and len(input) > MAX_EXEC_STDIN_BYTES:
            raise OpenShellError(f"input is {len(input)} bytes; openshell sandbox exec accepts at most {MAX_EXEC_STDIN_BYTES} bytes of stdin")
        return await self.run("sandbox", "exec", "-n", name, "--no-tty", "--no-login-shell", *(["--workdir", workdir] if workdir else []),
                              *[a for k, v in (env or {}).items() for a in ("--env", f"{k}={v}")], "--", *argv, check=False, input=input)

    async def write_file(self, name: str, path: str, data: bytes) -> None:
        """Write `data` to `path` inside the sandbox via stdin, so the content never appears in argv.
        The path is a positional argument to a fixed script, never interpolated into it."""
        rc, _, err = await self.exec(name, ["sh", "-c", 'umask 077 && mkdir -p -- "$(dirname -- "$1")" && cat > "$1"', "sh", path], input=data)
        if rc != 0:
            raise OpenShellError(f"writing {path} in sandbox {name} failed ({rc}): {err.strip()[-500:]}")

    async def delete_sandboxes(self, names: list[str]):
        if names:
            await self.run("sandbox", "delete", *names)

    def exec_tty_argv(self, name: str, argv: list[str], workdir: str, env: dict[str, str]) -> list[str]:
        # env here is non-secret configuration only (base URLs); secrets come from providers.
        return [self.binary, "sandbox", "exec", "-n", name, "--tty", "--workdir", workdir,
                *[a for k, v in env.items() for a in ("--env", f"{k}={v}")], "--", *argv]
