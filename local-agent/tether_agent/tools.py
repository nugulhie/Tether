"""Tools the model may call. All paths are confined to the job's workdir (the cloned repository).

The workdir check here keeps the model on task; the security boundary is the OpenShell sandbox
(Landlock filesystem policy, L7 network policy), which also confines whatever run_shell starts.
"""
import json
import os
import signal
import subprocess

# Environment variables run_shell children never get. They hold only OpenShell placeholders, but
# nothing the model runs needs the LLM gateway credential.
SHELL_ENV_DROP = ("TETHER_LLM_TOKEN", "ANTHROPIC_AUTH_TOKEN", "OPENAI_API_KEY", "TETHER_TASK")
MAX_WRITE_BYTES = 4 * 1024 * 1024
MAX_LIST_ENTRIES = 1000


class ToolError(Exception):
    """A tool call the model got wrong; reported back to the model, never fatal."""


SCHEMAS = [
    {"type": "function", "function": {
        "name": "read_file", "description": "Read a UTF-8 text file in the repository. Long files are truncated.",
        "parameters": {"type": "object", "properties": {"path": {"type": "string", "description": "Path relative to the repository root"}},
                       "required": ["path"]}}},
    {"type": "function", "function": {
        "name": "write_file", "description": "Create or overwrite a UTF-8 text file in the repository (parent directories are created).",
        "parameters": {"type": "object", "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
                       "required": ["path", "content"]}}},
    {"type": "function", "function": {
        "name": "list_dir", "description": "List a directory in the repository. Directories end with '/'.",
        "parameters": {"type": "object", "properties": {"path": {"type": "string", "default": "."}}}}},
    {"type": "function", "function": {
        "name": "run_shell", "description": "Run a shell command (sh -c) in the repository root, without a terminal or stdin. "
                                            "Returns the exit code and combined stdout/stderr, truncated. Commands are time-limited.",
        "parameters": {"type": "object", "properties": {"command": {"type": "string"}}, "required": ["command"]}}},
    {"type": "function", "function": {
        "name": "finish", "description": "Call exactly once when the task is complete, with a short summary of what was done.",
        "parameters": {"type": "object", "properties": {"summary": {"type": "string"}}, "required": ["summary"]}}},
]


def truncate(text: str, limit: int) -> str:
    data = text.encode("utf-8", errors="replace")
    if len(data) <= limit:
        return text
    return data[:limit].decode("utf-8", errors="ignore") + f"\n[... truncated: {len(data) - limit} more bytes]"


class Tools:
    def __init__(self, workdir: str, max_output_bytes: int, shell_timeout: float):
        self.root = os.path.realpath(workdir)
        self.max_output = max_output_bytes
        self.shell_timeout = shell_timeout

    def resolve(self, path) -> str:
        """Absolute real path inside the workdir; symlinks and '..' that leave it are refused."""
        if not isinstance(path, str) or not path or "\x00" in path:
            raise ToolError("path must be a non-empty string")
        full = os.path.realpath(os.path.join(self.root, path))
        if full != self.root and not full.startswith(self.root + os.sep):
            raise ToolError(f"path is outside the repository: {path!r}")
        return full

    def call(self, name: str, raw_args) -> str:
        try:
            args = json.loads(raw_args or "{}") if isinstance(raw_args, str) else (raw_args or {})
        except json.JSONDecodeError as e:
            raise ToolError(f"arguments are not valid JSON: {e}")
        if not isinstance(args, dict):
            raise ToolError("arguments must be a JSON object")
        fn = {"read_file": self.read_file, "write_file": self.write_file, "list_dir": self.list_dir, "run_shell": self.run_shell}.get(name)
        if fn is None:
            raise ToolError(f"unknown tool {name!r}")
        try:
            return fn(**args)
        except TypeError as e:
            raise ToolError(f"bad arguments for {name}: {e}")

    def read_file(self, path):
        full = self.resolve(path)
        if not os.path.isfile(full):
            raise ToolError(f"not a file: {path!r}")
        with open(full, "rb") as f:
            data = f.read(self.max_output + 1)
        return truncate(data.decode("utf-8", errors="replace"), self.max_output)

    def write_file(self, path, content):
        if not isinstance(content, str):
            raise ToolError("content must be a string")
        data = content.encode("utf-8")
        if len(data) > MAX_WRITE_BYTES:
            raise ToolError(f"content exceeds {MAX_WRITE_BYTES} bytes")
        full = self.resolve(path)
        if full == self.root or os.path.isdir(full):
            raise ToolError(f"is a directory: {path!r}")
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "wb") as f:
            f.write(data)
        return f"wrote {len(data)} bytes to {os.path.relpath(full, self.root)}"

    def list_dir(self, path="."):
        full = self.resolve(path)
        if not os.path.isdir(full):
            raise ToolError(f"not a directory: {path!r}")
        names = sorted(os.listdir(full))
        shown = [n + ("/" if os.path.isdir(os.path.join(full, n)) else "") for n in names[:MAX_LIST_ENTRIES]]
        if len(names) > MAX_LIST_ENTRIES:
            shown.append(f"[... {len(names) - MAX_LIST_ENTRIES} more entries]")
        return truncate("\n".join(shown), self.max_output)

    def run_shell(self, command):
        if not isinstance(command, str) or not command.strip():
            raise ToolError("command must be a non-empty string")
        env = {k: v for k, v in os.environ.items() if k not in SHELL_ENV_DROP}
        # Own process group, so a timeout kills everything the command started.
        proc = subprocess.Popen(["/bin/sh", "-c", command], cwd=self.root, env=env, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            out, _ = proc.communicate(timeout=self.shell_timeout)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                out, _ = proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:  # something left the group and still holds the pipe
                proc.kill()
                out = b""
            return truncate(f"timed out after {self.shell_timeout:g}s (killed)\n" + out.decode("utf-8", errors="replace"), self.max_output)
        return truncate(f"exit code {proc.returncode}\n" + out.decode("utf-8", errors="replace"), self.max_output)
