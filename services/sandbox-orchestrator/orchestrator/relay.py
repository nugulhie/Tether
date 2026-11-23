"""Terminal relay: a WebSocket on one side, `openshell sandbox exec --tty` under a PTY on the other.

Protocol: binary frames carry terminal bytes in both directions. Text frames carry JSON
control messages: client -> {"type": "resize", "cols": C, "rows": R}; server -> {"type":
"exit", "code": N} just before closing.
"""
import asyncio
import fcntl
import json
import os
import pty
import signal
import struct
import termios

from fastapi import WebSocket, WebSocketDisconnect


def set_winsize(fd: int, rows: int, cols: int):
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", max(1, rows), max(1, cols), 0, 0))


class Relay:
    def __init__(self, argv: list[str], rows: int = 24, cols: int = 80):
        self.argv, self.rows, self.cols = argv, rows, cols
        self.proc: asyncio.subprocess.Process | None = None
        self.master: int | None = None

    async def start(self):
        self.master, slave = pty.openpty()
        set_winsize(self.master, self.rows, self.cols)
        self.proc = await asyncio.create_subprocess_exec(*self.argv, stdin=slave, stdout=slave, stderr=slave, start_new_session=True)
        os.close(slave)
        os.set_blocking(self.master, False)

    def resize(self, rows: int, cols: int):
        set_winsize(self.master, rows, cols)
        # The PTY is not the child's controlling terminal, so tell it explicitly.
        try:
            os.killpg(self.proc.pid, signal.SIGWINCH)
        except ProcessLookupError:
            pass

    def kill(self):
        if self.proc and self.proc.returncode is None:
            try:
                os.killpg(self.proc.pid, signal.SIGHUP)
            except ProcessLookupError:
                pass

    async def pump(self, ws: WebSocket) -> int:
        loop = asyncio.get_running_loop()
        output: asyncio.Queue[bytes | None] = asyncio.Queue()

        def readable():
            try:
                data = os.read(self.master, 65536)
            except BlockingIOError:
                return
            except OSError:  # EIO: the child closed the terminal
                data = b""
            if not data:
                loop.remove_reader(self.master)
            output.put_nowait(data or None)

        loop.add_reader(self.master, readable)

        async def to_client():
            while (data := await output.get()) is not None:
                await ws.send_bytes(data)

        async def from_client():
            while True:
                msg = await ws.receive()
                if msg["type"] == "websocket.disconnect":
                    raise WebSocketDisconnect()
                if msg.get("bytes"):
                    os.write(self.master, msg["bytes"])
                elif msg.get("text"):
                    ctl = json.loads(msg["text"])
                    if ctl.get("type") == "resize":
                        self.resize(int(ctl["rows"]), int(ctl["cols"]))

        sender, receiver = asyncio.create_task(to_client()), asyncio.create_task(from_client())
        try:
            done, _ = await asyncio.wait({sender, receiver}, return_when=asyncio.FIRST_COMPLETED)
            if receiver in done:  # client went away: stop the remote command
                self.kill()
            code = await self.proc.wait()
            if receiver not in done:
                await sender  # drain remaining output
        finally:
            for t in (sender, receiver):
                t.cancel()
            loop.remove_reader(self.master)
            os.close(self.master)
        return code
