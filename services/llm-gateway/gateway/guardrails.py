"""Prompt and response guardrails (ADR 0001, D3).

Rules come from the session's policy (`guardrails` section, validated by the policy compiler):

    guardrails:
      input:  {secrets: true, pii: true, deny_patterns: ["(?i)drop\\s+table"]}
      output: {secrets: true, pii: false}

The checks here are rule based. `check_input` and `OutputScanner` are the interface the gateway
uses, so a model-based guardrail can replace them later without touching the proxy.

Failure handling is the caller's job and is always fail-closed: any exception raised here
(other than `Violation`) makes the gateway refuse the request or cut the stream.
"""
import json
import re

# Credentials that must not be sent to, or produced by, a model.
SECRETS = {
    # Bounded by characters that cannot be part of a key, not \b: streamed text is concatenated,
    # and "fineAKIA..." must not hide a key.
    "aws_access_key": r"(?<![0-9A-Z])(?:AKIA|ASIA)[0-9A-Z]{16}(?![0-9A-Z])",
    "github_token": r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b",
    "private_key": r"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----",
    "slack_token": r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b",
    "provider_api_key": r"\bsk-(?:ant-[A-Za-z0-9]+-)?[A-Za-z0-9_-]{32,}\b",
    "session_token": r"\bast_[A-Za-z0-9_-]{20,}\b",
}
# Personal data (Korea-first).
PII = {
    "kr_resident_number": r"\b\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])-?[1-8]\d{6}\b",
    "kr_mobile_number": r"\b01[016789]-?\d{3,4}-?\d{4}\b",
    "card_number": r"\b(?:\d[ -]?){13,19}\b",
}
_SECRETS = {k: re.compile(v) for k, v in SECRETS.items()}
_PII = {k: re.compile(v) for k, v in PII.items()}
# Characters of already-scanned output kept so a match split across stream events is still found.
TAIL = 512
# Keys whose string values are protocol metadata, not text.
_META_KEYS = {"type", "id", "model", "role", "object", "stop_reason", "finish_reason", "event", "index", "signature"}


class Violation(Exception):
    """`safe` is the checked output that precedes the violating event and may still be sent."""

    def __init__(self, direction: str, rules: list[str], safe: bytes = b""):
        super().__init__(f"{direction} guardrail: {', '.join(rules)}")
        self.direction, self.rules, self.safe = direction, rules, safe


def _luhn(digits: str) -> bool:
    total, alt = 0, False
    for d in reversed(digits):
        n = int(d) * (2 if alt else 1)
        total += n - 9 if n > 9 else n
        alt = not alt
    return total % 10 == 0


def strings(obj):
    """Every text value in a JSON document (decoded, so escapes cannot hide a pattern)."""
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, list):
        for v in obj:
            yield from strings(v)
    elif isinstance(obj, dict):
        for k, v in obj.items():
            if k not in _META_KEYS:
                yield from strings(v)


def scan(text: str, rules: dict) -> list[str]:
    """Names of the rules `text` breaks."""
    hits = []
    if rules.get("secrets"):
        hits += [f"secrets.{k}" for k, rx in _SECRETS.items() if rx.search(text)]
    if rules.get("pii"):
        for k, rx in _PII.items():
            for m in rx.finditer(text):
                if k != "card_number" or _luhn(re.sub(r"\D", "", m.group())):
                    hits.append(f"pii.{k}")
                    break
    for i, pat in enumerate(rules.get("deny_patterns") or []):
        if re.search(pat, text):
            hits.append(f"deny_patterns[{i}]")
    return hits


def check_input(body: bytes, guardrails: dict | None):
    """Raise Violation if the request body breaks the input rules."""
    rules = (guardrails or {}).get("input")
    if not rules:
        return
    hits = scan("\n".join(strings(json.loads(body))), rules)
    if hits:
        raise Violation("input", hits)


class OutputScanner:
    """Checks a response as it streams. `feed` takes raw bytes and returns the bytes that are safe
    to send (complete SSE lines only, so nothing is sent before it is checked); it raises Violation
    when a rule is broken. Concatenating everything returned equals the upstream bytes."""

    def __init__(self, guardrails: dict | None, streaming: bool):
        self.rules = (guardrails or {}).get("output") or {}
        self.streaming, self.pending, self.tail, self.body = streaming, b"", "", b""

    @property
    def active(self) -> bool:
        return bool(self.rules)

    def _check(self, text: str):
        if not text:
            return
        window = self.tail + text
        hits = scan(window, self.rules)
        if hits:
            raise Violation("output", hits)
        self.tail = window[-TAIL:]

    def feed(self, chunk: bytes) -> bytes:
        if not self.active:
            return chunk
        if not self.streaming:
            self.body += chunk  # checked whole in finish(); nothing is sent before that
            return b""
        self.pending += chunk
        cut = self.pending.rfind(b"\n")
        if cut < 0:
            return b""
        ready, self.pending = self.pending[:cut + 1], self.pending[cut + 1:]
        # Checked one event at a time, so a violation still lets the events before it through.
        pos, boundary = 0, 0
        for line in ready.split(b"\n")[:-1]:
            if line.startswith(b"data:"):
                try:
                    text = "".join(strings(json.loads(line[5:].strip())))
                except ValueError:
                    text = ""  # e.g. "[DONE]"
                try:
                    self._check(text)
                except Violation as v:
                    v.safe = ready[:boundary]
                    raise
            pos += len(line) + 1
            if not line.strip():
                boundary = pos  # end of an SSE event
        return ready

    def finish(self) -> bytes:
        if not self.active:
            return b""
        if not self.streaming:
            try:
                doc = json.loads(self.body)
            except ValueError:
                doc = self.body.decode("utf-8", "replace")
            self._check("\n".join(strings(doc)))
            return self.body
        rest, self.pending = self.pending, b""
        if rest.startswith(b"data:"):
            try:
                self._check("".join(strings(json.loads(rest[5:].strip()))))
            except ValueError:
                pass
        return rest


def stream_error(provider: str, message: str) -> bytes:
    """A terminal error event in the provider's own SSE format, so clients stop cleanly."""
    if provider == "anthropic":
        return b"event: error\ndata: " + json.dumps({"type": "error", "error": {"type": "api_error", "message": message}}).encode() + b"\n\n"
    return b"data: " + json.dumps({"error": {"type": "guardrail_violation", "message": message}}).encode() + b"\n\n"
