"""Rule-based guardrail checks (gateway/guardrails.py)."""
import json

import pytest

from gateway import guardrails as gr

AWS = "AKIAIOSFODNN7EXAMPLE"
ALL = {"secrets": True, "pii": True}


@pytest.mark.parametrize("text,rule", [
    (f"key={AWS}", "secrets.aws_access_key"),
    (f"fine{AWS}", "secrets.aws_access_key"),  # glued to preceding text, as concatenated stream deltas are
    ("ghp_" + "a" * 36, "secrets.github_token"),
    ("-----BEGIN RSA PRIVATE KEY-----", "secrets.private_key"),
    ("-----BEGIN PRIVATE KEY-----", "secrets.private_key"),
    ("ast_" + "x" * 30, "secrets.session_token"),
    ("주민번호 900101-1234567", "pii.kr_resident_number"),
    ("010-1234-5678", "pii.kr_mobile_number"),
    ("4111 1111 1111 1111", "pii.card_number"),
])
def test_detects(text, rule):
    assert rule in gr.scan(text, ALL)


@pytest.mark.parametrize("text", ["AKIA-short", "order 1234 5678 9012 3456", "version 2026-11-23", "def private_key(): pass"])
def test_ignores_lookalikes(text):
    assert gr.scan(text, ALL) == []


def test_rules_are_opt_in():
    assert gr.scan(AWS, {"pii": True}) == []
    assert gr.scan("rm -rf /", {"deny_patterns": [r"rm\s+-rf\s+/"]}) == ["deny_patterns[0]"]


def test_input_checks_decoded_json_strings():
    # A JSON escape must not hide a key from the check.
    body = json.dumps({"messages": [{"role": "user", "content": AWS}]}).replace("A", "\\u0041", 1).encode()
    assert b"AKIA" not in body
    with pytest.raises(gr.Violation) as e:
        gr.check_input(body, {"input": {"secrets": True}})
    assert e.value.rules == ["secrets.aws_access_key"]
    gr.check_input(body, {"output": {"secrets": True}})  # no input rules: nothing to check
    gr.check_input(body, None)


def test_input_must_be_json():
    with pytest.raises(ValueError):
        gr.check_input(b"not json", {"input": {"secrets": True}})


def sse(*texts):
    return b"".join(b"data: " + json.dumps({"type": "content_block_delta", "delta": {"type": "text_delta", "text": t}}).encode() + b"\n\n"
                    for t in texts)


def test_stream_passes_clean_bytes_unchanged_in_any_chunking():
    raw = sse("hello ", "world") + b"data: [DONE]\n\n"
    sc = gr.OutputScanner({"output": {"secrets": True}}, streaming=True)
    out = b"".join(sc.feed(raw[i:i + 7]) for i in range(0, len(raw), 7)) + sc.finish()
    assert out == raw


def test_stream_holds_back_partial_lines():
    sc = gr.OutputScanner({"output": {"secrets": True}}, streaming=True)
    raw = sse("hello")
    assert sc.feed(raw[:10]) == b""
    assert sc.feed(raw[10:]) == raw


def test_stream_catches_a_secret_split_across_events():
    sc = gr.OutputScanner({"output": {"secrets": True}}, streaming=True)
    assert sc.feed(sse("here: AKIAIOSF")) != b""
    with pytest.raises(gr.Violation):
        sc.feed(sse("ODNN7EXAMPLE"))


def test_violation_carries_the_checked_events_before_it():
    sc = gr.OutputScanner({"output": {"secrets": True}}, streaming=True)
    with pytest.raises(gr.Violation) as e:
        sc.feed(sse("fine", AWS, "after"))
    assert e.value.safe == sse("fine")


def test_non_streaming_is_held_until_checked():
    body = json.dumps({"choices": [{"message": {"content": f"use {AWS}"}}]}).encode()
    sc = gr.OutputScanner({"output": {"secrets": True}}, streaming=False)
    assert sc.feed(body) == b""
    with pytest.raises(gr.Violation):
        sc.finish()


def test_inactive_scanner_is_a_pass_through():
    sc = gr.OutputScanner({"input": {"secrets": True}}, streaming=True)
    assert not sc.active and sc.feed(b"partial") == b"partial" and sc.finish() == b""


def test_stream_error_formats():
    a = gr.stream_error("anthropic", "blocked")
    assert a.startswith(b"event: error\ndata: ") and json.loads(a.split(b"data: ")[1])["error"]["message"] == "blocked"
    o = gr.stream_error("local", "blocked")
    assert json.loads(o[6:])["error"]["type"] == "guardrail_violation"
