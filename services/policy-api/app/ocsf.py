"""Normalize audit events to OCSF (base event fields plus the relevant class).

Events are stored in the audit_events table and written to stdout as JSON lines
so a log forwarder can ship them to the SIEM.
"""
import json
import logging
import time

OCSF_VERSION = "1.3.0"
PRODUCT = {"name": "Company Agent Security Platform", "vendor_name": "Company"}

API_ACTIVITY = (6003, 6, "API Activity", "Application Activity")
PROCESS_ACTIVITY = (1007, 1, "Process Activity", "System Activity")
AUTHENTICATION = (3002, 3, "Authentication", "Identity & Access Management")

# event_type -> (class, activity_id, activity_name)
EVENT_TYPES = {
    "session.create": (API_ACTIVITY, 1, "Create"),
    "permission.check": (API_ACTIVITY, 2, "Read"),
    "credential.issue": (API_ACTIVITY, 1, "Create"),
    "sandbox.create": (PROCESS_ACTIVITY, 1, "Launch"),
    "sandbox.reuse": (PROCESS_ACTIVITY, 1, "Launch"),
    "agent.exit": (PROCESS_ACTIVITY, 2, "Terminate"),
    "sandbox.delete": (PROCESS_ACTIVITY, 2, "Terminate"),
    "policy.publish": (API_ACTIVITY, 3, "Update"),
    "session.revoke": (API_ACTIVITY, 4, "Delete"),
    "llm.request": (API_ACTIVITY, 1, "Create"),
    "llm.content": (API_ACTIVITY, 1, "Create"),
    "llm.denied": (API_ACTIVITY, 99, "Other"),
    "audit.content.read": (API_ACTIVITY, 2, "Read"),
    "audit.content.hold.start": (API_ACTIVITY, 1, "Create"),
    "audit.content.hold.end": (API_ACTIVITY, 4, "Delete"),
    "audit.content.purge": (API_ACTIVITY, 4, "Delete"),
    "audit.content.rekey": (API_ACTIVITY, 3, "Update"),
    "guardrail.block": (API_ACTIVITY, 99, "Other"),
    "guardrail.error": (API_ACTIVITY, 99, "Other"),
    "guardrail.bypass.start": (API_ACTIVITY, 1, "Create"),
    "guardrail.bypass.end": (API_ACTIVITY, 4, "Delete"),
    "agent.job.request": (API_ACTIVITY, 1, "Create"),
    "agent.job.approve": (API_ACTIVITY, 3, "Update"),
    "agent.job.reject": (API_ACTIVITY, 3, "Update"),
    "agent.job.disable": (API_ACTIVITY, 3, "Update"),
    "agent.job.result": (API_ACTIVITY, 1, "Create"),
    "agent.job.result.read": (API_ACTIVITY, 2, "Read"),
    "session.end": (API_ACTIVITY, 4, "Delete"),
    "auth.token.issue": (AUTHENTICATION, 1, "Logon"),
}
# Users and agent sessions report nothing: sandbox lifecycle is recorded by the orchestrator,
# which is the only component that can create, attach to or delete sandboxes.
CLIENT_EVENT_TYPES: set[str] = set()
# Which service may report which event types.
SERVICE_EVENT_TYPES = {"credential-broker": {"credential.issue"}, "llm-gateway": {"llm.request", "llm.denied", "guardrail.block", "guardrail.error"},
                       "sandbox-orchestrator": {"sandbox.create", "sandbox.reuse", "agent.exit", "sandbox.delete"}}

log = logging.getLogger("audit")
if not log.handlers:
    log.addHandler(logging.StreamHandler())
    log.setLevel(logging.INFO)
    log.propagate = False


def build(event_type, *, user_id, device_id=None, device_verified=False, session_id=None,
          source, success=True, allowed=None, message="", data=None):
    (class_uid, category_uid, class_name, category_name), activity_id, activity_name = EVENT_TYPES[event_type]
    event = {
        "time": int(time.time() * 1000),
        "class_uid": class_uid,
        "class_name": class_name,
        "category_uid": category_uid,
        "category_name": category_name,
        "activity_id": activity_id,
        "activity_name": activity_name,
        "type_uid": class_uid * 100 + activity_id,
        "severity_id": 1,
        "status_id": 1 if success else 2,
        "message": message or event_type,
        "metadata": {"version": OCSF_VERSION, "product": PRODUCT, "log_provider": source, "event_code": event_type},
        "actor": {"user": {"uid": user_id}},
        "unmapped": data or {},
    }
    if device_id:
        event["device"] = {"uid": device_id, "type_id": 0, "is_trusted": device_verified}
    if session_id:
        event["actor"]["session"] = {"uid": session_id}
    if allowed is not None:
        event["metadata"]["profiles"] = ["security_control"]
        event["disposition_id"] = 1 if allowed else 2
        event["disposition"] = "Allowed" if allowed else "Blocked"
    return event


def emit(event):
    log.info(json.dumps(event, separators=(",", ":"), default=str))
