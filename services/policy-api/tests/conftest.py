import copy
import os
from pathlib import Path

import pytest
import yaml

POLICY_DIR = Path(__file__).parents[3] / "policies"
os.environ["DATABASE_URL"] = "sqlite://"
os.environ["AUTH_MODE"] = "dev"
os.environ["CREDENTIAL_BROKER_TOKEN"] = "broker-secret"
os.environ["POLICY_PUBLISHER_TOKEN"] = "publisher-secret"
os.environ["POLICY_DIR"] = str(POLICY_DIR)
os.environ["MIGRATE_ON_STARTUP"] = "0"
os.environ["SIEM_TOKEN"] = "siem-secret"
os.environ["ORCHESTRATOR_TOKEN"] = "orchestrator-secret"
os.environ["LLM_GATEWAY_TOKEN"] = "gateway-secret"
os.environ["INTERCEPTOR_TOKEN"] = "interceptor-secret"

PUBLISHER = {"Authorization": "Bearer publisher-secret"}
ORCHESTRATOR = {"Authorization": "Bearer orchestrator-secret"}


def start_session(client, body, headers):
    """Create a session the only way possible: the orchestrator relaying the user's token.

    `headers` are what the user presented to the orchestrator: their bearer token and, when the
    orchestrator's mTLS proxy verified a client certificate, X-Client-Cert-Fingerprint.
    """
    auth = headers.get("Authorization", "")
    token = auth[7:] if auth.startswith("Bearer ") else ""
    body = {**body, "user_token": token}
    if "X-Client-Cert-Fingerprint" in headers:
        body.update(device_id=headers["X-Client-Cert-Fingerprint"], device_verified=True)
    return client.post("/v1/agent/sessions", json=body, headers=ORCHESTRATOR)
BASE = yaml.safe_load((POLICY_DIR / "backend-dev.yaml").read_text())


@pytest.fixture(autouse=True)
def fresh_db():
    """Each test gets its own database built by the real migrations, with policies/ loaded."""
    from sqlalchemy import create_engine
    from sqlalchemy.pool import StaticPool
    import app.main as m
    from app.db import migrate
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    m.Session.configure(bind=engine)
    migrate(bind=engine)
    m.load_dev_policies()
    yield
    engine.dispose()


@pytest.fixture
def publish():
    """Publish the repository policy with overrides (plus extra policies) as the next bundle."""
    from fastapi.testclient import TestClient
    import app.main as m
    from sqlalchemy import func, select
    client = TestClient(m.app)

    def _publish(*extra, expect=200, **overrides):
        with m.Session() as db:
            serial = (db.scalar(select(func.max(m.PolicyBundle.serial))) or 0) + 1
        base = {**copy.deepcopy(BASE), **overrides}
        r = client.post("/v1/policies/bundle", headers=PUBLISHER,
                        json={"format": 1, "serial": serial, "git_commit": "test", "policies": [base, *extra]})
        assert r.status_code == expect, r.text
        return r.json()

    return _publish
