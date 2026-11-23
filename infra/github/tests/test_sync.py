import json
import sys
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).parents[1]))
import sync_ip_allow_list as s  # noqa: E402

ORG = {"id": "O_1", "ipAllowListEnabledSetting": "DISABLED", "ipAllowListForInstalledAppsEnabledSetting": "DISABLED",
       "ipAllowListEntries": {"nodes": [
           {"id": "E_old", "allowListValue": "192.0.2.0/24", "name": "company-agent: old-egress", "isActive": True},
           {"id": "E_human", "allowListValue": "198.51.100.7/32", "name": "manual entry", "isActive": True},
           {"id": "E_off", "allowListValue": "203.0.113.10/32", "name": "company-agent: sandbox-egress", "isActive": False}]}}


def fake(monkeypatch, org=ORG):
    calls = []

    def handle(req):
        body = json.loads(req.content)
        calls.append(body)
        if body["query"].startswith("query"):
            return httpx.Response(200, json={"data": {"organization": org}})
        return httpx.Response(200, json={"data": {}})
    monkeypatch.setattr(s, "transport", httpx.MockTransport(handle))
    monkeypatch.setenv("GITHUB_ADMIN_TOKEN", "t")
    return calls


def test_plan_orders_safely_and_keeps_unmanaged(monkeypatch):
    fake(monkeypatch)
    actions = s.main(["--org", "acme", "--cidr", "sandbox-egress=203.0.113.10/32", "--cidr", "vpn=198.51.100.16/28"])
    assert actions == [("create", "198.51.100.16/28", "company-agent: vpn"), ("activate", "E_off", "203.0.113.10/32"),
                       ("enable", "ipAllowList", ""), ("enable", "installedApps", ""), ("delete", "E_old", "192.0.2.0/24")]


def test_dry_run_makes_no_changes(monkeypatch):
    calls = fake(monkeypatch)
    s.main(["--org", "acme", "--cidr", "sandbox-egress=203.0.113.10/32"])
    assert all(c["query"].startswith("query") for c in calls)


def test_apply(monkeypatch):
    calls = fake(monkeypatch)
    s.main(["--org", "acme", "--cidr", "sandbox-egress=203.0.113.10/32", "--prune-unmanaged", "--apply"])
    muts = [c["query"] for c in calls[1:]]
    assert any("updateIpAllowListForInstalledAppsEnabledSetting" in q for q in muts)
    assert sum("deleteIpAllowListEntry" in q for q in muts) == 2  # managed old + unmanaged (pruned)


@pytest.mark.parametrize("cidr", ["x", "egress=10.0.0.0/8", "egress=203.0.113.10/24", "=1.2.3.4/32"])
def test_rejects_bad_or_broad_cidrs(monkeypatch, cidr):
    fake(monkeypatch)
    with pytest.raises(SystemExit):
        s.main(["--org", "acme", "--cidr", cidr])
