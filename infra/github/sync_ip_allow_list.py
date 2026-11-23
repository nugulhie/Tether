#!/usr/bin/env python3
"""Keep the GitHub Enterprise Cloud organization IP allow list equal to the approved egress set.

The organization's repositories are then reachable only from the sandbox egress proxy (and any
extra ranges you approve, such as an office or VPN egress). That closes the "clone onto an
unmanaged machine and run an agent there" path for git, the API and GitHub App tokens alike.

Entries this script manages are named "tether: <label>"; other entries are left alone
unless --prune-unmanaged is given. Dry run by default.

  GITHUB_ADMIN_TOKEN=... ./sync_ip_allow_list.py --org acme \\
      --cidr sandbox-egress=203.0.113.10/32 [--cidr office-vpn=198.51.100.0/28] [--apply]
"""
import argparse
import ipaddress
import os
import sys

import httpx

API = "https://api.github.com/graphql"
PREFIX = "tether: "
transport = None  # overridable in tests

QUERY = """query($login: String!) { organization(login: $login) { id
  ipAllowListEnabledSetting ipAllowListForInstalledAppsEnabledSetting
  ipAllowListEntries(first: 100) { nodes { id allowListValue name isActive } } } }"""


def gql(token, query, variables):
    with httpx.Client(timeout=30, transport=transport) as c:
        r = c.post(API, headers={"Authorization": f"Bearer {token}"}, json={"query": query, "variables": variables})
    r.raise_for_status()
    body = r.json()
    if body.get("errors"):
        raise SystemExit(f"GitHub API error: {body['errors']}")
    return body["data"]


def plan(org_data, desired: dict[str, str], prune_unmanaged: bool):
    entries = org_data["ipAllowListEntries"]["nodes"]
    have = {e["allowListValue"]: e for e in entries}
    actions = []
    for label, cidr in desired.items():
        e = have.get(cidr)
        if not e:
            actions.append(("create", cidr, PREFIX + label))
        elif not e["isActive"]:
            actions.append(("activate", e["id"], cidr))
    for e in entries:
        managed = (e["name"] or "").startswith(PREFIX)
        if e["allowListValue"] not in desired.values() and (managed or prune_unmanaged):
            actions.append(("delete", e["id"], e["allowListValue"]))
    if org_data["ipAllowListEnabledSetting"] != "ENABLED":
        actions.append(("enable", "ipAllowList", ""))
    # Without this, GitHub App installation tokens (the agents' tokens) would ignore the list.
    if org_data["ipAllowListForInstalledAppsEnabledSetting"] != "ENABLED":
        actions.append(("enable", "installedApps", ""))
    # Enable the list only after the approved entries exist, never lock everyone out first.
    return sorted(actions, key=lambda a: {"create": 0, "activate": 1, "enable": 2, "delete": 3}[a[0]])


def apply(token, owner_id, actions):
    m = {
        "create": "mutation($o:ID!,$v:String!,$n:String!){createIpAllowListEntry(input:{ownerId:$o,allowListValue:$v,name:$n,isActive:true}){clientMutationId}}",
        "activate": "mutation($id:ID!,$v:String!){updateIpAllowListEntry(input:{ipAllowListEntryId:$id,allowListValue:$v,isActive:true}){clientMutationId}}",
        "delete": "mutation($id:ID!){deleteIpAllowListEntry(input:{ipAllowListEntryId:$id}){clientMutationId}}",
        "ipAllowList": "mutation($o:ID!){updateIpAllowListEnabledSetting(input:{ownerId:$o,settingValue:ENABLED}){clientMutationId}}",
        "installedApps": "mutation($o:ID!){updateIpAllowListForInstalledAppsEnabledSetting(input:{ownerId:$o,settingValue:ENABLED}){clientMutationId}}",
    }
    for kind, a, b in actions:
        if kind == "create":
            gql(token, m["create"], {"o": owner_id, "v": a, "n": b})
        elif kind == "activate":
            gql(token, m["activate"], {"id": a, "v": b})
        elif kind == "delete":
            gql(token, m["delete"], {"id": a})
        else:
            gql(token, m[a], {"o": owner_id})


def parse_cidrs(values):
    out = {}
    for v in values:
        label, _, cidr = v.partition("=")
        if not label or not cidr:
            raise SystemExit(f"--cidr must be label=CIDR: {v!r}")
        try:
            net = ipaddress.ip_network(cidr, strict=True)
        except ValueError as e:
            raise SystemExit(f"invalid CIDR {cidr!r}: {e}")
        if net.prefixlen < (24 if net.version == 4 else 48):
            raise SystemExit(f"{cidr} is too broad for an allow list entry")
        out[label] = str(net)
    return out


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--org", required=True)
    ap.add_argument("--cidr", action="append", required=True, help="label=CIDR, repeatable")
    ap.add_argument("--prune-unmanaged", action="store_true", help="also delete entries not created by this script")
    ap.add_argument("--apply", action="store_true")
    a = ap.parse_args(argv)
    token = os.environ.get("GITHUB_ADMIN_TOKEN") or sys.exit("GITHUB_ADMIN_TOKEN is required")
    desired = parse_cidrs(a.cidr)
    org = gql(token, QUERY, {"login": a.org})["organization"]
    if len(org["ipAllowListEntries"]["nodes"]) >= 100:
        sys.exit("more than 100 allow list entries: paginate before using this script")
    actions = plan(org, desired, a.prune_unmanaged)
    for act in actions:
        print(("APPLY " if a.apply else "PLAN  ") + " ".join(x for x in act if x))
    if a.apply:
        apply(token, org["id"], actions)
    return actions


if __name__ == "__main__":
    main()
