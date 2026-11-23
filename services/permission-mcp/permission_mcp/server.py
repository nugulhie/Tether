import os, httpx
from mcp.server.fastmcp import FastMCP
mcp=FastMCP("tether-permission")
# Set by the orchestrator in managed sandboxes; POLICY_API for local development.
API=os.getenv("TETHER_POLICY_API") or os.getenv("POLICY_API","http://localhost:8080")
def headers():
    # Injected into the sandbox as an OpenShell provider credential: the agent only sees a
    # placeholder, which the OpenShell proxy replaces with the real session token on egress.
    # User, device, repo and environment are taken from this session server-side.
    return {"Authorization":f"Bearer {os.environ['TETHER_SESSION_TOKEN']}"}
@mcp.tool()
async def check_permission(action:str,resource:str,context:dict|None=None)->dict:
    """Policy decision interface. It does not replace OpenShell enforcement.

    action: network_connect | process_exec | file_read | file_write (anything else is denied).
    resource: host or URL, executable, absolute path, or s3:// URI.
    """
    async with httpx.AsyncClient(timeout=5) as c:
        r=await c.post(f"{API}/v1/permissions/check",json={"action":action,"resource":resource,"context":context or {}},headers=headers()); r.raise_for_status(); return r.json()
@mcp.tool()
async def get_effective_policy(agent:str,environment:str="development")->dict:
    async with httpx.AsyncClient(timeout=5) as c:
        r=await c.get(f"{API}/v1/policies/effective",params={"agent":agent,"environment":environment},headers=headers()); r.raise_for_status(); return r.json()
def main(): mcp.run(transport="stdio")
