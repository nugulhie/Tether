import base64,json,os,signal,ssl,subprocess,sys,threading,time,click,httpx
from pathlib import Path
HOME=Path.home()/".company-agent"; TOKEN_FILE=HOME/"token.json"
# Deployed by MDM. When present it is authoritative: environment overrides are ignored so a
# user cannot point the signed launcher at a different orchestrator.
MANAGED_CONFIG=Path("/Library/Application Support/CompanyAgent/config.json"); MANAGED_OWNER_UID=0
ENV_KEYS={"orchestrator":"COMPANY_ORCHESTRATOR","device_id":"COMPANY_DEVICE_ID","oidc_issuer":"COMPANY_OIDC_ISSUER",
          "oidc_client_id":"COMPANY_OIDC_CLIENT_ID","client_cert":"COMPANY_CLIENT_CERT","client_key":"COMPANY_CLIENT_KEY"}
DEFAULTS={"orchestrator":"http://localhost:8083","device_id":"local-dev"}

def managed_config():
    if not MANAGED_CONFIG.exists(): return None
    st=MANAGED_CONFIG.stat()
    # A managed file anyone could edit is worse than none: refuse to run.
    if st.st_uid!=MANAGED_OWNER_UID or st.st_mode&0o022:
        raise click.ClickException(f"{MANAGED_CONFIG} must be owned by root and not group/world-writable")
    return json.loads(MANAGED_CONFIG.read_text())

def setting(key):
    m=managed_config()
    if m is not None: return m.get(key,DEFAULTS.get(key))
    return os.getenv(ENV_KEYS[key],DEFAULTS.get(key))

def http(timeout=10):
    # mTLS client certificate identifies the device when the API sits behind an mTLS proxy.
    cert=setting("client_cert"); key=setting("client_key")
    return httpx.Client(timeout=timeout,cert=(cert,key) if cert else None)

# --- OIDC login (device authorization grant, RFC 8628) -----------------------

def oidc_config():
    issuer=setting("oidc_issuer"); client_id=setting("oidc_client_id")
    if not (issuer and client_id): raise click.ClickException("set COMPANY_OIDC_ISSUER and COMPANY_OIDC_CLIENT_ID")
    with http() as c: d=c.get(issuer.rstrip("/")+"/.well-known/openid-configuration").raise_for_status().json()
    return client_id,d

def jwt_exp(token):
    payload=token.split(".")[1]; payload+="="*(-len(payload)%4)
    return json.loads(base64.urlsafe_b64decode(payload))["exp"]

def save_token(t):
    # The ID token is the API bearer (like kubectl's OIDC plugin); the API's audience is the client id.
    HOME.mkdir(parents=True,exist_ok=True,mode=0o700)
    data={"id_token":t["id_token"],"refresh_token":t.get("refresh_token"),"expires_at":jwt_exp(t["id_token"])}
    fd=os.open(TOKEN_FILE,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
    with os.fdopen(fd,"w") as f: json.dump(data,f)
    os.chmod(TOKEN_FILE,0o600)  # O_CREAT mode does not apply to an existing file

def load_token():
    if os.getenv("COMPANY_AGENT_TOKEN") and managed_config() is None: return os.environ["COMPANY_AGENT_TOKEN"]
    if not TOKEN_FILE.exists(): raise click.ClickException("not logged in: run `company-agent login`")
    t=json.loads(TOKEN_FILE.read_text())
    if t["expires_at"]-60>time.time(): return t["id_token"]
    if not t.get("refresh_token"): raise click.ClickException("login expired: run `company-agent login`")
    client_id,d=oidc_config()
    with http() as c: r=c.post(d["token_endpoint"],data={"grant_type":"refresh_token","refresh_token":t["refresh_token"],"client_id":client_id})
    if r.status_code!=200 or "id_token" not in r.json(): raise click.ClickException("login expired: run `company-agent login`")
    # Keep the old refresh token if the IdP does not rotate it.
    new=r.json(); new.setdefault("refresh_token",t["refresh_token"]); save_token(new); return new["id_token"]

@click.group()
def cli(): pass

@cli.command()
def login():
    """Sign in with company SSO."""
    client_id,d=oidc_config()
    with http() as c:
        a=c.post(d["device_authorization_endpoint"],data={"client_id":client_id,"scope":"openid email profile offline_access"}).raise_for_status().json()
        click.echo(f"Open {a.get('verification_uri_complete') or a['verification_uri']} and enter code {a['user_code']}")
        interval=a.get("interval",5); deadline=time.time()+a.get("expires_in",600)
        while time.time()<deadline:
            time.sleep(interval)
            r=c.post(d["token_endpoint"],data={"grant_type":"urn:ietf:params:oauth:grant-type:device_code","device_code":a["device_code"],"client_id":client_id})
            if r.status_code==200: save_token(r.json()); click.echo("Logged in."); return
            err=r.json().get("error")
            if err=="slow_down": interval+=5
            elif err!="authorization_pending": raise click.ClickException(f"login failed: {err}")
    raise click.ClickException("login timed out")

# --- agent launch -------------------------------------------------------------
# The launcher is only a terminal. The orchestrator creates the session, obtains credentials,
# builds the sandbox on the managed gateway and relays the terminal; this machine never holds
# a session token, gateway credentials or cloud/GitHub credentials.

def git_remote():
    try: subprocess.check_output(["git","rev-parse","--show-toplevel"],text=True,stderr=subprocess.DEVNULL)
    except (subprocess.CalledProcessError,FileNotFoundError): raise click.ClickException("run company-agent inside a Git repository")
    remote=subprocess.run(["git","remote","get-url","origin"],text=True,capture_output=True).stdout.strip()
    if not remote: raise click.ClickException("the repository has no origin remote; agents work on the company GitHub copy")
    return remote

def request_launch(agent,environment,token):
    url=f"{setting('orchestrator').rstrip('/')}/v1/launch"
    try:
        with http(timeout=300) as c:
            r=c.post(url,headers={"Authorization":f"Bearer {token}"},json={"agent":agent,"repo":git_remote(),"environment":environment,"device_id":setting("device_id")})
    except httpx.HTTPError as e: raise click.ClickException(f"cannot reach {url}: {e}")
    if r.status_code>=400:
        detail=r.json().get("detail",r.text) if r.headers.get("content-type","").startswith("application/json") else r.text
        raise click.ClickException(f"launch refused ({r.status_code}): {detail}")
    return r.json()

def ws_connect(url):
    from websockets.sync.client import connect
    ctx=None
    if url.startswith("wss://"):
        ctx=ssl.create_default_context()
        if setting("client_cert"): ctx.load_cert_chain(setting("client_cert"),setting("client_key"))
    return connect(url,ssl=ctx,max_size=None,open_timeout=30)

def fd(stream):
    try: return stream.fileno()
    except (OSError,ValueError,AttributeError): return None  # not a real file (e.g. test runners)

def terminal_size():
    try: return os.get_terminal_size(fd(sys.stdout))
    except (OSError,TypeError): return os.terminal_size((80,24))

def attach(launch):
    base=setting("orchestrator").rstrip("/").replace("https://","wss://",1).replace("http://","ws://",1)
    size=terminal_size()
    ws=ws_connect(f"{base}{launch['attach_path']}?ticket={launch['ticket']}&rows={size.lines}&cols={size.columns}")
    stdin=fd(sys.stdin); out=getattr(sys.stdout,"buffer",sys.stdout)
    saved=None
    if stdin is not None and os.isatty(stdin):
        import termios,tty
        saved=termios.tcgetattr(stdin); tty.setraw(stdin)
        def resized(*_):
            s=terminal_size()
            try: ws.send(json.dumps({"type":"resize","rows":s.lines,"cols":s.columns}))
            except Exception: pass
        signal.signal(signal.SIGWINCH,resized)
    def pump_stdin():
        while True:
            data=os.read(stdin,4096)
            if not data: break
            try: ws.send(data)
            except Exception: break
    if stdin is not None: threading.Thread(target=pump_stdin,daemon=True).start()
    code=None
    try:
        for msg in ws:
            if isinstance(msg,bytes): out.write(msg); out.flush()
            else:
                ctl=json.loads(msg)
                if ctl.get("type")=="exit": code=int(ctl.get("code",1))
    except Exception as e:  # dropped connection, revoked session, orchestrator restart
        if code is None: click.echo(f"\r\n[company-agent] connection lost: {e}",err=True)
    finally:
        if saved is not None:
            import termios
            termios.tcsetattr(stdin,termios.TCSADRAIN,saved)
        ws.close()
    if code is None: click.echo("\r\n[company-agent] session ended by the server",err=True)
    return 1 if code is None else code

def run(agent,environment):
    launch=request_launch(agent,environment,load_token())
    click.echo(f"[company-agent] sandbox {launch['sandbox_name']} (policy v{launch['policy_version']})",err=True)
    return attach(launch)

@cli.command()
@click.option("--environment",default="development")
def claude(environment):
    """Run Claude Code in a managed sandbox."""
    sys.exit(run("claude",environment))

@cli.command()
@click.option("--environment",default="development")
def codex(environment):
    """Run Codex in a managed sandbox."""
    sys.exit(run("codex",environment))

main=cli
if __name__=="__main__": cli()
