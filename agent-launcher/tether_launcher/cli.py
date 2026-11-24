import base64,json,os,signal,ssl,subprocess,sys,threading,time,click,httpx
from pathlib import Path
HOME=Path.home()/".tether"; TOKEN_FILE=HOME/"token.json"
def user_config_path(): return HOME/"config.json"  # written by `tether setup`
# Deployed by MDM. When present it is authoritative: environment overrides are ignored so a
# user cannot point the signed launcher at a different orchestrator.
MANAGED_CONFIG=Path("/Library/Application Support/Tether/config.json"); MANAGED_OWNER_UID=0
ENV_KEYS={"orchestrator":"TETHER_ORCHESTRATOR","device_id":"TETHER_DEVICE_ID","oidc_issuer":"TETHER_OIDC_ISSUER",
          "oidc_client_id":"TETHER_OIDC_CLIENT_ID","client_cert":"TETHER_CLIENT_CERT","client_key":"TETHER_CLIENT_KEY",
          "ca_bundle":"TETHER_CA_BUNDLE","policy_api":"TETHER_POLICY_API","model":"TETHER_MODEL"}
DEFAULTS={"orchestrator":"http://localhost:8083","device_id":"local-dev"}

def managed_config():
    if not MANAGED_CONFIG.exists(): return None
    st=MANAGED_CONFIG.stat()
    # A managed file anyone could edit is worse than none: refuse to run.
    if st.st_uid!=MANAGED_OWNER_UID or st.st_mode&0o022:
        raise click.ClickException(f"{MANAGED_CONFIG} must be owned by root and not group/world-writable")
    return json.loads(MANAGED_CONFIG.read_text())

def user_config():
    try: return json.loads(user_config_path().read_text())
    except FileNotFoundError: return {}
    except ValueError: raise click.ClickException(f"{user_config_path()} is not valid JSON: run `tether setup` again")

def setting(key):
    """Managed (MDM) config wins outright; otherwise environment, then `tether setup`'s file, then defaults."""
    m=managed_config()
    if m is not None: return m.get(key,DEFAULTS.get(key))
    return os.getenv(ENV_KEYS[key]) or user_config().get(key) or DEFAULTS.get(key)

def tls_context():
    """Server trust (the company CA when given) plus the client certificate, for HTTPS and WebSocket alike.
    Built here rather than with httpx's cert=/verify=<path>: with a CA path httpx 0.28 drops the certificate."""
    ca=setting("ca_bundle"); cert=setting("client_cert")
    ctx=ssl.create_default_context(cafile=ca) if ca else ssl.create_default_context()
    if cert: ctx.load_cert_chain(cert,setting("client_key"))
    return ctx

def http(timeout=10):
    # mTLS client certificate identifies the person (no SSO) or the device behind an mTLS proxy.
    return httpx.Client(timeout=timeout,verify=tls_context())

def mtls_mode():
    """No SSO: the client certificate is the identity, exchanged for a short-lived token."""
    return not setting("oidc_issuer") and bool(setting("client_cert"))

def mtls_token():
    url=f"{setting('orchestrator').rstrip('/')}/v1/auth/token"
    try:
        with http() as c: r=c.post(url)
    except httpx.HTTPError as e: raise click.ClickException(f"cannot reach {url}: {e}")
    if r.status_code!=200: raise click.ClickException(f"certificate login refused ({r.status_code}): {r.text[:200]}")
    t=r.json(); save_token({"id_token":t["token"]},expires_at=t["expires_at"]); return t

# --- OIDC login (device authorization grant, RFC 8628) -----------------------

def oidc_config():
    issuer=setting("oidc_issuer"); client_id=setting("oidc_client_id")
    if not (issuer and client_id): raise click.ClickException("set TETHER_OIDC_ISSUER and TETHER_OIDC_CLIENT_ID")
    with http() as c: d=c.get(issuer.rstrip("/")+"/.well-known/openid-configuration").raise_for_status().json()
    return client_id,d

def jwt_exp(token):
    payload=token.split(".")[1]; payload+="="*(-len(payload)%4)
    return json.loads(base64.urlsafe_b64decode(payload))["exp"]

def save_token(t,expires_at=None):
    # The ID token is the API bearer (like kubectl's OIDC plugin); the API's audience is the client id.
    HOME.mkdir(parents=True,exist_ok=True,mode=0o700)
    data={"id_token":t["id_token"],"refresh_token":t.get("refresh_token"),"expires_at":expires_at or jwt_exp(t["id_token"])}
    fd=os.open(TOKEN_FILE,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
    with os.fdopen(fd,"w") as f: json.dump(data,f)
    os.chmod(TOKEN_FILE,0o600)  # O_CREAT mode does not apply to an existing file

def load_token():
    if os.getenv("TETHER_TOKEN") and managed_config() is None: return os.environ["TETHER_TOKEN"]
    if mtls_mode():
        # Certificate login is silent: fetch a fresh token whenever the stored one is missing or expiring.
        if TOKEN_FILE.exists():
            t=json.loads(TOKEN_FILE.read_text())
            if t["expires_at"]-60>time.time(): return t["id_token"]
        return mtls_token()["token"]
    if not TOKEN_FILE.exists(): raise click.ClickException("not logged in: run `tether login`")
    t=json.loads(TOKEN_FILE.read_text())
    if t["expires_at"]-60>time.time(): return t["id_token"]
    if not t.get("refresh_token"): raise click.ClickException("login expired: run `tether login`")
    client_id,d=oidc_config()
    with http() as c: r=c.post(d["token_endpoint"],data={"grant_type":"refresh_token","refresh_token":t["refresh_token"],"client_id":client_id})
    if r.status_code!=200 or "id_token" not in r.json(): raise click.ClickException("login expired: run `tether login`")
    # Keep the old refresh token if the IdP does not rotate it.
    new=r.json(); new.setdefault("refresh_token",t["refresh_token"]); save_token(new); return new["id_token"]

@click.group()
def cli(): pass

@cli.command()
def login():
    """Sign in with company SSO, or with your client certificate when there is no SSO."""
    if mtls_mode():
        t=mtls_token(); click.echo(f"Logged in as {t['user_id']} (client certificate)."); return
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

# --- setup ----------------------------------------------------------------------
# The administrator hands over one folder (infra/pki/tether-pki.sh user): cert.pem, key.pem,
# service-ca.crt and usually tether.json ({"server": ..., "model": ...}).

def write_private(path,data:bytes,mode):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,mode)
    with os.fdopen(fd,"wb") as f: f.write(data)
    os.chmod(path,mode)

@cli.command()
@click.argument("folder",type=click.Path(exists=True,file_okay=False,path_type=Path))
@click.option("--server",help="Server address, e.g. https://192.168.1.27 (default: tether.json in the folder).")
@click.option("--model",help="Default model for jobs (default: tether.json in the folder).")
def setup(folder,server,model):
    """Install the certificate folder your administrator gave you, then sign in."""
    if managed_config() is not None: raise click.ClickException("this Mac's settings are managed (MDM); ask your administrator")
    files={n:folder/n for n in ("cert.pem","key.pem","service-ca.crt")}
    missing=[n for n,f in files.items() if not f.is_file()]
    if missing: raise click.ClickException(f"{folder} is missing {', '.join(missing)}")
    given=json.loads((folder/"tether.json").read_text()) if (folder/"tether.json").is_file() else {}
    server=(server or given.get("server") or "").rstrip("/"); model=model or given.get("model")
    if not server.startswith("https://"): raise click.ClickException("give --server https://<server address>")
    try:  # the key must belong to the certificate, and the CA must be a certificate
        ssl.create_default_context(cafile=str(files["service-ca.crt"])).load_cert_chain(str(files["cert.pem"]),str(files["key.pem"]))
    except (ssl.SSLError,OSError) as e: raise click.ClickException(f"the certificate files do not work together: {e}")
    HOME.mkdir(parents=True,exist_ok=True,mode=0o700); os.chmod(HOME,0o700)
    for n,f in files.items(): write_private(HOME/n,f.read_bytes(),0o600)
    cfg={"orchestrator":server,"client_cert":str(HOME/"cert.pem"),"client_key":str(HOME/"key.pem"),"ca_bundle":str(HOME/"service-ca.crt")}
    if model: cfg["model"]=model
    write_private(user_config_path(),json.dumps(cfg,indent=2).encode(),0o600)
    TOKEN_FILE.unlink(missing_ok=True)  # a token from an earlier identity must not outlive it
    overridden=[v for k,v in ENV_KEYS.items() if k in cfg and os.getenv(v)]
    if overridden: click.echo(f"note: {', '.join(overridden)} in your environment override these settings",err=True)
    click.echo(f"Settings saved to {user_config_path()}. The folder {folder} can now be deleted.")
    t=mtls_token(); click.echo(f"Logged in as {t['user_id']} (client certificate).")

# --- agent launch -------------------------------------------------------------
# The launcher is only a terminal. The orchestrator creates the session, obtains credentials,
# builds the sandbox on the managed gateway and relays the terminal; this machine never holds
# a session token, gateway credentials or cloud/GitHub credentials.

def git_remote():
    try: subprocess.check_output(["git","rev-parse","--show-toplevel"],text=True,stderr=subprocess.DEVNULL)
    except (subprocess.CalledProcessError,FileNotFoundError): raise click.ClickException("run tether inside a Git repository")
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
    return connect(url,ssl=tls_context() if url.startswith("wss://") else None,max_size=None,open_timeout=30)

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
        if code is None: click.echo(f"\r\n[tether] connection lost: {e}",err=True)
    finally:
        if saved is not None:
            import termios
            termios.tcsetattr(stdin,termios.TCSADRAIN,saved)
        ws.close()
    if code is None: click.echo("\r\n[tether] session ended by the server",err=True)
    return 1 if code is None else code

def run(agent,environment):
    launch=request_launch(agent,environment,load_token())
    click.echo(f"[tether] sandbox {launch['sandbox_name']} (policy v{launch['policy_version']})",err=True)
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

# --- local-agent jobs ------------------------------------------------------------
# Jobs run the company's local model on a repository: request -> administrator approval -> run.
# The run happens on the server; what it produced (answer, log tail, patch) is fetched afterwards.
# Behind the mTLS front both APIs share one address; TETHER_POLICY_API is for setups where they don't.

def api(method,path,*,orchestrator=False,timeout=30,**kw):
    base=setting("orchestrator") if orchestrator else (setting("policy_api") or setting("orchestrator"))
    url=f"{base.rstrip('/')}{path}"
    try:
        with http(timeout=timeout) as c: r=c.request(method,url,headers={"Authorization":f"Bearer {load_token()}"},**kw)
    except httpx.HTTPError as e: raise click.ClickException(f"cannot reach {url}: {e}")
    if r.status_code>=400:
        detail=r.json().get("detail",r.text) if r.headers.get("content-type","").startswith("application/json") else r.text
        raise click.ClickException(f"{method} {path} refused ({r.status_code}): {detail}")
    return r.json()

def resolve_job(ref):
    """A full job id, or a unique prefix of one of the jobs you can see."""
    if len(ref)==36: return ref
    hits=[j for j in api("GET","/v1/agent/jobs")["jobs"] if j["id"].startswith(ref)]
    if len(hits)!=1: raise click.ClickException(f"{'no' if not hits else 'more than one'} job matches {ref!r}: see `tether job list`")
    return hits[0]["id"]

def read_task(task,task_file):
    if bool(task)==bool(task_file): raise click.ClickException("give the task with exactly one of --task or --task-file")
    if task: return task
    return sys.stdin.read() if task_file=="-" else Path(task_file).read_text()

def run_summary(r):
    if r["status"]!="finished": return r["status"]
    if r.get("timed_out"): return "timed out"
    return "ok" if r.get("returncode")==0 else f"failed (exit {r.get('returncode')})"

@cli.group()
def job():
    """Tasks for the company's local model: request, get approved, run, read the result."""

@job.command("request")
@click.option("--task",help="What the agent should do.")
@click.option("--task-file",type=click.Path(allow_dash=True),help="Read the task from a file (- for stdin).")
@click.option("--name",help="Short name (default: the first line of the task).")
@click.option("--repo",help="Repository URL (default: this checkout's origin).")
@click.option("--model",help="Model (default: TETHER_MODEL).")
@click.option("--every",type=int,help="Also run on a schedule, every N minutes.")
@click.option("--max-runtime",type=int,default=3600,show_default=True,help="Seconds before a run is stopped.")
def job_request(task,task_file,name,repo,model,every,max_runtime):
    """Ask for a job. An administrator approves it before it can run."""
    text=read_task(task,task_file)
    model=model or setting("model")
    if not model: raise click.ClickException("give --model (or set TETHER_MODEL)")
    name=name or (text.strip().splitlines() or ["job"])[0][:60]
    j=api("POST","/v1/agent/jobs",json={"name":name,"repo":repo or git_remote(),"model":model,"task":text,
                                         "interval_minutes":every,"max_runtime_seconds":max_runtime})
    click.echo(f"{j['id']}  {j['status']}  {j['name']}")
    click.echo("Waiting for an administrator's approval. Then: tether job run "+j["id"][:8],err=True)

@job.command("list")
@click.option("--status",type=click.Choice(["pending","approved","rejected","disabled"]))
def job_list(status):
    """Your jobs (administrators: everyone's)."""
    for j in api("GET","/v1/agent/jobs",params={"status":status} if status else None)["jobs"]:
        every=f"every {j['interval_minutes']}m" if j["interval_minutes"] else "manual"
        click.echo(f"{j['id'][:8]}  {j['status']:<8}  {j['owner']:<12}  {every:<10}  {j['name']}")

def decision(action):
    @click.argument("job_ref")
    @click.option("--reason",required=True,help="Recorded in the audit log.")
    def cmd(job_ref,reason):
        j=api("POST",f"/v1/admin/agent/jobs/{resolve_job(job_ref)}/{action}",json={"reason":reason})
        click.echo(f"{j['id'][:8]}  {j['status']}  {j['name']}")
    cmd.__doc__=f"{action.capitalize()} a job (administrators)."
    return job.command(action)(cmd)
for _a in ("approve","reject","disable"): decision(_a)

@job.command("show")
@click.argument("job_ref")
def job_show(job_ref):
    """A job's details, task and runs."""
    jid=resolve_job(job_ref)
    j=next((x for x in api("GET","/v1/agent/jobs")["jobs"] if x["id"]==jid),None)
    if j:
        for k in ("id","name","owner","status","repo","model","interval_minutes","max_runtime_seconds","decided_by","decision_reason"):
            click.echo(f"{k:<20}{j[k]}")
        click.echo("task:\n  "+j["task"].replace("\n","\n  "))
    runs=api("GET",f"/v1/agent/jobs/{jid}/runs")["runs"]
    click.echo("runs:" if runs else "runs: none")
    for r in runs: click.echo(f"  {r['session_id']}  {r['started_at'][:19]}  {r['trigger']:<8}  {run_summary(r)}")

def show_result(jid,sid,part):
    r=api("GET",f"/v1/agent/jobs/{jid}/runs/{sid}")
    if r["status"]!="finished":
        raise click.ClickException(f"run {sid} is {r['status']}" + ("" if r["status"]=="running" else " (no result was stored)"))
    note=" (truncated)" if r.get(f"{part}_truncated") else ""
    click.echo(f"[tether] run {sid}: {run_summary(r)}{note}",err=True)
    if r.get("error"): click.echo(f"[tether] {r['error']}",err=True)
    body=r.get(part)
    if body is None:
        click.echo(f"[tether] no {part}" + (" (removed after the retention period)" if r.get("purged") else ""),err=True)
    else:
        click.echo(body,nl=not body.endswith("\n"))
    return 0 if run_summary(r)=="ok" else 1

def part_option(f):
    f=click.option("--diff","part",flag_value="diff",help="Print the repository changes as a patch (for git apply).")(f)
    f=click.option("--log","part",flag_value="log",help="Print the end of the agent's log.")(f)
    return click.option("--output","part",flag_value="output",default=True,help="Print the agent's answer (default).")(f)

@job.command("run")
@click.argument("job_ref")
@click.option("--wait/--no-wait",default=True,show_default=True,help="Wait for the run and print its result.")
@part_option
def job_run(job_ref,wait,part):
    """Run an approved job now."""
    jid=resolve_job(job_ref)
    started=api("POST",f"/v1/jobs/{jid}/run",orchestrator=True,timeout=300)
    sid=started["session_id"]
    click.echo(f"[tether] started run {sid} in sandbox {started['sandbox_name']}",err=True)
    if not wait: return
    click.echo("[tether] waiting for it to finish (Ctrl-C stops waiting, not the run)",err=True)
    try:
        while True:
            r=next((x for x in api("GET",f"/v1/agent/jobs/{jid}/runs")["runs"] if x["session_id"]==sid),None)
            if r and r["status"]!="running": break
            time.sleep(POLL_SECONDS)
    except KeyboardInterrupt:
        click.echo(f"\n[tether] later: tether job result {jid[:8]} --run {sid}",err=True); sys.exit(130)
    sys.exit(show_result(jid,sid,part))

POLL_SECONDS=5

@job.command("result")
@click.argument("job_ref")
@click.option("--run","run_id",help="A run's session id (default: the latest finished run).")
@part_option
def job_result(job_ref,run_id,part):
    """What a run produced: the answer (default), --diff or --log."""
    jid=resolve_job(job_ref)
    if not run_id:
        done=[r for r in api("GET",f"/v1/agent/jobs/{jid}/runs")["runs"] if r["status"]=="finished"]
        if not done: raise click.ClickException("this job has no finished run yet")
        run_id=done[0]["session_id"]
    sys.exit(show_result(jid,run_id,part))

main=cli
if __name__=="__main__": cli()
