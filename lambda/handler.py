import os, json, time, base64, hmac, hashlib, logging, re
import boto3
from botocore.exceptions import ClientError

log = logging.getLogger()
log.setLevel(logging.INFO)

# ----------- ENV -----------
REGION            = os.environ.get("REGION", "us-east-2")
OTP_TABLE         = os.environ["OTP_TABLE"]
SES_SENDER        = os.environ["SES_SENDER"]
ALLOWED_DOMAIN    = os.environ.get("ALLOWED_DOMAIN", "gmail.com").lower()
PARAM_USER_PREFIX = os.environ.get("PARAM_USER_PREFIX", "/ec2-dashboard/users")
JWT_PARAM         = os.environ["JWT_PARAM"]
ENV_NAMES         = [x.strip() for x in os.environ.get("ENV_NAMES", "NAQA1,NAQA2,NAQA3,NAQA6,APQA1,EUQA1,Dev").split(",") if x.strip()]

ec2 = boto3.client("ec2", region_name=REGION)
ssm = boto3.client("ssm", region_name=REGION)
ses = boto3.client("ses", region_name=REGION)
ddb = boto3.resource("dynamodb", region_name=REGION)
table = ddb.Table(OTP_TABLE)
pssm = boto3.client("ssm", region_name=REGION)  # param store, send commands too

# ----------- JWT helpers -----------
def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")

def _jwt_for(sub: str, role: str, ttl_seconds: int = 3600) -> str:
    header  = _b64url(json.dumps({"alg":"HS256","typ":"JWT"}).encode())
    now     = int(time.time())
    payload = _b64url(json.dumps({"sub":sub,"role":role,"iat":now,"exp":now+ttl_seconds}).encode())
    secret  = pssm.get_parameter(Name=JWT_PARAM, WithDecryption=True)["Parameter"]["Value"].encode()
    sig     = _b64url(hmac.new(secret, f"{header}.{payload}".encode(), hashlib.sha256).digest())
    return f"{header}.{payload}.{sig}"

def _ok(body, code=200):    return {"statusCode": code, "headers":{"content-type":"application/json"}, "body": json.dumps(body)}
def _bad(code, msg):        return {"statusCode": code, "headers":{"content-type":"application/json"}, "body": json.dumps({"error": msg})}

# ----------- OTP -----------
def _otp_key(email): return f"otp:{email}"
def _ovt_key(tok):   return f"ovt:{tok}"

def request_otp(body):
    email = (body.get("email") or "").strip().lower()
    if not email or not email.endswith("@"+ALLOWED_DOMAIN):
        return _bad(400, f"only {ALLOWED_DOMAIN} allowed")

    code = f"{int(time.time()*1000)%1000000:06d}"
    ttl  = int(time.time()) + 10*60  # 10 min
    table.put_item(Item={"email":_otp_key(email), "code":code, "ttl":ttl})
    try:
        ses.send_email(
            Source=SES_SENDER,
            Destination={"ToAddresses":[email]},
            Message={
                "Subject":{"Data":"Your EC2 Dashboard OTP"},
                "Body":{"Text":{"Data":f"Your one-time code is {code}. It expires in 10 minutes."}}
            }
        )
    except ClientError as e:
        log.exception("SES send failed")
        return _bad(500, "otp_send_failed")
    return _ok({"sent": True})

def verify_otp(body):
    email = (body.get("email") or "").strip().lower()
    code  = (body.get("code") or "").strip()
    if not email or not code: return _bad(400,"missing_email_or_code")
    r = table.get_item(Key={"email":_otp_key(email)})
    it = r.get("Item")
    if not it or it.get("code") != code or int(time.time()) > int(it.get("ttl",0)):
        return _bad(400,"invalid_or_expired_otp")
    table.delete_item(Key={"email":_otp_key(email)})

    ovt = base64.urlsafe_b64encode(os.urandom(12)).decode().rstrip("=")
    table.put_item(Item={"email":_ovt_key(ovt), "addr":email, "ttl": int(time.time())+5*60})
    return _ok({"ovt": ovt})

def _consume_ovt(ovt: str) -> str|None:
    if not ovt: return None
    r = table.get_item(Key={"email":_ovt_key(ovt)})
    it = r.get("Item")
    if not it or int(time.time()) > int(it.get("ttl",0)): return None
    table.delete_item(Key={"email":_ovt_key(ovt)})
    return it.get("addr")

# ----------- Users (SSM Parameter Store) -----------
def _load_user(username: str):
    name = f"{PARAM_USER_PREFIX}/{username}"
    try:
        p = pssm.get_parameter(Name=name, WithDecryption=True)["Parameter"]["Value"]
    except pssm.exceptions.ParameterNotFound:
        return None
    # "password,role,email,name"
    parts = [x.strip() for x in p.split(",")]
    return {
        "password": parts[0] if len(parts)>0 else "",
        "role":     (parts[1].lower() if len(parts)>1 and parts[1] else "read"),
        "email":    (parts[2] if len(parts)>2 else ""),
        "name":     (parts[3] if len(parts)>3 else username)
    }

def login(body):
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""
    ovt      = body.get("ovt") or ""
    if not username or not password or not ovt:
        return _bad(400,"missing_fields")

    verified_email = _consume_ovt(ovt)
    if not verified_email:
        return _bad(400,"otp_not_verified")

    u = _load_user(username)
    if not u or u["password"] != password:
        return _bad(401,"invalid_credentials")

    token = _jwt_for(username, u["role"])
    return _ok({"token": token, "role": u["role"], "user": {"username":username, "name":u["name"], "email": u["email"]}})

# ----------- Auth (for protected routes) -----------
def _auth(event):
    h = event.get("headers") or {}
    auth = h.get("authorization") or h.get("Authorization") or ""
    if not auth.lower().startswith("bearer "): raise Exception("noauth")
    token = auth.split(" ",1)[1].strip()
    try:
        h64,p64,s64 = token.split(".")
        secret = pssm.get_parameter(Name=JWT_PARAM, WithDecryption=True)["Parameter"]["Value"].encode()
        expect = base64.urlsafe_b64encode(hmac.new(secret, f"{h64}.{p64}".encode(), hashlib.sha256).digest()).rstrip(b"=").decode()
        if expect != s64: raise Exception("sig")
        payload = json.loads(base64.urlsafe_b64decode(p64+"===").decode())
        if int(time.time()) >= int(payload.get("exp",0)): raise Exception("exp")
        return payload
    except Exception:
        raise

# ----------- EC2 helpers -----------
def _is_env(name: str) -> str|None:
    """Return env token if any of ENV_NAMES is contained in 'name'."""
    nl = name.upper()
    for e in ENV_NAMES:
        if e.upper() in nl:
            return e
    return None

def _block(name: str) -> str:
    up = name.upper()
    if "DM" in up: return "DM"
    if "EA" in up: return "EA"
    return "DM"

def instances(_event, _ctx):
    # find instances with a Name tag that includes any ENV token
    filters = [{"Name": "tag:Name", "Values": [f"*{e}*" for e in ENV_NAMES]}]
    r = ec2.describe_instances(Filters=filters)
    envs = {}
    total = running = stopped = 0
    for res in r.get("Reservations", []):
        for i in res.get("Instances", []):
            state = i.get("State",{}).get("Name")
            name = next((t["Value"] for t in i.get("Tags",[]) if t["Key"]=="Name"), i["InstanceId"])
            env  = _is_env(name) or "Other"
            blk  = _block(name)
            envs.setdefault(env, {"DM":[], "EA":[]})
            envs[env][blk].append({"id": i["InstanceId"], "name": name, "state": state})
            total += 1
            if state=="running": running+=1
            if state=="stopped": stopped+=1
    return _ok({"summary":{"total": total, "running": running, "stopped": stopped}, "envs": envs})

def instance_action(event, _ctx):
    b = json.loads(event.get("body") or "{}")
    iid = b.get("id")
    action = (b.get("action") or "").lower()
    if not iid or action not in ("start","stop"):
        return _bad(400,"bad_request")
    try:
        if action=="start": ec2.start_instances(InstanceIds=[iid])
        else: ec2.stop_instances(InstanceIds=[iid])
    except ClientError as e:
        return _bad(400, e.response.get("Error",{}).get("Message","ec2_error"))
    return _ok({"ok": True})

def bulk_action(event, _ctx):
    b = json.loads(event.get("body") or "{}")
    ids = b.get("ids") or []
    action = (b.get("action") or "").lower()
    if not ids or action not in ("start","stop"): return _bad(400,"bad_request")
    try:
        if action=="start": ec2.start_instances(InstanceIds=ids)
        else: ec2.stop_instances(InstanceIds=ids)
    except ClientError as e:
        return _bad(400, e.response.get("Error",{}).get("Message","ec2_error"))
    return _ok({"ok": True})

# ----------- SSM Services ----------
def _run_powershell(instance_id: str, script: str, timeout=120):
    cmd = ssm.send_command(
        InstanceIds=[instance_id],
        DocumentName="AWS-RunPowerShellScript",
        Parameters={"commands": [script]},
        CloudWatchOutputConfig={"CloudWatchLogGroupName":"__ec2_dashboard__", "CloudWatchOutputEnabled": False},
    )
    cid = cmd["Command"]["CommandId"]
    # poll
    for _ in range(int(timeout/2)):
        time.sleep(2)
        inv = ssm.get_command_invocation(CommandId=cid, InstanceId=instance_id)
        st = inv.get("Status")
        if st in ("Success","Failed","Cancelled","TimedOut"):
            out = (inv.get("StandardOutputContent") or "").strip()
            err = (inv.get("StandardErrorContent") or "").strip()
            return (st=="Success", out, err)
    return (False, "", "timeout")

def _json_services(out: str):
    if not out: return []
    try:
        data = json.loads(out)
        if isinstance(data, dict): data = [data]
        # normalize
        items=[]
        for s in data:
            items.append({
                "Name": s.get("Name") or "",
                "DisplayName": s.get("DisplayName") or "",
                "Status": s.get("Status") or s.get("State") or ""
            })
        return items
    except Exception:
        return []

def services(event, _ctx):
    b = json.loads(event.get("body") or "{}")
    iid   = b.get("id")
    mode  = (b.get("mode") or "list").lower()   # list|start|stop|iisreset
    name  = b.get("service") or ""
    inst_name = (b.get("instanceName") or "")
    pattern   = (b.get("pattern") or "").strip()
    typ = "generic"
    nm = inst_name.lower()
    if "sql" in nm:    typ = "sql"
    elif "redis" in nm: typ = "redis"
    elif re.search(r"\bsvc\b|\bweb\b", nm): typ = "svcweb"

    if not iid: return _bad(400,"missing_instance")

    if mode == "list":
        if typ == "sql":
            ps = r"""
$sv = Get-Service | Where-Object { $_.Name -match '^(MSSQL|SQLAgent|SQLBrowser|SQLWriter)' } |
  Select-Object Name,DisplayName,Status
$sv | ConvertTo-Json
""".strip()
            ok,out,err = _run_powershell(iid, ps)
            return _ok({"services": _json_services(out) if ok else [], "type": typ, "error": (None if ok else err)})

        if typ == "redis":
            ps = r"""
$sv = Get-Service | Where-Object { $_.Name -match 'redis' -or $_.DisplayName -match 'redis' } |
  Select-Object Name,DisplayName,Status
$sv | ConvertTo-Json
""".strip()
            ok,out,err = _run_powershell(iid, ps)
            return _ok({"services": _json_services(out) if ok else [], "type": typ, "error": (None if ok else err)})

        # SVC/WEB requires a pattern (2-5+ letters)
        if typ == "svcweb":
            if not pattern or len(pattern) < 2:
                return _ok({"services": [], "type": typ, "hint": "enter 2+ letters to filter"})
            # escape regex
            esc = re.sub(r"[^A-Za-z0-9_\-\.\s]", ".", pattern)
            ps = rf"""
$re = '{esc}'
$sv = Get-Service | Where-Object {{ $_.Name -match $re -or $_.DisplayName -match $re }} |
  Select-Object Name,DisplayName,Status
$sv | ConvertTo-Json
""".strip()
            ok,out,err = _run_powershell(iid, ps)
            return _ok({"services": _json_services(out) if ok else [], "type": typ, "error": (None if ok else err)})

        # generic / unknown
        return _ok({"services": [], "type": typ})

    if mode in ("start","stop"):
        if not name: return _bad(400,"service_required")
        action = "Start-Service" if mode=="start" else "Stop-Service"
        ps = rf"""
try {{
  {action} -Name '{name}' -ErrorAction Stop
}} catch {{}}
Get-Service -Name '{name}' | Select-Object Name,DisplayName,Status | ConvertTo-Json
""".strip()
        ok,out,err = _run_powershell(iid, ps)
        return _ok({"services": _json_services(out) if ok else [], "type": typ, "error": (None if ok else err)})

    if mode == "iisreset":
        if typ != "svcweb":
            return _bad(400,"iisreset_only_for_svcweb")
        ps = "iisreset /restart"
        ok,out,err = _run_powershell(iid, ps)
        return _ok({"ok": ok, "type": typ, "error": (None if ok else err)})

    return _bad(400,"bad_mode")

# ----------- Router -----------
def lambda_handler(event, ctx):
    path   = (event.get("rawPath") or event.get("path") or "").lower()
    method = (event.get("requestContext",{}).get("http",{}).get("method")
              or event.get("httpMethod") or "GET").upper()

    if method == "OPTIONS": return _ok({"ok": True})

    if path.endswith("/request-otp") and method=="POST": return request_otp(json.loads(event.get("body") or "{}"))
    if path.endswith("/verify-otp")  and method=="POST": return verify_otp(json.loads(event.get("body") or "{}"))
    if path.endswith("/login")       and method=="POST": return login(json.loads(event.get("body") or "{}"))

    try: _auth(event)
    except Exception:
        return _bad(401,"unauthorized")

    if path.endswith("/instances")       and method=="GET":  return instances(event, ctx)
    if path.endswith("/instance-action") and method=="POST": return instance_action(event, ctx)
    if path.endswith("/bulk-action")     and method=="POST": return bulk_action(event, ctx)
    if path.endswith("/services")        and method=="POST": return services(event, ctx)

    return _bad(404,"not_found")
