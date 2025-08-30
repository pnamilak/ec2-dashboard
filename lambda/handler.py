import os, json, time, base64, hmac, hashlib
import boto3

REGION            = os.environ.get("REGION", "us-east-2")
OTP_TABLE         = os.environ.get("OTP_TABLE")
SES_SENDER        = os.environ.get("SES_SENDER")
ALLOWED_DOMAIN    = os.environ.get("ALLOWED_DOMAIN", "gmail.com")
PARAM_USER_PREFIX = os.environ.get("PARAM_USER_PREFIX")              # "/<project>/users"
JWT_PARAM         = os.environ.get("JWT_PARAM")                      # "/<project>/jwt_secret"
ENV_NAMES         = [e for e in os.environ.get("ENV_NAMES","").split(",") if e]

ssm      = boto3.client("ssm", region_name=REGION)
ec2      = boto3.client("ec2", region_name=REGION)
ses      = boto3.client("ses", region_name=REGION)
dynamodb = boto3.resource("dynamodb", region_name=REGION)

# ---------------- JWT (minimal) ----------------
def _b64url(x: bytes) -> str:
    return base64.urlsafe_b64encode(x).rstrip(b"=").decode()

def _b64url_json(obj) -> str:
    return _b64url(json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode())

def _sign(msg: bytes, secret: bytes) -> str:
    return _b64url(hmac.new(secret, msg, hashlib.sha256).digest())

def make_jwt(payload: dict) -> str:
    secret = ssm.get_parameter(Name=JWT_PARAM, WithDecryption=True)["Parameter"]["Value"].encode()
    header = {"alg": "HS256", "typ": "JWT"}
    p1 = _b64url_json(header)
    p2 = _b64url_json(payload)
    sig = _sign(f"{p1}.{p2}".encode(), secret)
    return f"{p1}.{p2}.{sig}"

# ---------------- helpers ----------------
def ok(body):    return {"statusCode": 200, "headers":{"content-type":"application/json"}, "body": json.dumps(body)}
def bad(msg):    return {"statusCode": 400, "headers":{"content-type":"application/json"}, "body": json.dumps({"error": msg})}
def denied(msg): return {"statusCode": 401, "headers":{"content-type":"application/json"}, "body": json.dumps({"error": msg})}

def _json_or_default(s, default):
    try:
        return json.loads(s) if s else default
    except Exception:
        return default

def run_ps(instance_id: str, commands: list[str], timeout_sec: int = 120):
    """Run PowerShell via SSM and return (success, stdout_str, stderr_str)."""
    resp = ssm.send_command(
        DocumentName="AWS-RunPowerShellScript",
        InstanceIds=[instance_id],
        Parameters={"commands": commands},
    )
    cmd_id = resp["Command"]["CommandId"]
    t0 = time.time()
    while True:
        inv = ssm.get_command_invocation(CommandId=cmd_id, InstanceId=instance_id)
        st = inv.get("Status")
        if st in ("Success","Cancelled","TimedOut","Failed"):
            return (st=="Success",
                    inv.get("StandardOutputContent","") or "",
                    inv.get("StandardErrorContent","") or "")
        if time.time() - t0 > timeout_sec:
            return (False, "", "timeout")
        time.sleep(2)

def _infer_kind(name: str) -> str:
    n = (name or "").lower()
    if "sql"   in n: return "sql"
    if "redis" in n: return "redis"
    if "web" in n or "svc" in n: return "web"
    return "generic"

# ---------------- routes ----------------
def route_request_otp(body):
    email = (body.get("email") or "").strip()
    if not email or not email.lower().endswith("@"+ALLOWED_DOMAIN.lower()):
        return bad("Email must be @"+ALLOWED_DOMAIN)
    code = str(time.time_ns())[-6:]  # simple demo 6-digit code
    tbl = dynamodb.Table(OTP_TABLE)
    ttl = int(time.time()) + 300
    tbl.put_item(Item={"email": email, "code": code, "expiresAt": ttl})
    ses.send_email(
        Source=SES_SENDER,
        Destination={"ToAddresses":[email]},
        Message={"Subject":{"Data":"Your OTP"},
                 "Body":{"Text":{"Data": f"Your EC2 Dashboard OTP is: {code} (valid 5 minutes)"}}}
    )
    return ok({"message":"otp sent"})

def route_verify_otp(body):
    email = (body.get("email") or "").strip()
    code  = (body.get("code") or "").strip()
    if not email or not code: return bad("Missing email/code")
    it = dynamodb.Table(OTP_TABLE).get_item(Key={"email": email}).get("Item")
    if not it or it.get("code") != code: return bad("Invalid OTP")
    return ok({"message":"verified"})

def route_login(body):
    username = (body.get("username") or "").strip()
    password = (body.get("password") or "").strip()
    if not username or not password: return bad("Missing credentials")
    try:
        p = ssm.get_parameter(Name=f"{PARAM_USER_PREFIX}/{username}", WithDecryption=True)["Parameter"]["Value"]
    except ssm.exceptions.ParameterNotFound:
        return denied("User not provisioned in Parameter Store")
    parts = [x.strip() for x in p.split(",")]
    if len(parts) < 2:  return denied("User record invalid")
    pw, role = parts[0], parts[1]
    email = parts[2] if len(parts) > 2 else ""
    name  = parts[3] if len(parts) > 3 else username
    if password != pw:  return denied("Invalid username/password")

    token = make_jwt({"sub": username, "role": role, "iat": int(time.time())})
    return ok({"token": token, "role": role, "user": {"username": username, "email": email, "name": name, "role": role}})

def route_instances(_authz):
    # list all visible instances; group by env tokens
    resp = ec2.describe_instances()
    items = []
    for r in resp.get("Reservations", []):
        for i in r.get("Instances", []):
            state = i.get("State",{}).get("Name")
            iid = i.get("InstanceId")
            name = ""
            for t in i.get("Tags",[]):
                if t["Key"]=="Name": name = t["Value"]; break
            if not name: 
                continue
            items.append({"id": iid, "name": name, "state": state})

    envs = {e: {"DM": [], "EA": []} for e in ENV_NAMES or []}
    for it in items:
        env = next((e for e in ENV_NAMES if e and e.lower() in it["name"].lower()), None) or (ENV_NAMES[0] if ENV_NAMES else "ENV")
        blk = "EA" if "ea" in it["name"].lower() else ("DM" if "dm" in it["name"].lower() else "DM")
        envs.setdefault(env, {"DM":[],"EA":[]})
        envs[env][blk].append(it)

    summary = {
        "total":   len(items),
        "running": sum(1 for x in items if x["state"]=="running"),
        "stopped": sum(1 for x in items if x["state"]=="stopped"),
    }
    return ok({"summary": summary, "envs": envs})

def route_instance_action(body):
    iid = body.get("id")
    action = body.get("action")
    if not iid or action not in ("start","stop"): return bad("Missing/invalid")
    if action=="start": ec2.start_instances(InstanceIds=[iid])
    else: ec2.stop_instances(InstanceIds=[iid])
    return ok({"message": f"{action} requested"})

# ---------- SERVICES ----------
def route_services(body):
    iid     = body.get("id")
    name    = body.get("name") or ""
    mode    = (body.get("mode") or "list").lower()
    svcname = (body.get("service") or "").strip()
    pattern = (body.get("pattern") or "").strip()
    if not iid: return bad("Missing instance id")

    kind = _infer_kind(name)

    # --- scripts ---
    if mode == "list":
        if kind == "sql":
            ps = r'''
$names = @('MSSQLSERVER','SQLSERVERAGENT')
try{
  $instKey = 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL'
  if(Test-Path $instKey){
    (Get-ItemProperty -Path $instKey).PSObject.Properties | ForEach-Object {
      $names += "MSSQL$" + $_.Name
      $names += "SQLAgent$" + $_.Name
    }
  }
}catch{}
Get-Service -Name $names -ErrorAction SilentlyContinue | Select Name,DisplayName,Status | ConvertTo-Json -Compress
'''
        elif kind == "redis":
            ps = r"Get-Service -Name 'redis*' -ErrorAction SilentlyContinue | Select Name,DisplayName,Status | ConvertTo-Json -Compress"
        else:
            # free-text filter by name/displayname (case-insensitive); empty = return nothing
            pat = pattern.replace('"','`"')
            ps = f'''
$pat = "{pat}"
if([string]::IsNullOrWhiteSpace($pat)){{ @() | ConvertTo-Json }} else {{
  $rx = "(?i)" + [regex]::Escape($pat)
  Get-Service | Where-Object {{ $_.Name -match $rx -or $_.DisplayName -match $rx }} |
    Select Name,DisplayName,Status | ConvertTo-Json -Compress
}}
'''
        ok_, out, err = run_ps(iid, [ps])
        services = _json_or_default(out, [])
        if not ok_:
            return bad(f"SSM error: {err or 'unknown'}")
        return ok({"kind": kind, "services": services})

    if mode in ("start","stop"):
        if not svcname: return bad("Missing service")
        ps = f'''
try {{
  {"Start-Service" if mode=="start" else "Stop-Service -Force -ErrorAction SilentlyContinue"} -Name "{svcname}"
  Start-Sleep -Seconds 1
}} catch {{}}
Get-Service -Name "{svcname}" -ErrorAction SilentlyContinue | Select Name,DisplayName,Status | ConvertTo-Json -Compress
'''
        ok_, out, err = run_ps(iid, [ps])
        if not ok_:
            return bad(f"SSM error: {err or 'unknown'}")
        return ok({"services": _json_or_default(out, [])})

    if mode == "iisreset":
        ps = r'''
try{ iisreset /restart | Out-Null } catch {}
Get-Service W3SVC,WAS -ErrorAction SilentlyContinue | Select Name,DisplayName,Status | ConvertTo-Json -Compress
'''
        ok_, out, err = run_ps(iid, [ps], timeout_sec=180)
        if not ok_:
            return bad(f"SSM error: {err or 'unknown'}")
        return ok({"services": _json_or_default(out, [])})

    return bad("Unknown mode")

# -------------- Lambda entry --------------
def lambda_handler(event, context):
    route = (event.get("rawPath") or "").lower()
    method = (event.get("requestContext",{}).get("http",{}).get("method") or "GET").upper()
    body = _json_or_default(event.get("body"), {})

    if route == "/request-otp" and method=="POST":  return route_request_otp(body)
    if route == "/verify-otp"  and method=="POST":  return route_verify_otp(body)
    if route == "/login"       and method=="POST":  return route_login(body)

    # protected routes (authorizer supplies context)
    if route == "/instances" and method=="GET":
        return route_instances(event.get("requestContext",{}).get("authorizer"))
    if route == "/instance-action" and method=="POST":
        return route_instance_action(body)
    if route == "/services" and method=="POST":
        return route_services(body)

    return {"statusCode":404, "headers":{"content-type":"text/plain"}, "body":"not found"}
