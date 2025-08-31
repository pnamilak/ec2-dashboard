import os
import json
import time
import uuid
import hmac
import base64
import hashlib
import boto3
from botocore.exceptions import ClientError

# -------------------------------------------------------------------
# Environment
# -------------------------------------------------------------------
REGION            = os.environ.get("REGION", "us-east-2")
OTP_TABLE         = os.environ["OTP_TABLE"]
SES_SENDER        = os.environ["SES_SENDER"]
ALLOWED_DOMAIN    = os.environ.get("ALLOWED_DOMAIN", "example.com")
PARAM_USER_PREFIX = os.environ["PARAM_USER_PREFIX"]              # e.g. /ec2-dashboard/users
JWT_PARAM         = os.environ["JWT_PARAM"]                      # e.g. /ec2-dashboard/jwt_secret
ENV_NAMES         = [e.strip() for e in (os.environ.get("ENV_NAMES") or "").split(",") if e.strip()]

ddb   = boto3.resource("dynamodb", region_name=REGION)
ses   = boto3.client("ses", region_name=REGION)
ssm   = boto3.client("ssm", region_name=REGION)
ec2   = boto3.client("ec2", region_name=REGION)
table = ddb.Table(OTP_TABLE)

# -------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------
_CORS_HEADERS = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "authorization,content-type",
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
}

def ok(body):
    return {"statusCode": 200, "headers": _CORS_HEADERS, "body": json.dumps(body)}

def bad(code, message):
    return {"statusCode": code, "headers": _CORS_HEADERS, "body": json.dumps({"error": message})}

def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")

def _jwt_for(username: str, role: str, ttl_seconds: int = 3600) -> str:
    header  = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    now     = int(time.time())
    payload = _b64url(json.dumps({"sub": username, "role": role, "iat": now, "exp": now + ttl_seconds}).encode())
    secret  = ssm.get_parameter(Name=JWT_PARAM, WithDecryption=True)["Parameter"]["Value"].encode()
    sig     = _b64url(hmac.new(secret, f"{header}.{payload}".encode(), hashlib.sha256).digest())
    return f"{header}.{payload}.{sig}"

def _read_user(username: str):
    """
    Reads /<prefix>/<username> from SSM Parameter Store.

    Supported value formats (backwards compatible):
      - "password|role"
      - "password,role,email,displayName"  (CSV)
    """
    name = f"{PARAM_USER_PREFIX.rstrip('/')}/{username}"
    raw  = ssm.get_parameter(Name=name, WithDecryption=True)["Parameter"]["Value"]
    if "|" in raw:
        parts = raw.split("|")
        pwd   = parts[0].strip()
        role  = (parts[1].strip().lower() if len(parts) > 1 else "read") or "read"
        email = ""
        disp  = username
    else:
        parts = [p.strip() for p in raw.split(",")]
        pwd   = parts[0] if len(parts) > 0 else ""
        role  = (parts[1].lower() if len(parts) > 1 and parts[1] else "read")
        email = parts[2] if len(parts) > 2 else ""
        disp  = parts[3] if len(parts) > 3 else username

    return {"password": pwd, "role": role or "read", "email": email, "display": disp}

# -------------------------------------------------------------------
# OTP
# -------------------------------------------------------------------
def request_otp(data):
    email = (data.get("email") or "").strip().lower()
    if not email or not email.endswith(f"@{ALLOWED_DOMAIN}"):
        return bad(403, "not_allowed_domain")

    code = str(uuid.uuid4().int)[-6:]
    ttl  = int(time.time()) + 300  # 5 min

    table.put_item(Item={"email": email, "code": code, "expiresAt": ttl})

    ses.send_email(
        Source=SES_SENDER,
        Destination={"ToAddresses": [email]},
        Message={
            "Subject": {"Data": "Your EC2 Dashboard OTP"},
            "Body": {"Text": {"Data": f"Your OTP code is {code}. It expires in 5 minutes."}},
        },
    )
    return ok({"ok": True})

def verify_otp(data):
    email = (data.get("email") or "").strip().lower()
    code  = (data.get("code") or "").strip()
    resp  = table.get_item(Key={"email": email})
    item  = resp.get("Item")
    if not item or item.get("code") != code or int(time.time()) > int(item.get("expiresAt", 0)):
        return bad(401, "invalid_otp")
    # one-time: remove after use
    table.delete_item(Key={"email": email})
    # the frontend stores this email in localStorage and forwards it to /login
    return ok({"ok": True})

# -------------------------------------------------------------------
# Auth helpers
# -------------------------------------------------------------------
def _auth(event):
    # Basic bearer presence check only; API Gateway Lambda Authorizer verifies signature/exp.
    hdrs = event.get("headers") or {}
    auth = hdrs.get("authorization") or hdrs.get("Authorization") or ""
    if not auth.lower().startswith("bearer "):
        raise Exception("no_token")
    return True

# -------------------------------------------------------------------
# EC2 / SSM
# -------------------------------------------------------------------
def instances(event, _):
    """
    Robust instance lister.

    - If ENV_NAMES is empty, create a single "All" env and show everything.
    - If an instance name doesn't match any env token, it appears under "Unassigned".
    - Dream Mapper vs Encore Anywhere buckets decided by a simple name heuristic.
    """
    resp = ec2.describe_instances(Filters=[{"Name": "instance-state-name", "Values": ["running", "stopped"]}])

    env_names = ENV_NAMES[:] if ENV_NAMES else ["All"]
    envs = {e: {"DM": [], "EA": []} for e in env_names}
    # spillover
    if "Unassigned" not in envs:
        envs["Unassigned"] = {"DM": [], "EA": []}

    summary = {"total": 0, "running": 0, "stopped": 0}

    for res in resp.get("Reservations", []):
        for inst in res.get("Instances", []):
            state = inst["State"]["Name"]
            name  = next((t["Value"] for t in inst.get("Tags", []) if t["Key"] == "Name"), "") or inst["InstanceId"]
            lname = name.lower()

            # map env
            env = None
            for e in env_names:
                if e.lower() in lname:
                    env = e
                    break
            if env is None:
                env = "Unassigned"

            # bucket heuristic
            bucket = "EA"
            if any(x in lname for x in ["dmsql", "dmsvc", "dmweb", "dream", "sql"]):
                bucket = "DM"

            envs.setdefault(env, {"DM": [], "EA": []})
            envs[env][bucket].append({"id": inst["InstanceId"], "name": name, "state": state})

            summary["total"] += 1
            if state == "running":
                summary["running"] += 1
            elif state == "stopped":
                summary["stopped"] += 1

    return ok({"summary": summary, "envs": envs})

def instance_action(event, _):
    body = json.loads(event.get("body") or "{}")
    iid  = body.get("id")
    act  = (body.get("action") or "").lower()
    if not iid or act not in ("start", "stop"):
        return bad(400, "bad_request")
    try:
        if act == "start":
            ec2.start_instances(InstanceIds=[iid])
        else:
            ec2.stop_instances(InstanceIds=[iid])
        return ok({"ok": True})
    except ClientError:
        return bad(500, "internal")

# ---------- SSM helpers ----------
def ssm_online(iid):
    try:
        r = ssm.describe_instance_information(Filters=[{"Key": "InstanceIds", "Values": [iid]}])
        info = (r.get("InstanceInformationList") or [])
        if not info:
            return False, "not_managed"
        return info[0].get("PingStatus") == "Online", info[0].get("PingStatus")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("AccessDenied", "AccessDeniedException"):
            return False, "denied"
        return False, "error"

POWERSHELL_LIST_SQL = r"""
$svcs = Get-Service | Where-Object { $_.Name -match '^MSSQL' -or $_.Name -match '^SQLSERVERAGENT' }
$svcs | Select-Object Name,DisplayName,Status | ConvertTo-Json
"""

POWERSHELL_LIST_GENERIC = r"""
param([string]$Pattern="")
if ($Pattern -eq "") { Write-Output "[]"; exit 0 }
$svcs = Get-Service | Where-Object { $_.Name -like "*$Pattern*" -or $_.DisplayName -like "*$Pattern*" }
$svcs | Select-Object Name,DisplayName,Status | ConvertTo-Json
"""

POWERSHELL_SVC = r"""
param([string]$Name,[string]$Mode)
if ($Mode -eq "start") { Start-Service -Name $Name -ErrorAction SilentlyContinue }
if ($Mode -eq "stop")  { Stop-Service -Name  $Name -Force -ErrorAction SilentlyContinue }
$svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
if ($null -eq $svc) { Write-Output "{}" } else { $svc | Select-Object Name,DisplayName,Status | ConvertTo-Json }
"""

POWERSHELL_IISRESET = r"iisreset /noforce | Out-Null; Write-Output '{""ok"":true}'"

def _run_ps(iid, script, timeout=30):
    try:
        sent = ssm.send_command(
            DocumentName="AWS-RunPowerShellScript",
            InstanceIds=[iid],
            Parameters={"commands": [script]},
        )
    except ClientError as e:
        code = e.response["Error"]["Code"]
        return None, ("denied" if code in ("AccessDenied", "AccessDeniedException") else "send_failed")

    cmd_id = sent["Command"]["CommandId"]
    t0 = time.time()
    while time.time() - t0 < timeout:
        inv = ssm.get_command_invocation(CommandId=cmd_id, InstanceId=iid)
        st = inv.get("Status")
        if st == "Success":
            return (inv.get("StandardOutputContent", "").strip() or "[]"), None
        if st in ("Cancelled", "TimedOut", "Failed"):
            return None, "invocation_" + st.lower()
        time.sleep(1)
    return None, "timeout"

def services(event, _):
    body = json.loads(event.get("body") or "{}")
    iid  = body.get("id")
    mode = (body.get("mode") or "list").lower()
    iname = (body.get("instanceName") or "").lower()

    if not iid:
        return ok({"error": "bad_request"})

    online, reason = ssm_online(iid)
    if not online:
        return ok({"error": ("denied" if reason == "denied" else "not_connected"), "reason": reason})

    if mode == "list":
        if "sql" in iname:
            out, err = _run_ps(iid, POWERSHELL_LIST_SQL)
        else:
            pattern = (body.get("pattern") or "").strip()
            scr = f'param([string]$Pattern="{pattern}");' + POWERSHELL_LIST_GENERIC.split("\n", 1)[1]
            out, err = _run_ps(iid, scr)
        if err:
            return ok({"error": err})
        try:
            svcs = json.loads(out or "[]")
            if isinstance(svcs, dict):
                svcs = [svcs]
        except Exception:
            svcs = []
        return ok({"services": svcs})

    if mode in ("start", "stop"):
        name = body.get("service")
        if not name:
            return ok({"error": "bad_request"})
        script = POWERSHELL_SVC.replace('$Mode', f'"{mode}"').replace('$Name', f'"{name}"')
        out, err = _run_ps(iid, script)
        if err:
            return ok({"error": err})
        try:
            svc = json.loads(out or "{}")
        except Exception:
            svc = {}
        return ok({"service": svc})

    if mode == "iisreset":
        out, err = _run_ps(iid, POWERSHELL_IISRESET)
        if err:
            return ok({"error": err})
        return ok({"ok": True})

    return ok({"error": "bad_request"})

# -------------------------------------------------------------------
# Login
# -------------------------------------------------------------------
def login(data):
    """
    Body JSON:
      {
        "username": "...",
        "password": "...",
        "otp_email": "user@domain"   <-- required; must match the user's email in SSM
      }
    """
    user = (data.get("username") or "").strip()
    pwd  = (data.get("password") or "")
    otp_email = (data.get("otp_email") or "").strip().lower()

    if not user or not pwd:
        return bad(400, "missing_credentials")
    if not otp_email:
        # frontend should forward verified email from /verify-otp
        return bad(401, "missing_verified_otp")

    try:
        rec = _read_user(user)  # {password, role, email, display}
    except Exception:
        return bad(401, "invalid_user")

    if rec.get("password") != pwd:
        return bad(401, "invalid_password")

    # Enforce OTP email match when user has an email set in SSM
    uemail = (rec.get("email") or "").strip().lower()
    if uemail and otp_email != uemail:
        return bad(401, "otp_email_mismatch")

    role  = rec.get("role") or "read"
    token = _jwt_for(user, role, ttl_seconds=3600)

    return {
        "statusCode": 200,
        "headers": _CORS_HEADERS,
        "body": json.dumps({
            "token": token,
            "role": role,
            "user": {"username": user, "role": role, "name": rec.get("display") or user}
        }),
    }

# -------------------------------------------------------------------
# Router
# -------------------------------------------------------------------
def lambda_handler(event, ctx):
    method = (event.get("requestContext", {}).get("http", {}).get("method")
              or event.get("httpMethod") or "GET").upper()
    path = (event.get("rawPath") or event.get("path") or "/").lower()

    # Basic CORS preflight
    if method == "OPTIONS":
        return ok({"ok": True})

    # Public endpoints
    if path.endswith("/request-otp") and method == "POST":
        return request_otp(json.loads(event.get("body") or "{}"))
    if path.endswith("/verify-otp") and method == "POST":
        return verify_otp(json.loads(event.get("body") or "{}"))
    if path.endswith("/login") and method == "POST":
        return login(json.loads(event.get("body") or "{}"))

    # Protected endpoints
    try:
        _auth(event)
    except Exception:
        return bad(401, "unauthorized")

    if path.endswith("/instances") and method == "GET":
        return instances(event, ctx)
    if path.endswith("/instance-action") and method == "POST":
        return instance_action(event, ctx)
    if path.endswith("/services") and method == "POST":
        return services(event, ctx)

    return bad(404, "not_found")
