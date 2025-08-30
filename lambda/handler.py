import os, json, time, base64, hmac, hashlib
import boto3
from botocore.exceptions import ClientError

REGION = os.environ.get("REGION", "us-east-2")
OTP_TABLE = os.environ.get("OTP_TABLE")
SES_SENDER = os.environ.get("SES_SENDER")
ALLOWED_DOMAIN = os.environ.get("ALLOWED_DOMAIN", "gmail.com")
PARAM_USER_PREFIX = os.environ.get("PARAM_USER_PREFIX")
JWT_PARAM = os.environ.get("JWT_PARAM")
ENV_NAMES = [e for e in (os.environ.get("ENV_NAMES","").split(",")) if e]

ssm = boto3.client("ssm", region_name=REGION)
ec2 = boto3.client("ec2", region_name=REGION)
ses = boto3.client("ses", region_name=REGION)
dynamodb = boto3.resource("dynamodb", region_name=REGION)

# ---------------- JWT minimal (HS256) ----------------
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

def _map_ssm_error(e: Exception) -> str:
    # normalize well-known SSM errors for UI
    if isinstance(e, ClientError):
        code = e.response.get("Error", {}).get("Code", "")
        msg  = e.response.get("Error", {}).get("Message", "")
        if "TargetNotConnected" in code or "TargetNotConnected" in msg:
            return "not_connected"
        if "AccessDenied" in code:
            return "denied"
    return "internal"

def run_ps(instance_id: str, commands: list[str], timeout_sec: int = 90):
    """Run PowerShell via SSM and return the invocation dict."""
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
            return inv
        if time.time() - t0 > timeout_sec:
            raise TimeoutError("SSM command timeout")
        time.sleep(2)

def json_or_default(s, default):
    try:
        return json.loads(s) if s else default
    except Exception:
        return default

# ---------------- routes ----------------
def route_request_otp(body):
    email = body.get("email","").strip()
    if not email or not email.lower().endswith("@"+ALLOWED_DOMAIN.lower()):
        return bad("Email must be @"+ALLOWED_DOMAIN)

    code = str(time.time_ns())[-6:]  # quick 6-digit code
    tbl = dynamodb.Table(OTP_TABLE)
    ttl = int(time.time()) + 300
    tbl.put_item(Item={"email": email, "code": code, "expiresAt": ttl})

    # send email (friendly error if SES blocks)
    try:
        ses.send_email(
            Source=SES_SENDER,
            Destination={"ToAddresses":[email]},
            Message={"Subject":{"Data":"Your OTP"},
                     "Body":{"Text":{"Data": f"Your EC2 Dashboard OTP is: {code} (valid 5 minutes)"}}}
        )
    except ClientError as e:
        msg = e.response.get("Error",{}).get("Message","SES send failed")
        return bad(f"SES: {msg}")

    return ok({"message":"otp sent"})

def route_verify_otp(body):
    email = body.get("email","").strip()
    code  = body.get("code","").strip()
    tbl = dynamodb.Table(OTP_TABLE)
    it = tbl.get_item(Key={"email": email}).get("Item")
    if not it or it.get("code") != code or int(time.time()) > int(it.get("expiresAt",0)):
        return bad("Invalid OTP")
    return ok({"message":"verified"})

def route_login(body):
    username = body.get("username","").strip()
    password = body.get("password","").strip()
    if not username or not password:
        return bad("Missing credentials")

    # VERY simple demo auth from SSM param: "password,role,email,name"
    try:
        p = ssm.get_parameter(Name=f"{PARAM_USER_PREFIX}/{username}", WithDecryption=True)["Parameter"]["Value"]
    except ClientError:
        return denied("User not provisioned")

    parts = [x.strip() for x in p.split(",")]
    if len(parts) < 2: return denied("User not provisioned")
    pw, role = parts[0], parts[1]
    email = parts[2] if len(parts) > 2 else ""
    name  = parts[3] if len(parts) > 3 else username

    if password != pw:
        return denied("Invalid username/password")

    token = make_jwt({"sub": username, "role": role, "iat": int(time.time())})
    return ok({"token": token, "role": role, "user": {"username": username, "email": email, "name": name, "role": role}})

def route_instances(_authz):
    # group by env token (ENV_NAMES) & DM/EA by simple naming convention
    resp = ec2.describe_instances()
    items = []
    for r in resp.get("Reservations", []):
        for i in r.get("Instances", []):
            state = i.get("State",{}).get("Name")
            iid = i.get("InstanceId")
            name = ""
            for t in i.get("Tags",[]):
                if t["Key"]=="Name": name = t["Value"]; break
            if not name: continue
            items.append({"id": iid, "name": name, "state": state})

    envs = {e: {"DM": [], "EA": []} for e in ENV_NAMES if e}
    for it in items:
        env = next((e for e in ENV_NAMES if e and e.lower() in it["name"].lower()), None) or (ENV_NAMES[0] if ENV_NAMES else "ENV")
        blk = "DM" if "dm" in it["name"].lower() else ("EA" if "ea" in it["name"].lower() else "DM")
        envs.setdefault(env, {"DM":[],"EA":[]})
        envs[env][blk].append(it)

    summary = {
        "total": len(items),
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
def _svc_rows_sql():
    # MSSQL default + named instances and agents
    names = [
        "MSSQLSERVER", "SQLSERVERAGENT",
        "MSSQL$*", "SQLAgent$*"
    ]
    vec = ",".join([f"'{n}'" for n in names])
    return rf"Get-Service -Name {vec} -ErrorAction SilentlyContinue | Select Name,DisplayName,Status | ConvertTo-Json -Compress"

def route_services(body):
    iid = (body.get("id") or "").strip()
    mode = (body.get("mode") or "list").strip()
    pattern = (body.get("pattern") or "").strip()
    svc = (body.get("service") or "").strip()
    instance_name = (body.get("instanceName") or "")
    if not iid: return bad("Missing instance id")

    try:
        if mode == "list":
            # SQL-only when instance name contains 'sql'
            if "sql" in instance_name.lower():
                ps = _svc_rows_sql()
            else:
                if pattern:
                    ps = f"Get-Service -Name \"*{pattern}*\" -ErrorAction SilentlyContinue | Select Name,DisplayName,Status | ConvertTo-Json -Compress"
                else:
                    # wait for user filter (return empty list)
                    return ok({"services": []})
            inv = run_ps(iid, [ps])
            services = json_or_default(inv.get("StandardOutputContent",""), [])
            return ok({"services": services})

        if mode in ("start","stop"):
            if not svc: return bad("Missing service")
            if mode=="start":
                ps = f'Start-Service -Name "{svc}"; Start-Sleep -Seconds 1; Get-Service -Name "{svc}" | Select Name,DisplayName,Status | ConvertTo-Json -Compress'
            else:
                ps = f'Stop-Service -Name "{svc}" -Force -ErrorAction SilentlyContinue; Start-Sleep -Seconds 1; Get-Service -Name "{svc}" | Select Name,DisplayName,Status | ConvertTo-Json -Compress'
            inv = run_ps(iid, [ps])
            services = json_or_default(inv.get("StandardOutputContent",""), [])
            return ok({"services": services})

        if mode == "iisreset":
            cmds = ['iisreset /restart']
            inv = run_ps(iid, cmds)
            return ok({"message":"iisreset requested"})

        return bad("Unknown mode")

    except Exception as e:
        return ok({"error": _map_ssm_error(e)})

# -------------- Lambda entry --------------
def lambda_handler(event, context):
    route = (event.get("rawPath") or "").lower()
    method = (event.get("requestContext",{}).get("http",{}).get("method") or "GET").upper()
    body = json.loads(event.get("body") or "{}")

    if route == "/request-otp" and method=="POST":  return route_request_otp(body)
    if route == "/verify-otp"  and method=="POST":  return route_verify_otp(body)
    if route == "/login"       and method=="POST":  return route_login(body)

    # protected
    if route == "/instances" and method=="GET":     return route_instances(event.get("requestContext",{}).get("authorizer"))
    if route == "/instance-action" and method=="POST": return route_instance_action(body)
    if route == "/services" and method=="POST":     return route_services(body)

    return {"statusCode":404, "body":"not found"}
