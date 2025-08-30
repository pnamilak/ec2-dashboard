import os, json, time, base64, hmac, hashlib
import boto3
from botocore.exceptions import ClientError

REGION = os.environ.get("REGION", "us-east-2")
OTP_TABLE = os.environ.get("OTP_TABLE")
SES_SENDER = os.environ.get("SES_SENDER")
ALLOWED_DOMAIN = os.environ.get("ALLOWED_DOMAIN", "gmail.com")
PARAM_USER_PREFIX = os.environ.get("PARAM_USER_PREFIX")
JWT_PARAM = os.environ.get("JWT_PARAM")
ENV_NAMES = [x for x in os.environ.get("ENV_NAMES", "").split(",") if x]

ssm = boto3.client("ssm", region_name=REGION)
ec2 = boto3.client("ec2", region_name=REGION)
ses = boto3.client("ses", region_name=REGION)
dynamodb = boto3.resource("dynamodb", region_name=REGION)

# ---------------- JWT minimal (no external libs) ----------------
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
def srv_err(msg):return {"statusCode": 500, "headers":{"content-type":"application/json"}, "body": json.dumps({"error": msg})}

def run_ps(instance_id: str, commands: list[str], timeout_sec: int = 90):
    """Run PowerShell via SSM and return the invocation dict. Raises on timeout."""
    try:
        resp = ssm.send_command(
            DocumentName="AWS-RunPowerShellScript",
            InstanceIds=[instance_id],
            Parameters={"commands": commands},
        )
    except ClientError as e:
        return {"Status":"ClientError", "StandardOutputContent":"", "StandardErrorContent":str(e)}
    cmd_id = resp["Command"]["CommandId"]

    t0 = time.time()
    while True:
        try:
            inv = ssm.get_command_invocation(CommandId=cmd_id, InstanceId=instance_id)
        except ClientError as e:
            return {"Status":"ClientError", "StandardOutputContent":"", "StandardErrorContent":str(e)}
        st = inv.get("Status")
        if st in ("Success","Cancelled","TimedOut","Failed","ClientError"):
            return inv
        if time.time() - t0 > timeout_sec:
            return {"Status":"TimedOut", "StandardOutputContent":"", "StandardErrorContent":"SSM command timed out"}
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
    code = str(time.time_ns())[-6:]  # demo code
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
    email = body.get("email","").strip()
    code  = body.get("code","").strip()
    tbl = dynamodb.Table(OTP_TABLE)
    it = tbl.get_item(Key={"email": email}).get("Item")
    if not it or it.get("code") != code: return bad("Invalid OTP")
    return ok({"message":"verified"})

def route_login(body):
    username = body.get("username","").strip()
    password = body.get("password","").strip()
    if not username or not password: return bad("Missing credentials")

    # value format "password,role,email,name"
    try:
        p = ssm.get_parameter(Name=f"{PARAM_USER_PREFIX}/{username}", WithDecryption=True)["Parameter"]["Value"]
    except ClientError:
        return denied("User not provisioned")
    parts = [x.strip() for x in p.split(",")]
    if len(parts) < 2: return denied("User not provisioned")
    pw, role = parts[0], parts[1].lower()
    email = parts[2] if len(parts) > 2 else ""
    name  = parts[3] if len(parts) > 3 else username

    if password != pw: return denied("Invalid username/password")

    token = make_jwt({"sub": username, "role": role, "iat": int(time.time())})
    return ok({"token": token, "role": role, "user": {"username": username, "email": email, "name": name, "role": role}})

def route_me(authz):
    # echo claims and expand user record (email/name) from SSM if present
    username = (authz or {}).get("sub")
    role     = (authz or {}).get("role", "read").lower()
    result = {"username": username, "role": role, "email":"", "name": username or ""}
    if username:
        try:
            p = ssm.get_parameter(Name=f"{PARAM_USER_PREFIX}/{username}", WithDecryption=True)["Parameter"]["Value"]
            parts = [x.strip() for x in p.split(",")]
            result["email"] = parts[2] if len(parts)>2 else ""
            result["name"]  = parts[3] if len(parts)>3 else (username or "")
        except ClientError:
            pass
    return ok({"user": result})

def route_instances(authz):
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

def route_instance_action(body, authz):
    # read-only users cannot start/stop
    role = (authz or {}).get("role","read").lower()
    if role != "admin":
        return denied("read-only role")
    iid = body.get("id")
    action = body.get("action")
    if not iid or action not in ("start","stop"): return bad("Missing/invalid")
    if action=="start": ec2.start_instances(InstanceIds=[iid])
    else: ec2.stop_instances(InstanceIds=[iid])
    return ok({"message": f"{action} requested"})

# ---------- SERVICES ----------
def route_services(body, authz):
    role = (authz or {}).get("role","read").lower()
    iid = body.get("id")
    mode = (body.get("mode") or "list").lower()
    pattern = (body.get("pattern") or "").strip()
    svc = (body.get("service") or "").strip()
    if not iid: return bad("Missing instance id")

    # common helper to run and normalize response & errors
    def _run(ps_list):
        inv = run_ps(iid, ps_list)
        if inv.get("Status") not in ("Success",):
            return {"error": inv.get("StandardErrorContent") or inv.get("Status") or "SSM unknown error"}
        return {"ok": True, "out": inv.get("StandardOutputContent","")}

    if mode == "list":
        if pattern:
            ps = f'Get-Service -Name "*{pattern}*" -ErrorAction SilentlyContinue | Select Name,Status | ConvertTo-Json -Compress'
        else:
            ps = r'''Get-Service | Where-Object { $_.Name -match '(?i)svc|web|w3svc|was|iis' -or $_.DisplayName -match '(?i)IIS|WWW|Web' } | Select Name,Status | ConvertTo-Json -Compress'''
        res = _run([ps])
        if "error" in res: return ok({"error": res["error"], "services":[]})
        return ok({"services": json_or_default(res["out"], [])})

    if mode in ("start","stop"):
        if role != "admin":
            return denied("read-only role")
        if not svc: return bad("Missing service")
        if mode=="start":
            ps = f'Start-Service -Name "{svc}"; Start-Sleep -Seconds 1; Get-Service -Name "{svc}" | Select Name,Status | ConvertTo-Json -Compress'
        else:
            ps = f'Stop-Service -Name "{svc}" -Force -ErrorAction SilentlyContinue; Start-Sleep -Seconds 1; Get-Service -Name "{svc}" | Select Name,Status | ConvertTo-Json -Compress'
        res = _run([ps])
        if "error" in res: return ok({"error": res["error"], "services":[]})
        return ok({"services": json_or_default(res["out"], [])})

    if mode == "iisreset":
        if role != "admin":
            return denied("read-only role")
        cmds = [
            'iisreset /restart',
            'Get-Service W3SVC,WAS -ErrorAction SilentlyContinue | Select Name,Status | ConvertTo-Json -Compress'
        ]
        res = _run(cmds)
        if "error" in res: return ok({"error": res["error"], "services":[]})
        return ok({"services": json_or_default(res["out"], [])})

    if mode == "sqlinfo":
        ps = r'''
$svcs = Get-Service -Name 'MSSQL*','SQLAgent*' -ErrorAction SilentlyContinue | Select Name,Status
$os = Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber

$items = @()
try{
  $instKey = 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL'
  if(Test-Path $instKey){
    $map = Get-ItemProperty -Path $instKey
    $map.PSObject.Properties | ForEach-Object {
      $iname = $_.Name
      $code = $_.Value
      $cvKey = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$code\MSSQLServer\CurrentVersion"
      $cv = Get-ItemProperty -Path $cvKey -ErrorAction SilentlyContinue
      if($cv){
        $items += [pscustomobject]@{
          Instance=$iname
          Version=$cv.CurrentVersion
          PatchLevel=$cv.PatchLevel
        }
      }
    }
  }
}catch{}

$result = [pscustomobject]@{
  Services=$svcs
  OS=$os
  SQL=$items
}
$result | ConvertTo-Json -Compress -Depth 6
'''
        res = _run([ps])
        if "error" in res: return ok({"error": res["error"], "services":[]})
        data = json_or_default(res["out"], {})
        return ok({
            "services": data.get("Services",[]),
            "os": data.get("OS", {}),
            "sql": data.get("SQL", []),
        })

    return bad("Unknown mode")

def route_ssm_ping(body):
    """Quick diag: ensure Systems Manager sees the instance (and agent online)."""
    iid = body.get("id")
    if not iid: return bad("Missing instance id")
    try:
        # 1) Describe in SSM inventory
        info = boto3.client("ssm", region_name=REGION).describe_instance_information(
            Filters=[{"Key":"InstanceIds","Values":[iid]}]
        )
        # 2) Run a tiny PowerShell echo to validate SendCommand path
        res = run_ps(iid, ["Write-Output 'hello-ssm'"])
        return ok({
            "ssmInfo": info.get("InstanceInformationList", []),
            "cmdStatus": res.get("Status"),
            "stderr": res.get("StandardErrorContent",""),
            "stdout": res.get("StandardOutputContent","")
        })
    except ClientError as e:
        return ok({"error": str(e)})

# -------------- Lambda entry --------------
def lambda_handler(event, context):
    route = (event.get("rawPath") or "").lower()
    method = (event.get("requestContext",{}).get("http",{}).get("method") or "GET").upper()
    body = json.loads(event.get("body") or "{}")
    authz = event.get("requestContext",{}).get("authorizer") or {}

    if route == "/request-otp" and method=="POST":  return route_request_otp(body)
    if route == "/verify-otp"  and method=="POST":  return route_verify_otp(body)
    if route == "/login"       and method=="POST":  return route_login(body)

    # protected
    if route == "/me"               and method=="GET":  return route_me(authz)
    if route == "/instances"        and method=="GET":  return route_instances(authz)
    if route == "/instance-action"  and method=="POST": return route_instance_action(body, authz)
    if route == "/services"         and method=="POST": return route_services(body, authz)
    if route == "/ssm-ping"         and method=="POST": return route_ssm_ping(body)

    return {"statusCode":404, "body":"not found"}
