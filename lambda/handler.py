import os, json, time, base64, hmac, hashlib
import boto3
from botocore.exceptions import ClientError

REGION = os.environ.get("REGION", "us-east-2")
OTP_TABLE = os.environ.get("OTP_TABLE")
SES_SENDER = os.environ.get("SES_SENDER")
ALLOWED_DOMAIN = os.environ.get("ALLOWED_DOMAIN", "gmail.com")
PARAM_USER_PREFIX = os.environ.get("PARAM_USER_PREFIX")
JWT_PARAM = os.environ.get("JWT_PARAM")
ENV_NAMES = os.environ.get("ENV_NAMES","").split(",")

ssm = boto3.client("ssm", region_name=REGION)
ec2 = boto3.client("ec2", region_name=REGION)
ses = boto3.client("ses", region_name=REGION)
dynamodb = boto3.resource("dynamodb", region_name=REGION)

# ---------------- JWT minimal ----------------
def _b64url(x: bytes) -> str:
    return base64.urlsafe_b64encode(x).rstrip(b"=").decode()

def _b64url_json(obj) -> str:
    return _b64url(json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode())

def _sign(msg: bytes, secret: bytes) -> str:
    return _b64url(hmac.new(secret, msg, hashlib.sha256).digest())

def _jwt_secret() -> bytes:
    return ssm.get_parameter(Name=JWT_PARAM, WithDecryption=True)["Parameter"]["Value"].encode()

def make_jwt(payload: dict) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    p1 = _b64url_json(header)
    p2 = _b64url_json(payload)
    sig = _sign(f"{p1}.{p2}".encode(), _jwt_secret())
    return f"{p1}.{p2}.{sig}"

def parse_jwt(token: str) -> dict:
    try:
        p1, p2, sig = token.split(".")
        expect = _sign(f"{p1}.{p2}".encode(), _jwt_secret())
        if not hmac.compare_digest(expect, sig): return {}
        payload = json.loads(base64.urlsafe_b64decode(p2 + "=="))
        if "exp" in payload and int(time.time()) > int(payload["exp"]): return {}
        return payload
    except Exception:
        return {}

# ---------------- helpers ----------------
def ok(body):    return {"statusCode": 200, "headers":{"content-type":"application/json"}, "body": json.dumps(body)}
def bad(msg):    return {"statusCode": 400, "headers":{"content-type":"application/json"}, "body": json.dumps({"error": msg})}
def denied(msg): return {"statusCode": 401, "headers":{"content-type":"application/json"}, "body": json.dumps({"error": msg})}

def json_or_default(s, default):
    try:
        return json.loads(s) if s else default
    except Exception:
        return default

def map_ssm_error(inv: dict) -> str | None:
    """Return a short code for known SSM failures, else None."""
    st = inv.get("Status")
    stderr = (inv.get("StandardErrorContent") or "").lower()
    if st == "Success":
        return None
    if "targetnotconnected" in stderr:
        return "not_connected"
    if "accessdenied" in stderr or "access denied" in stderr:
        return "denied"
    if st == "TimedOut":
        return "timeout"
    if st in ("Cancelled","Failed"):
        return "failed"
    return "failed"

def run_ps(instance_id: str, commands: list[str], timeout_sec: int = 90) -> dict:
    """Run PowerShell via SSM and return the invocation dict (even on fail)."""
    try:
        resp = ssm.send_command(
            DocumentName="AWS-RunPowerShellScript",
            InstanceIds=[instance_id],
            Parameters={"commands": commands},
        )
        cmd_id = resp["Command"]["CommandId"]
    except ClientError as e:
        # Map common errors to our short codes
        msg = str(e).lower()
        if "targetnotconnected" in msg:
            return {"Status":"Failed","StandardErrorContent":"TargetNotConnected"}
        if "accessdenied" in msg:
            return {"Status":"Failed","StandardErrorContent":"AccessDenied"}
        return {"Status":"Failed","StandardErrorContent":str(e)}

    t0 = time.time()
    while True:
        try:
            inv = ssm.get_command_invocation(CommandId=cmd_id, InstanceId=instance_id)
        except ClientError as e:
            return {"Status":"Failed","StandardErrorContent":str(e)}

        st = inv.get("Status")
        if st in ("Success","Cancelled","TimedOut","Failed"):
            return inv
        if time.time() - t0 > timeout_sec:
            inv["Status"] = "TimedOut"
            return inv
        time.sleep(2)

# ---------------- routes: auth ----------------
def route_request_otp(body):
    email = body.get("email","").strip()
    if not email or not email.lower().endswith("@"+ALLOWED_DOMAIN.lower()):
        return bad("Email must be @"+ALLOWED_DOMAIN)
    code = str(time.time_ns())[-6:]  # simple demo code
    ttl = int(time.time()) + 300
    dynamodb.Table(OTP_TABLE).put_item(Item={"email": email, "code": code, "expiresAt": ttl})
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
    it = dynamodb.Table(OTP_TABLE).get_item(Key={"email": email}).get("Item")
    if not it or it.get("code") != code:
        return bad("Invalid OTP")
    # short-lived OTP token (server-signed)
    now = int(time.time())
    otp_token = make_jwt({"typ":"otp","sub":email,"iat":now,"exp": now + 600})
    return ok({"message":"verified","otp_token": otp_token})

def route_login(body):
    username = body.get("username","").strip()
    password = body.get("password","").strip()
    otp_token = body.get("otp_token","").strip()

    if not username or not password:
        return bad("Missing credentials")

    # Require a valid OTP token first
    otp = parse_jwt(otp_token) if otp_token else {}
    if not otp or otp.get("typ") != "otp":
        return denied("OTP required")

    # VERY simple demo auth from SSM param: value format "password,role,email,name"
    try:
        p = ssm.get_parameter(Name=f"{PARAM_USER_PREFIX}/{username}", WithDecryption=True)["Parameter"]["Value"]
    except ClientError:
        return denied("User not provisioned")

    parts = [x.strip() for x in p.split(",")]
    if len(parts) < 2:
        return denied("User not provisioned")
    pw, role = parts[0], parts[1]
    email = parts[2] if len(parts) > 2 else ""
    name  = parts[3] if len(parts) > 3 else username

    # optional: bind OTP email to user record when available
    if email and otp.get("sub"):
        # enforce that OTP email domain matches the stored email domain (same org)
        try:
            if email.split("@",1)[1].lower() != otp["sub"].split("@",1)[1].lower():
                return denied("OTP email mismatch")
        except Exception:
            pass

    if password != pw:
        return denied("Invalid username/password")

    token = make_jwt({"sub": username, "role": role, "iat": int(time.time())})
    return ok({"token": token, "role": role, "user": {"username": username, "email": email, "name": name, "role": role}})

# ---------------- routes: EC2 & SSM ----------------
def route_instances(_authz):
    resp = ec2.describe_instances()
    items = []
    for r in resp.get("Reservations", []):
        for i in r.get("Instances", []):
            state = i.get("State",{}).get("Name")
            iid = i.get("InstanceId")
            name = ""
            for t in i.get("Tags",[]):
                if t["Key"]=="Name":
                    name = t["Value"]; break
            if not name: 
                name = iid
            items.append({"id": iid, "name": name, "state": state})

    envs = {e: {"DM": [], "EA": []} for e in ENV_NAMES if e}
    for it in items:
        env = next((e for e in ENV_NAMES if e and e.lower() in it["name"].lower()), None) or (ENV_NAMES[0] if ENV_NAMES else "ENV")
        blk = "EA" if "ea" in it["name"].lower() else ("DM")
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
    if not iid or action not in ("start","stop"):
        return bad("Missing/invalid")
    if action=="start":
        ec2.start_instances(InstanceIds=[iid])
    else:
        ec2.stop_instances(InstanceIds=[iid])
    return ok({"message": f"{action} requested"})

def route_services(body):
    iid = body.get("id")
    mode = body.get("mode","list")
    svc_kind = (body.get("svc_kind") or "web").lower()  # sql | redis | web
    pattern = (body.get("pattern") or "").strip()
    svc = (body.get("service") or "").strip()
    if not iid: 
        return bad("Missing instance id")

    if mode == "list":
        if svc_kind == "sql":
            ps = "Get-Service -Name 'MSSQL*','SQLAgent*' -ErrorAction SilentlyContinue | Select Name,Status | ConvertTo-Json -Compress"
        elif svc_kind == "redis":
            ps = "Get-Service -Name 'redis*' -ErrorAction SilentlyContinue | Select Name,Status | ConvertTo-Json -Compress"
        else:
            if pattern:
                ps = f"Get-Service -Name '*{pattern}*' -ErrorAction SilentlyContinue | Select Name,Status | ConvertTo-Json -Compress"
            else:
                ps = "Get-Service W3SVC,WAS -ErrorAction SilentlyContinue | Select Name,Status | ConvertTo-Json -Compress"

        inv = run_ps(iid, [ps])
        err = map_ssm_error(inv)
        if err:
            return ok({"error": err})
        services = json_or_default(inv.get("StandardOutputContent",""), [])
        return ok({"services": services})

    if mode in ("start","stop"):
        if not svc: return bad("Missing service")
        if mode=="start":
            ps = f'Start-Service -Name "{svc}"; Start-Sleep -Seconds 1; Get-Service -Name "{svc}" | Select Name,Status | ConvertTo-Json -Compress'
        else:
            ps = f'Stop-Service -Name "{svc}" -Force -ErrorAction SilentlyContinue; Start-Sleep -Seconds 1; Get-Service -Name "{svc}" | Select Name,Status | ConvertTo-Json -Compress'
        inv = run_ps(iid, [ps])
        err = map_ssm_error(inv)
        if err:
            return ok({"error": err})
        services = json_or_default(inv.get("StandardOutputContent",""), [])
        return ok({"services": services})

    if mode == "iisreset":
        cmds = [
            'iisreset /restart',
            'Get-Service W3SVC,WAS -ErrorAction SilentlyContinue | Select Name,Status | ConvertTo-Json -Compress'
        ]
        inv = run_ps(iid, cmds)
        err = map_ssm_error(inv)
        if err:
            return ok({"error": err})
        services = json_or_default(inv.get("StandardOutputContent",""), [])
        return ok({"services": services})

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
        inv = run_ps(iid, [ps])
        err = map_ssm_error(inv)
        if err:
            return ok({"error": err})
        data = json_or_default(inv.get("StandardOutputContent",""), {})
        return ok({"services": data.get("Services",[]) , "os": data.get("OS", {}), "sql": data.get("SQL", [])})

    return bad("Unknown mode")

# -------------- Lambda entry --------------
def lambda_handler(event, context):
    route = (event.get("rawPath") or "").lower()
    method = (event.get("requestContext",{}).get("http",{}).get("method") or "GET").upper()
    body = json.loads(event.get("body") or "{}")

    if route == "/request-otp" and method=="POST":  return route_request_otp(body)
    if route == "/verify-otp"  and method=="POST":  return route_verify_otp(body)
    if route == "/login"       and method=="POST":  return route_login(body)

    if route == "/instances" and method=="GET":     return route_instances(event.get("requestContext",{}).get("authorizer"))
    if route == "/instance-action" and method=="POST": return route_instance_action(body)
    if route == "/services" and method=="POST":     return route_services(body)

    return {"statusCode":404, "body":"not found"}
