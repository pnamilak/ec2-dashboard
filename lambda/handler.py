import os, json, time, base64, hmac, hashlib
import boto3
from botocore.exceptions import ClientError

REGION = os.environ.get("REGION", "us-east-2")
OTP_TABLE = os.environ.get("OTP_TABLE")
SES_SENDER = os.environ.get("SES_SENDER")
ALLOWED_DOMAIN = os.environ.get("ALLOWED_DOMAIN", "gmail.com")
PARAM_USER_PREFIX = os.environ.get("PARAM_USER_PREFIX")
JWT_PARAM = os.environ.get("JWT_PARAM")
ENV_NAMES = [e for e in os.environ.get("ENV_NAMES","").split(",") if e]

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
def make_jwt(payload: dict) -> str:
    secret = ssm.get_parameter(Name=JWT_PARAM, WithDecryption=True)["Parameter"]["Value"].encode()
    header = {"alg":"HS256","typ":"JWT"}
    p1 = _b64url_json(header)
    p2 = _b64url_json(payload)
    sig = _sign(f"{p1}.{p2}".encode(), secret)
    return f"{p1}.{p2}.{sig}"

# ---------------- helpers ----------------
def ok(body):    return {"statusCode": 200, "headers":{"content-type":"application/json"}, "body": json.dumps(body)}
def bad(msg):    return {"statusCode": 400, "headers":{"content-type":"application/json"}, "body": json.dumps({"error": msg})}
def denied(msg): return {"statusCode": 401, "headers":{"content-type":"application/json"}, "body": json.dumps({"error": msg})}

def json_or_default(s, default):
    try:
        return json.loads(s) if s else default
    except Exception:
        return default

def run_ps(instance_id: str, commands: list[str], timeout_sec: int = 120, first_sleep: float = 1.0):
    """
    Run PowerShell via SSM and robustly poll for the invocation.
    Handles 'InvocationDoesNotExist' races by retrying until visible.
    """
    resp = ssm.send_command(
        DocumentName="AWS-RunPowerShellScript",
        InstanceIds=[instance_id],
        Parameters={"commands": commands},
    )
    cmd_id = resp["Command"]["CommandId"]

    # Give SSM a moment to materialize the invocation record
    time.sleep(first_sleep)

    t0 = time.time()
    while True:
        try:
            inv = ssm.get_command_invocation(CommandId=cmd_id, InstanceId=instance_id)
            st = inv.get("Status")
            if st in ("Success","Cancelled","TimedOut","Failed"):
                return inv
        except ClientError as e:
            code = e.response.get("Error",{}).get("Code")
            if code == "InvocationDoesNotExist":
                # race: keep polling until the record appears or timeout
                pass
            else:
                raise
        if (time.time() - t0) > timeout_sec:
            raise TimeoutError("SSM command timeout")
        time.sleep(2)

# ---------------- routes ----------------
def route_request_otp(body):
    email = body.get("email","").strip()
    if not email or not email.lower().endswith("@"+ALLOWED_DOMAIN.lower()):
        return bad("Email must be @"+ALLOWED_DOMAIN)
    code = str(time.time_ns())[-6:]
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
    return ok({"message":"verified"})

def route_login(body):
    username = body.get("username","").strip()
    password = body.get("password","").strip()
    if not username or not password: return bad("Missing credentials")

    # SSM value format: "password,role,email,name"
    p = ssm.get_parameter(Name=f"{PARAM_USER_PREFIX}/{username}", WithDecryption=True)["Parameter"]["Value"]
    parts = [x.strip() for x in p.split(",")]
    if len(parts) < 2: return denied("User not provisioned")
    pw, role = parts[0], parts[1]
    email = parts[2] if len(parts) > 2 else ""
    name  = parts[3] if len(parts) > 3 else username

    if password != pw: return denied("Invalid username/password")

    token = make_jwt({"sub": username, "role": role, "iat": int(time.time())})
    return ok({"token": token, "role": role, "user": {"username": username, "email": email, "name": name, "role": role}})

def route_instances(authz):
    # Simple discover + grouping by ENV token and block (DM/EA) inferred from name
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
            if not name: continue
            items.append({"id": iid, "name": name, "state": state})

    envs = {e: {"DM": [], "EA": []} for e in ENV_NAMES or ["ENV"]}
    for it in items:
        env = next((e for e in ENV_NAMES if e.lower() in it["name"].lower()), None) or (ENV_NAMES[0] if ENV_NAMES else "ENV")
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

def route_ssm_ping(body):
    iid = body.get("id")
    if not iid: return bad("Missing instance id")
    try:
        inv = run_ps(iid, [
            '$h = hostname',
            '$d = Get-Date -Format s',
            '[pscustomobject]@{ Host=$h; Time=$d } | ConvertTo-Json -Compress'
        ], first_sleep=1.2)
        data = json_or_default(inv.get("StandardOutputContent",""), {})
        return ok({"ping": data})
    except ClientError as e:
        return bad(f"SSM error: {e.response.get('Error',{}).get('Code','ClientError')}")
    except TimeoutError:
        return bad("SSM timeout")
    except Exception as e:
        return bad(f"SSM error: {str(e)}")

# ---------- SERVICES ----------
def route_services(body):
    iid = body.get("id")
    mode = (body.get("mode") or "list").lower()
    pattern = (body.get("pattern") or "").strip()
    svc = (body.get("service") or "").strip()
    if not iid: return bad("Missing instance id")

    try:
        if mode == "list":
            if pattern:
                ps = f'Get-Service -Name "*{pattern}*" -ErrorAction SilentlyContinue | Select Name,Status | ConvertTo-Json -Compress'
            else:
                ps = r'''Get-Service | Where-Object {
  $_.Name -match '(?i)svc|w3svc|was|wins|ssm|mssql|sqlagent|winrm' -or
  $_.DisplayName -match '(?i)IIS|WWW|Web|SQL|SSM|WinRM'
} | Select Name,Status | ConvertTo-Json -Compress'''
            inv = run_ps(iid, [ps])
            services = json_or_default(inv.get("StandardOutputContent",""), [])
            return ok({"services": services})

        if mode in ("start","stop"):
            if not svc: return bad("Missing service")
            if mode=="start":
                ps = f'Start-Service -Name "{svc}"; Start-Sleep -Seconds 1; Get-Service -Name "{svc}" | Select Name,Status | ConvertTo-Json -Compress'
            else:
                ps = f'Stop-Service -Name "{svc}" -Force -ErrorAction SilentlyContinue; Start-Sleep -Seconds 1; Get-Service -Name "{svc}" | Select Name,Status | ConvertTo-Json -Compress'
            inv = run_ps(iid, [ps])
            services = json_or_default(inv.get("StandardOutputContent",""), [])
            return ok({"services": services})

        if mode == "iisreset":
            cmds = [
                'iisreset /restart',
                'Start-Sleep -Seconds 2',
                'Get-Service W3SVC,WAS -ErrorAction SilentlyContinue | Select Name,Status | ConvertTo-Json -Compress'
            ]
            inv = run_ps(iid, cmds, timeout_sec=150)
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
        $items += [pscustomobject]@{ Instance=$iname; Version=$cv.CurrentVersion; PatchLevel=$cv.PatchLevel }
      }
    }
  }
}catch{}
[pscustomobject]@{ Services=$svcs; OS=$os; SQL=$items } | ConvertTo-Json -Compress -Depth 6
'''
            inv = run_ps(iid, [ps], first_sleep=1.2)
            data = json_or_default(inv.get("StandardOutputContent",""), {})
            return ok({
                "services": data.get("Services",[]),
                "os": data.get("OS", {}),
                "sql": data.get("SQL", []),
            })

        return bad("Unknown mode")

    except ClientError as e:
        code = e.response.get("Error",{}).get("Code", "ClientError")
        return bad(f"SSM error: {code}")
    except TimeoutError:
        return bad("SSM timeout")
    except Exception as e:
        return bad(f"SSM error: {str(e)}")

# -------------- Lambda entry --------------
def lambda_handler(event, context):
    route = (event.get("rawPath") or "").lower()
    method = (event.get("requestContext",{}).get("http",{}).get("method") or "GET").upper()
    try:
        body = json.loads(event.get("body") or "{}")
    except Exception:
        body = {}

    if route == "/request-otp" and method=="POST":  return route_request_otp(body)
    if route == "/verify-otp"  and method=="POST":  return route_verify_otp(body)
    if route == "/login"       and method=="POST":  return route_login(body)

    # protected
    if route == "/instances"        and method=="GET":  return route_instances(event.get("requestContext",{}).get("authorizer"))
    if route == "/instance-action"  and method=="POST": return route_instance_action(body)
    if route == "/services"         and method=="POST": return route_services(body)
    if route == "/ssm-ping"         and method=="POST": return route_ssm_ping(body)

    return {"statusCode":404, "body":"not found"}
