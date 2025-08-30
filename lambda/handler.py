import os, json, time, base64, hmac, hashlib, traceback
import boto3
from botocore.exceptions import ClientError

REGION = os.environ.get("REGION", "us-east-2")
OTP_TABLE = os.environ.get("OTP_TABLE")
SES_SENDER = os.environ.get("SES_SENDER")
ALLOWED_DOMAIN = os.environ.get("ALLOWED_DOMAIN", "gmail.com")
PARAM_USER_PREFIX = os.environ.get("PARAM_USER_PREFIX")
JWT_PARAM = os.environ.get("JWT_PARAM")
ENV_NAMES = [e for e in (os.environ.get("ENV_NAMES","").split(",")) if e]

ssm  = boto3.client("ssm",  region_name=REGION)
ec2  = boto3.client("ec2",  region_name=REGION)
ses  = boto3.client("ses",  region_name=REGION)
dyna = boto3.resource("dynamodb", region_name=REGION)

# ------------ helpers ------------
def ok(body):    return {"statusCode": 200, "headers":{"content-type":"application/json"}, "body": json.dumps(body)}
def bad(msg):    return {"statusCode": 400, "headers":{"content-type":"application/json"}, "body": json.dumps({"error": msg})}
def denied(msg): return {"statusCode": 401, "headers":{"content-type":"application/json"}, "body": json.dumps({"error": msg})}
def forbid(msg): return {"statusCode": 403, "headers":{"content-type":"application/json"}, "body": json.dumps({"error": msg})}

def _b64(x: bytes) -> str: return base64.urlsafe_b64encode(x).rstrip(b"=").decode()
def _b64j(obj) -> str:     return _b64(json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode())
def _sign(msg: bytes, secret: bytes) -> str: return _b64(hmac.new(secret, msg, hashlib.sha256).digest())

def make_jwt(payload: dict) -> str:
    secret = ssm.get_parameter(Name=JWT_PARAM, WithDecryption=True)["Parameter"]["Value"].encode()
    header = {"alg": "HS256", "typ": "JWT"}
    p1 = _b64j(header)
    p2 = _b64j(payload)
    sig = _sign(f"{p1}.{p2}".encode(), secret)
    return f"{p1}.{p2}.{sig}"

def json_or_default(s, default):
    try:
        return json.loads(s) if s else default
    except Exception:
        return default

def is_readonly(authz) -> bool:
    return str((authz or {}).get("role","user")).lower() != "admin"

# Unified SSM runner with crisp errors
def run_ps(instance_id: str, commands, timeout_sec: int = 90):
    try:
        resp = ssm.send_command(
            DocumentName="AWS-RunPowerShellScript",
            InstanceIds=[instance_id],
            Parameters={"commands": commands if isinstance(commands, list) else [commands]},
        )
    except ClientError as e:
        code = e.response.get("Error",{}).get("Code","ClientError")
        msg  = e.response.get("Error",{}).get("Message","")
        # Common SSM failures mapped to plain English
        if "TargetNotConnected" in msg or "is not connected" in msg:
            raise RuntimeError("SSM TargetNotConnected: agent not registered or no network route to SSM.")
        if code == "AccessDeniedException":
            raise RuntimeError("SSM access denied: check Lambda role permissions.")
        raise

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

# ------------ public routes ------------
def route_request_otp(body):
    email = body.get("email","").strip()
    if not email or not email.lower().endswith("@"+ALLOWED_DOMAIN.lower()):
        return bad("Email must be @"+ALLOWED_DOMAIN)
    code = str(time.time_ns())[-6:]  # demo only
    tbl = dyna.Table(OTP_TABLE)
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
    tbl = dyna.Table(OTP_TABLE)
    it = tbl.get_item(Key={"email": body.get("email","").strip()}).get("Item")
    if not it or it.get("code") != body.get("code","").strip(): return bad("Invalid OTP")
    return ok({"message":"verified"})

def route_login(body):
    username = body.get("username","").strip()
    password = body.get("password","").strip()
    if not username or not password: return bad("Missing credentials")
    try:
        raw = ssm.get_parameter(Name=f"{PARAM_USER_PREFIX}/{username}", WithDecryption=True)["Parameter"]["Value"]
    except ClientError:
        return denied("User not provisioned")
    parts = [x.strip() for x in raw.split(",")]
    if len(parts) < 2: return denied("User not provisioned")
    pw, role = parts[0], parts[1]
    email = parts[2] if len(parts)>2 else ""
    name  = parts[3] if len(parts)>3 else username
    if password != pw: return denied("Invalid username/password")

    token = make_jwt({"sub": username, "role": role, "name": name, "iat": int(time.time())})
    return ok({"token": token, "role": role, "user": {"username": username, "email": email, "name": name, "role": role}})

# ------------ protected routes ------------
def route_instances(authz):
    # describe + group by ENV_NAMES; DM if name has "dm", EA if "ea"
    items = []
    resp = ec2.describe_instances()
    for r in resp.get("Reservations", []):
        for i in r.get("Instances", []):
            name = next((t["Value"] for t in i.get("Tags",[]) if t["Key"]=="Name"), "")
            if not name: continue
            items.append({
                "id": i.get("InstanceId"),
                "name": name,
                "state": i.get("State",{}).get("Name")
            })

    envs = {e: {"DM": [], "EA": []} for e in ENV_NAMES or ["ENV"]}
    for it in items:
        env = next((e for e in ENV_NAMES if e.lower() in it["name"].lower()), (ENV_NAMES[0] if ENV_NAMES else "ENV"))
        blk = "EA" if "ea" in it["name"].lower() else "DM"
        envs.setdefault(env, {"DM":[], "EA":[]})
        envs[env][blk].append(it)

    summary = {
        "total":   len(items),
        "running": sum(1 for x in items if x["state"]=="running"),
        "stopped": sum(1 for x in items if x["state"]=="stopped"),
    }
    return ok({"summary": summary, "envs": envs})

def route_instance_action(authz, body):
    if is_readonly(authz):
        return forbid("Read-only role: not allowed to start/stop instances")
    iid = body.get("id"); action = body.get("action")
    if not iid or action not in ("start","stop"): return bad("Missing/invalid")
    if action=="start": ec2.start_instances(InstanceIds=[iid])
    else: ec2.stop_instances(InstanceIds=[iid])
    return ok({"message": f"{action} requested"})

def route_services(authz, body):
    iid = body.get("id"); mode = body.get("mode","list")
    pattern = (body.get("pattern") or "").strip()
    svc = (body.get("service") or "").strip()
    if not iid: return bad("Missing instance id")

    # safety: block mutations for read-only
    if mode in ("start","stop","iisreset") and is_readonly(authz):
        return forbid("Read-only role: not allowed to modify services")

    if mode == "list":
        if pattern:
            ps = f'Get-Service -Name "*{pattern}*" -ErrorAction SilentlyContinue | Select Name,Status | ConvertTo-Json -Compress'
        else:
            ps = r'''Get-Service | Where-Object { $_.Name -match '(?i)svc|web|w3svc|was|iis' -or $_.DisplayName -match '(?i)IIS|WWW|Web' } | Select Name,Status | ConvertTo-Json -Compress'''
        inv = run_ps(iid, ps)
        return ok({"services": json_or_default(inv.get("StandardOutputContent",""), [])})

    if mode in ("start","stop"):
        if not svc: return bad("Missing service")
        ps = (f'Start-Service -Name "{svc}"; Start-Sleep 1; '
              f'Get-Service -Name "{svc}" | Select Name,Status | ConvertTo-Json -Compress') if mode=="start" else \
             (f'Stop-Service -Name "{svc}" -Force -ErrorAction SilentlyContinue; Start-Sleep 1; '
              f'Get-Service -Name "{svc}" | Select Name,Status | ConvertTo-Json -Compress')
        inv = run_ps(iid, ps)
        return ok({"services": json_or_default(inv.get("StandardOutputContent",""), [])})

    if mode == "iisreset":
        inv = run_ps(iid, ['iisreset /restart',
                           'Get-Service W3SVC,WAS -ErrorAction SilentlyContinue | Select Name,Status | ConvertTo-Json -Compress'])
        return ok({"services": json_or_default(inv.get("StandardOutputContent",""), [])})

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
[pscustomobject]@{ Services=$svcs; OS=$os; SQL=$items } | ConvertTo-Json -Compress -Depth 6
'''
        inv = run_ps(iid, ps)
        data = json_or_default(inv.get("StandardOutputContent",""), {})
        return ok({"services": data.get("Services",[]), "os": data.get("OS",{}), "sql": data.get("SQL",[])})

    return bad("Unknown mode")

# ---- NEW: SSM simple diagnostic (POST /ssm-ping {id}) ----
def route_ssm_ping(authz, body):
    iid = body.get("id")
    if not iid: return bad("Missing instance id")
    try:
        inv = run_ps(iid, 'Write-Output "__OK__"; (Get-Service -Name AmazonSSMAgent -ErrorAction SilentlyContinue | Select Name,Status) | ConvertTo-Json -Compress')
        out = inv.get("StandardOutputContent","")
        err = inv.get("StandardErrorContent","")
        return ok({"status": inv.get("Status"), "stdout": out, "stderr": err})
    except Exception as e:
        return {"statusCode": 500, "headers":{"content-type":"application/json"},
                "body": json.dumps({"error": f"SSM ping failed: {type(e).__name__}: {str(e)}"})}

# ------------ entry ------------
def lambda_handler(event, context):
    try:
        route  = (event.get("rawPath") or "").lower()
        method = (event.get("requestContext",{}).get("http",{}).get("method") or "GET").upper()
        body   = json.loads(event.get("body") or "{}")
        authz  = event.get("requestContext",{}).get("authorizer") or {}

        # public
        if route=="/request-otp" and method=="POST": return route_request_otp(body)
        if route=="/verify-otp"  and method=="POST": return route_verify_otp(body)
        if route=="/login"       and method=="POST": return route_login(body)

        # protected
        if route=="/instances"        and method=="GET":  return route_instances(authz)
        if route=="/instance-action"  and method=="POST": return route_instance_action(authz, body)
        if route=="/services"         and method=="POST": return route_services(authz, body)
        if route=="/ssm-ping"         and method=="POST": return route_ssm_ping(authz, body)

        return {"statusCode":404, "body":"not found"}
    except Exception as e:
        # always log the stack for CloudWatch, but send a clear message to UI
        print("ERROR:", traceback.format_exc())
        return {"statusCode": 500, "headers":{"content-type":"application/json"},
                "body": json.dumps({"error": f"internal: {type(e).__name__}: {str(e)}"})}
