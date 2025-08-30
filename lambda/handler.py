# handler.py
import os, json, time, base64, hmac, hashlib
import boto3

# ----------- ENV -----------
REGION             = os.environ.get("REGION", "us-east-2")
OTP_TABLE          = os.environ.get("OTP_TABLE")
SES_SENDER         = os.environ.get("SES_SENDER")
ALLOWED_DOMAIN     = os.environ.get("ALLOWED_DOMAIN", "gmail.com")
PARAM_USER_PREFIX  = os.environ.get("PARAM_USER_PREFIX")
JWT_PARAM          = os.environ.get("JWT_PARAM")
ENV_NAMES          = [e for e in os.environ.get("ENV_NAMES", "").split(",") if e]

# ----------- AWS clients -----------
ssm       = boto3.client("ssm", region_name=REGION)
ec2       = boto3.client("ec2", region_name=REGION)
ses       = boto3.client("ses", region_name=REGION)
dynamodb  = boto3.resource("dynamodb", region_name=REGION)

# ===================== JWT (minimal, no deps) =====================
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

# ===================== Helpers =====================
def ok(body):    return {"statusCode": 200, "headers":{"content-type":"application/json"}, "body": json.dumps(body)}
def bad(msg):    return {"statusCode": 400, "headers":{"content-type":"application/json"}, "body": json.dumps({"error": msg})}
def denied(msg): return {"statusCode": 401, "headers":{"content-type":"application/json"}, "body": json.dumps({"error": msg})}

def json_or_default(s, default):
    try:
        return json.loads(s) if s else default
    except Exception:
        return default

def run_ps(instance_id: str, commands: list[str], timeout_sec: int = 90):
    """Run a PowerShell SSM doc and return the invocation dict (polls until terminal)."""
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
        if st in ("Success", "Cancelled", "TimedOut", "Failed"):
            return inv
        if time.time() - t0 > timeout_sec:
            # synthesize timeout result to surface nicely
            return {
                "Status": "TimedOut",
                "StatusDetails": "Client timeout polling get_command_invocation",
                "StandardOutputContent": "",
                "StandardErrorContent": "Client-side timeout"
            }
        time.sleep(2)

def ssm_or_502(inv):
    """If SSM invocation failed, return a 502 response for the UI; else None."""
    if inv.get("Status") != "Success":
        return {
            "statusCode": 502,
            "headers": {"content-type":"application/json"},
            "body": json.dumps({
                "error": f"SSM {inv.get('Status')}",
                "detail": inv.get("StandardErrorContent", "") or inv.get("StatusDetails", "")
            })
        }
    return None

# ===================== Routes =====================
def route_request_otp(body):
    email = body.get("email","").strip()
    if not email or not email.lower().endswith("@"+ALLOWED_DOMAIN.lower()):
        return bad("Email must be @"+ALLOWED_DOMAIN)

    code = str(time.time_ns())[-6:]  # demo OTP
    ttl  = int(time.time()) + 300

    dynamodb.Table(OTP_TABLE).put_item(Item={"email": email, "code": code, "expiresAt": ttl})

    # Send email (best-effort)
    try:
        ses.send_email(
            Source=SES_SENDER,
            Destination={"ToAddresses":[email]},
            Message={
                "Subject":{"Data":"Your OTP"},
                "Body":{"Text":{"Data": f"Your EC2 Dashboard OTP is: {code} (valid 5 minutes)"}}
            }
        )
    except Exception as e:
        # Still return success so users don't learn about SES config via UI
        print("SES send_email failed:", repr(e))

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
    if not username or not password:
        return bad("Missing credentials")

    # Param value format: "password,role,email,name"
    try:
        p = ssm.get_parameter(Name=f"{PARAM_USER_PREFIX}/{username}", WithDecryption=True)["Parameter"]["Value"]
    except Exception:
        return denied("User not provisioned")

    parts   = [x.strip() for x in p.split(",")]
    if len(parts) < 2:  # need at least password & role
        return denied("User not provisioned")

    pw, role = parts[0], parts[1]
    email    = parts[2] if len(parts) > 2 else ""
    name     = parts[3] if len(parts) > 3 else username

    if password != pw:
        return denied("Invalid username/password")

    token = make_jwt({"sub": username, "name": name, "role": role, "iat": int(time.time())})
    return ok({"token": token, "role": role, "user": {"username": username, "email": email, "name": name, "role": role}})

def route_instances(authz):
    # Describe and group by ENV token and DM/EA (simple name-based convention)
    paginator = ec2.get_paginator("describe_instances")
    items = []
    for page in paginator.paginate():
        for r in page.get("Reservations", []):
            for i in r.get("Instances", []):
                state = i.get("State",{}).get("Name")
                iid   = i.get("InstanceId")
                name  = next((t["Value"] for t in i.get("Tags",[]) if t.get("Key")=="Name"), "")
                if not name:
                    continue
                items.append({"id": iid, "name": name, "state": state})

    envs = {e: {"DM": [], "EA": []} for e in ENV_NAMES or ["ENV"]}
    for it in items:
        nm = it["name"].lower()
        env = next((e for e in ENV_NAMES if e and e.lower() in nm), (ENV_NAMES[0] if ENV_NAMES else "ENV"))
        blk = "DM" if "dm" in nm else ("EA" if "ea" in nm else "DM")
        envs.setdefault(env, {"DM": [], "EA": []})
        envs[env][blk].append(it)

    summary = {
        "total":   len(items),
        "running": sum(1 for x in items if x["state"]=="running"),
        "stopped": sum(1 for x in items if x["state"]=="stopped"),
    }
    return ok({"summary": summary, "envs": envs})

def route_instance_action(body):
    iid    = body.get("id")
    action = body.get("action")
    if not iid or action not in ("start","stop"):
        return bad("Missing/invalid")
    if action == "start":
        ec2.start_instances(InstanceIds=[iid])
    else:
        ec2.stop_instances(InstanceIds=[iid])
    return ok({"message": f"{action} requested"})

# -------------------- SERVICES --------------------
def route_services(body):
    iid     = body.get("id")
    mode    = (body.get("mode") or "list").strip().lower()
    pattern = (body.get("pattern") or "").strip()
    svc     = (body.get("service") or "").strip()
    if not iid:
        return bad("Missing instance id")

    # guard against quotes in user input to keep the PS command valid
    qpattern = pattern.replace('"', '`"')
    qsvc     = svc.replace('"', '`"')

    if mode == "list":
        # If a filter pattern is provided, search by that; otherwise show common WEB/SVC/IIS services.
        if qpattern:
            ps = f'Get-Service -Name "*{qpattern}*" -ErrorAction SilentlyContinue | Select Name,Status | ConvertTo-Json -Compress'
        else:
            ps = r'''Get-Service |
Where-Object { $_.Name -match '(?i)svc|web|w3svc|was|iis' -or $_.DisplayName -match '(?i)IIS|WWW|Web' } |
Select Name,Status | ConvertTo-Json -Compress'''
        inv = run_ps(iid, [ps])
        err = ssm_or_502(inv)
        if err: return err
        return ok({"services": json_or_default(inv.get("StandardOutputContent",""), [])})

    if mode in ("start","stop"):
        if not qsvc:
            return bad("Missing service")
        if mode == "start":
            ps = f'Start-Service -Name "{qsvc}"; Start-Sleep -Seconds 1; Get-Service -Name "{qsvc}" | Select Name,Status | ConvertTo-Json -Compress'
        else:
            ps = f'Stop-Service -Name "{qsvc}" -Force -ErrorAction SilentlyContinue; Start-Sleep -Seconds 1; Get-Service -Name "{qsvc}" | Select Name,Status | ConvertTo-Json -Compress'
        inv = run_ps(iid, [ps])
        err = ssm_or_502(inv)
        if err: return err
        return ok({"services": json_or_default(inv.get("StandardOutputContent",""), [])})

    if mode == "iisreset":
        cmds = [
            'iisreset /restart',
            'Get-Service W3SVC,WAS -ErrorAction SilentlyContinue | Select Name,Status | ConvertTo-Json -Compress'
        ]
        inv = run_ps(iid, cmds)
        err = ssm_or_502(inv)
        if err: return err
        return ok({"services": json_or_default(inv.get("StandardOutputContent",""), [])})

    if mode == "sqlinfo":
        # SQL services + OS + SQL build info (for SQL hosts)
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
          Instance   = $iname
          Version    = $cv.CurrentVersion
          PatchLevel = $cv.PatchLevel
        }
      }
    }
  }
}catch{}

$result = [pscustomobject]@{
  Services = $svcs
  OS       = $os
  SQL      = $items
}
$result | ConvertTo-Json -Compress -Depth 6
'''
        inv = run_ps(iid, [ps])
        err = ssm_or_502(inv)
        if err: return err
        data = json_or_default(inv.get("StandardOutputContent",""), {})
        return ok({
            "services": data.get("Services", []),
            "os":       data.get("OS", {}),
            "sql":      data.get("SQL", []),
        })

    return bad("Unknown mode")

# ===================== Lambda entry =====================
def lambda_handler(event, context):
    route  = (event.get("rawPath") or "").lower()
    method = (event.get("requestContext",{}).get("http",{}).get("method") or "GET").upper()
    body   = json.loads(event.get("body") or "{}")

    # Public
    if route == "/request-otp" and method == "POST": return route_request_otp(body)
    if route == "/verify-otp"  and method == "POST": return route_verify_otp(body)
    if route == "/login"       and method == "POST": return route_login(body)

    # Protected (API Gateway authorizer already ran)
    if route == "/instances"        and method == "GET":  return route_instances(event.get("requestContext",{}).get("authorizer"))
    if route == "/instance-action"  and method == "POST": return route_instance_action(body)
    if route == "/services"         and method == "POST": return route_services(body)

    return {"statusCode": 404, "body": "not found"}
