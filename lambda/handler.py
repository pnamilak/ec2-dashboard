import os, json, time, hmac, hashlib, base64, boto3, random, string
from typing import Optional, List, Dict
from datetime import datetime, timedelta, timezone

REGION = os.environ.get("REGION", "us-east-1")
OTP_TABLE = os.environ["OTP_TABLE"]                 # DynamoDB table for OTP
SES_SENDER = os.environ["SES_SENDER"]               # verified SES sender
ALLOWED_DOMAIN = os.environ.get("ALLOWED_DOMAIN","gmail.com").lower()
PARAM_USER_PREFIX = os.environ["PARAM_USER_PREFIX"] # /<project>/users
JWT_PARAM = os.environ["JWT_PARAM"]                 # /<project>/jwt_secret
ENV_NAMES = [e for e in (os.environ.get("ENV_NAMES","").split(",")) if e]

ses = boto3.client("ses", region_name=REGION)
ddb = boto3.resource("dynamodb", region_name=REGION).Table(OTP_TABLE)
ssm = boto3.client("ssm", region_name=REGION)
ec2 = boto3.client("ec2", region_name=REGION)

# --------------------------- utilities ---------------------------

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")

def _b64url_json(obj: Dict) -> str:
    return _b64url(json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode())

def _jwt_sign(payload: Dict, secret: str, lifetime_hours: int = 8) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    now = int(time.time())
    payload = dict(payload)
    payload.update({"iat": now, "exp": now + lifetime_hours*3600})
    signing_input = ("%s.%s" % (_b64url_json(header), _b64url_json(payload))).encode()
    sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    return "%s.%s" % (signing_input.decode(), _b64url(sig))

def _jwt_verify(token: str, secret: str) -> Optional[Dict]:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        signing_input = ".".join(parts[:2]).encode()
        sig = base64.urlsafe_b64decode(parts[2] + "==")
        expected = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
        if not hmac.compare_digest(sig, expected):
            return None
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
        if "exp" in payload and time.time() > int(payload["exp"]):
            return None
        return payload
    except Exception:
        return None

def _respond(code: int, obj: Dict):
    return {
        "statusCode": code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "*",
            "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
        },
        "body": json.dumps(obj),
    }

def _otp() -> str:
    return "".join(random.choices(string.digits, k=6))

def _ssm_get_param(name: str) -> str:
    p = ssm.get_parameter(Name=name, WithDecryption=True)["Parameter"]["Value"]
    return p

def _send_ps(instance_id: str, lines: List[str], timeout_sec: int = 60):
    """Run PowerShell on instance via SSM and return (ok, stdout, stderr)."""
    resp = ssm.send_command(
        InstanceIds=[instance_id],
        DocumentName="AWS-RunPowerShellScript",
        Parameters={"commands": lines},
    )
    cmd_id = resp["Command"]["CommandId"]
    start = time.time()
    while True:
        inv = ssm.get_command_invocation(CommandId=cmd_id, InstanceId=instance_id)
        status = inv["Status"]
        if status in ("Success", "Cancelled", "TimedOut", "Failed"):
            return (status == "Success",
                    inv.get("StandardOutputContent", ""),
                    inv.get("StandardErrorContent", ""))
        if time.time() - start > timeout_sec:
            return (False, "", "Timeout waiting for SSM command (last: %s)" % status)
        time.sleep(1.2)

def _ps_json_block(ps: str) -> List[str]:
    return [ps, 'if ($?) { $result | ConvertTo-Json -Compress }']

def _ps_list_sql() -> List[str]:
    return _ps_json_block(r'''
$names = @("MSSQLSERVER","SQLSERVERAGENT")
$extra = Get-Service -Name "MSSQL*", "SQLAgent*" -ErrorAction SilentlyContinue
$base  = Get-Service -Name $names -ErrorAction SilentlyContinue
$result = @()
foreach($s in ($base + $extra | Sort-Object -Property Name -Unique)){
  $result += [PSCustomObject]@{ Name=$s.Name; Status="$($s.Status)" }
}
''')

def _ps_list_redis() -> List[str]:
    return _ps_json_block(r'''
$svcs = Get-Service -Name "Redis*" -ErrorAction SilentlyContinue
$result = @()
foreach($s in $svcs){
  $result += [PSCustomObject]@{ Name=$s.Name; Status="$($s.Status)" }
}
''')

def _ps_list_pattern(pattern: str) -> List[str]:
    # sanitize and safely inject into PowerShell without using f-strings
    pat = (pattern or "").replace("*", "").replace("?", "")
    ps_pat = pat.replace('"', '`"')  # escape double quotes for PowerShell

    # NOTE: double the braces {{ }} wherever PowerShell needs { } so that .format() doesn't eat them
    script = '''
$pat = "*{0}*"
$svcs = Get-Service -ErrorAction SilentlyContinue | Where-Object {{ $_.Name -like $pat -or $_.DisplayName -like $pat }}
$result = @()
foreach($s in $svcs){{
  $result += [PSCustomObject]@{{ Name=$s.Name; Status="$($s.Status)" }}
}}
'''.format(ps_pat)

    return _ps_json_block(script)


def _ps_iis_reset() -> List[str]:
    return ['iisreset /noforce']

# --------------------------- routes ---------------------------

def _route():
    return {
        ("POST", "/request-otp"): handle_request_otp,
        ("POST", "/verify-otp"):  handle_verify_otp,
        ("POST", "/login"):       handle_login,
        ("GET",  "/instances"):   auth_required(handle_instances),
        ("POST", "/instance-action"): auth_required(handle_instance_action),
        ("POST", "/services"):    auth_required(handle_services),
        ("OPTIONS", "/"): lambda e,_: _respond(200, {"ok": True})
    }

def auth_required(fn):
    def wrapper(event, ctx):
        headers = event.get("headers") or {}
        auth = headers.get("authorization") or headers.get("Authorization")
        if not auth or not auth.lower().startswith("bearer "):
            return _respond(401, {"error": "no_token"})
        token = auth.split(" ",1)[1]
        secret = _ssm_get_param(JWT_PARAM)
        payload = _jwt_verify(token, secret)
        if not payload:
            return _respond(401, {"error": "bad_token"})
        return fn(event, payload)
    return wrapper

# --------------------------- handlers ---------------------------

def handle_request_otp(event, _ctx):
    body = json.loads(event.get("body") or "{}")
    email = (body.get("email") or "").strip().lower()
    if not email or not email.endswith("@" + ALLOWED_DOMAIN):
        return _respond(400, {"error":"invalid_email"})
    code = _otp()
    # store with TTL 5 minutes
    ddb.put_item(Item={
        "email": email,
        "code": code,
        "expiresAt": int(time.time()) + 300
    })
    try:
        ses.send_email(
            Source=SES_SENDER,
            Destination={"ToAddresses":[email]},
            Message={
                "Subject":{"Data":"Your OTP for EC2 Dashboard"},
                "Body":{"Text":{"Data": "Your OTP is %s. It is valid for 5 minutes." % code}}
            },
        )
        return _respond(200, {"ok": True})
    except Exception as e:
        print("SES send failed:", repr(e))
        return _respond(500, {"error":"send_failed"})

def handle_verify_otp(event, _ctx):
    body = json.loads(event.get("body") or "{}")
    email = (body.get("email") or "").strip().lower()
    code  = (body.get("code") or "").strip()
    if not email or not code:
        return _respond(400, {"error":"missing"})
    item = ddb.get_item(Key={"email":email}).get("Item")
    if not item or item.get("code") != code or int(time.time()) > int(item.get("expiresAt",0)):
        return _respond(400, {"error":"invalid"})
    # one-time use
    ddb.delete_item(Key={"email":email})
    return _respond(200, {"ok": True})

def handle_login(event, _ctx):
    body = json.loads(event.get("body") or "{}")
    username = (body.get("username") or "").strip()
    password = (body.get("password") or "").strip()
    if not username or not password:
        return _respond(400, {"error":"missing"})
    try:
        param_name = "%s/%s" % (PARAM_USER_PREFIX, username)
        stored = _ssm_get_param(param_name)
    except Exception:
        return _respond(401, {"error":"invalid"})
    if stored != password:
        return _respond(401, {"error":"invalid"})
    secret = _ssm_get_param(JWT_PARAM)
    token = _jwt_sign({"sub": username}, secret, lifetime_hours=8)
    return _respond(200, {"token": token})

def handle_instances(event, user_ctx):
    # pull instances and group by env & block
    filters = [
        {"Name":"instance-state-name","Values":["pending","running","stopping","stopped"]},
    ]
    resp = ec2.describe_instances(Filters=filters)
    envs = {env: {"DM":[], "EA":[]} for env in ENV_NAMES}
    total=running=stopped=0
    for r in resp.get("Reservations",[]):
        for i in r.get("Instances",[]):
            name = next((t["Value"] for t in i.get("Tags",[]) if t["Key"]=="Name"), i.get("InstanceId"))
            env = None
            for e in ENV_NAMES:
                if e.lower() in name.lower():
                    env = e; break
            if not env:
                continue
            lname = name.lower()
            block = "DM" if "dm" in lname else ("EA" if "ea" in lname else "DM")
            state = i["State"]["Name"]
            entry = {"id": i["InstanceId"], "name": name, "state": state}
            envs[env][block].append(entry)
            total += 1
            if state=="running": running += 1
            if state=="stopped": stopped += 1
    return _respond(200, {"summary":{"total":total,"running":running,"stopped":stopped}, "envs": envs})

def handle_instance_action(event, user_ctx):
    body = json.loads(event.get("body") or "{}")
    id_ = body.get("id")
    action = (body.get("action") or "").lower()
    if id_ and action in ("start","stop"):
        if action=="start":
            ec2.start_instances(InstanceIds=[id_])
        else:
            ec2.stop_instances(InstanceIds=[id_])
        return _respond(200, {"ok": True})

    # group action: env + block
    env = body.get("env")
    block = body.get("block")  # "DM" or "EA"
    if env and block and action in ("start","stop"):
        resp = ec2.describe_instances(Filters=[{"Name":"instance-state-name","Values":["pending","running","stopping","stopped"]}])
        ids = []
        for r in resp.get("Reservations",[]):
            for i in r.get("Instances",[]):
                name = next((t["Value"] for t in i.get("Tags",[]) if t["Key"]=="Name"), "")
                lname = name.lower()
                if env.lower() in lname:
                    is_block = ("dm" in lname) if block=="DM" else ("ea" in lname)
                    if is_block:
                        ids.append(i["InstanceId"])
        if ids:
            if action=="start": ec2.start_instances(InstanceIds=ids)
            else: ec2.stop_instances(InstanceIds=ids)
        return _respond(200, {"ok": True, "count": len(ids)})

    return _respond(400, {"error":"bad_request"})

def handle_services(event, user_ctx):
    body = json.loads(event.get("body") or "{}")
    instance_id   = body.get("id")
    instance_name = (body.get("instanceName") or "").lower()
    mode          = (body.get("mode") or "list").lower()
    pattern       = (body.get("pattern") or "").strip()

    if not instance_id:
        return _respond(400, {"error":"missing_instance"})

    try:
        if mode == "iisreset":
            if ("svc" not in instance_name) and ("web" not in instance_name):
                return _respond(400, {"error":"not_web_svc"})
            ok, out, err = _send_ps(instance_id, _ps_iis_reset(), timeout_sec=120)
            return _respond(200 if ok else 500, {"message": "IIS reset executed" if ok else "IIS reset failed: %s" % err[:200]})

        if mode in ("start","stop"):
            svc_name = body.get("service")
            if not svc_name:
                return _respond(400, {"error":"missing_service"})
            action = "Start-Service" if mode=="start" else "Stop-Service"
            lines = ['%s -Name "%s" -ErrorAction Stop' % (action, svc_name), 'Write-Output "OK"']
            ok, out, err = _send_ps(instance_id, lines, timeout_sec=90)
            return _respond(200 if ok else 500, {"message": "%s %s: %s" % (mode, svc_name, ("OK" if ok else "FAILED")), "detail": ("" if ok else err[:300])})

        # list mode
        if "sql" in instance_name:
            ps = _ps_list_sql()
        elif "redis" in instance_name:
            ps = _ps_list_redis()
        else:
            ps = _ps_list_pattern(pattern or " ")
        ok, out, err = _send_ps(instance_id, ps, timeout_sec=90)
        services = []
        if ok and out.strip():
            try:
                data = json.loads(out)
                if isinstance(data, dict):
                    data = [data]
                for s in data:
                    if s:
                        services.append({"Name": s.get("Name"), "Status": s.get("Status")})
            except Exception:
                pass
        return _respond(200 if ok else 500, {"services": services, "message": ("" if ok else err[:300])})
    except Exception as e:
        print("services error:", repr(e))
        return _respond(500, {"error":"internal"})

# --------------------------- lambda entry ---------------------------

def lambda_handler(event, context):
    method = (event.get("requestContext",{}).get("http",{}).get("method") or event.get("httpMethod") or "GET").upper()
    path = (event.get("rawPath") or event.get("path") or "/").split("?")[0]
    key = (method, path)
    routes = _route()
    handler = routes.get(key)
    if handler:
        return handler(event, None)
    if method == "OPTIONS":
        return _respond(200, {"ok": True})
    return _respond(404, {"error": "not_found"})
