import os, json, time, boto3, base64, uuid, hmac, hashlib, re
from botocore.exceptions import ClientError

# ---------------- JWT utils ----------------
def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")

def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)

def _jwt_sign(claims: dict, ssm_client, jwt_param_name: str) -> str:
    header  = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64url(json.dumps(claims).encode())
    secret  = ssm_client.get_parameter(Name=jwt_param_name, WithDecryption=True)["Parameter"]["Value"].encode()
    sig     = _b64url(hmac.new(secret, f"{header}.{payload}".encode(), hashlib.sha256).digest())
    return f"{header}.{payload}.{sig}"

def _jwt_verify(token: str, ssm_client, jwt_param_name: str) -> dict:
    try:
        h, p, s = token.split(".")
    except Exception:
        raise ValueError("malformed_token")
    secret  = ssm_client.get_parameter(Name=jwt_param_name, WithDecryption=True)["Parameter"]["Value"].encode()
    exp_sig = _b64url(hmac.new(secret, f"{h}.{p}".encode(), hashlib.sha256).digest())
    if not hmac.compare_digest(exp_sig, s):
        raise ValueError("bad_signature")
    claims = json.loads(_b64url_decode(p).decode() or "{}")
    if int(time.time()) >= int(claims.get("exp", 0)):
        raise ValueError("token_expired")
    return claims

def _jwt_for(username: str, role: str, ssm_client, jwt_param_name: str, ttl_seconds: int = 3600) -> str:
    now = int(time.time())
    claims = {"sub": username, "role": role, "iat": now, "exp": now + ttl_seconds, "typ": "auth"}
    return _jwt_sign(claims, ssm_client, jwt_param_name)

# ---------------- Config / clients ----------------
REGION            = os.environ.get("REGION", "us-east-2")
OTP_TABLE         = os.environ["OTP_TABLE"]
SES_SENDER        = os.environ["SES_SENDER"]
ALLOWED_DOMAIN    = os.environ.get("ALLOWED_DOMAIN", "example.com")
PARAM_USER_PREFIX = os.environ["PARAM_USER_PREFIX"]   # e.g. /ec2-dashboard/users
JWT_PARAM         = os.environ["JWT_PARAM"]
ENV_NAMES         = [e.strip() for e in os.environ.get("ENV_NAMES","").split(",") if e.strip()]

ddb   = boto3.resource("dynamodb", region_name=REGION)
ses   = boto3.client("ses", region_name=REGION)
ssm   = boto3.client("ssm", region_name=REGION)
ec2   = boto3.client("ec2", region_name=REGION)
table = ddb.Table(OTP_TABLE)

def ok(b):  return {"statusCode":200,"headers":{"content-type":"application/json"},"body":json.dumps(b)}
def bad(c,m): return {"statusCode":c,"headers":{"content-type":"application/json"},"body":json.dumps({"error":m})}

# ---------------- OTP ----------------
def request_otp(data):
    email = (data.get("email") or "").strip().lower()
    if not email or not email.endswith("@"+ALLOWED_DOMAIN):
        return bad(403,"not_allowed_domain")
    code = str(uuid.uuid4().int)[-6:]
    table.put_item(Item={"email":email,"code":code,"expiresAt":int(time.time())+300})
    ses.send_email(
        Source=SES_SENDER,
        Destination={"ToAddresses":[email]},
        Message={"Subject":{"Data":"Your EC2 Dashboard OTP"},
                 "Body":{"Text":{"Data":f"Your OTP code is {code}. It expires in 5 minutes."}}}
    )
    return ok({"ok":True})

def verify_otp(data):
    email = (data.get("email") or "").strip().lower()
    code  = (data.get("code") or "").strip()
    r = table.get_item(Key={"email":email}); item = r.get("Item")
    if not item or item.get("code")!=code or int(time.time())>int(item.get("expiresAt",0)):
        return bad(401,"invalid_otp")
    table.delete_item(Key={"email":email})
    now = int(time.time())
    # short-lived OTP token (10 minutes)
    otp_token = _jwt_sign(
        {"typ":"otp","email":email,"iat":now,"exp": now+600, "jti": uuid.uuid4().hex},
        ssm, JWT_PARAM
    )
    return ok({"ok":True, "otp": otp_token})

# ---------------- Users in SSM ----------------
def _read_user(username: str):
    """
    Reads /<prefix>/<username> and parses multiple formats:
      - "password|role|email|Full Name"
      - "password,role,email,Full Name"
      - minimum: "password|role" or "password,role"
    """
    p = f"{PARAM_USER_PREFIX.rstrip('/')}/{username}"
    val = ssm.get_parameter(Name=p, WithDecryption=True)["Parameter"]["Value"]
    parts = re.split(r"[|,]", val)
    parts += ["", "", "", ""]                             # pad
    pwd   = (parts[0] or "").strip()
    role  = (parts[1] or "read").strip().lower()
    email = (parts[2] or "").strip().lower()
    name  = (parts[3] or username).strip()
    return {"password": pwd, "role": role or "read", "email": email, "name": name}

# ---------------- Login ----------------
def login(data):
    """
    Body JSON: { "username": "...", "password": "...", "otp": "<otp_jwt>" }
    Returns: { token, role, user: { username, role, name } }
    """
    u = (data.get("username") or "").strip()
    p = (data.get("password") or "")
    otp_token = (data.get("otp") or "").strip()

    if not u or not p:
        return bad(400, "missing_credentials")
    if not otp_token:
        return bad(400, "missing_verified_otp")

    try:
        user = _read_user(u)
    except Exception:
        return bad(401, "invalid_user")

    if user.get("password") != p:
        return bad(401, "invalid_password")

    # verify OTP token server-side
    try:
        claims = _jwt_verify(otp_token, ssm, JWT_PARAM)
        if claims.get("typ") != "otp":
            return bad(403, "invalid_otp_type")
        if user.get("email"):
            if (claims.get("email","").lower() != user["email"].lower()):
                return bad(403, "otp_email_mismatch")
    except ValueError as e:
        return bad(401, str(e))
    except Exception:
        return bad(401, "otp_invalid")

    role  = user.get("role") or "read"
    token = _jwt_for(u, role, ssm, JWT_PARAM, ttl_seconds=3600)
    body = {
        "token": token,
        "role": role,
        "user": {"username": u, "role": role, "name": user.get("name") or u}
    }
    return {
        "statusCode": 200,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "authorization,content-type",
            "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
        },
        "body": json.dumps(body),
    }

# ---------------- Auth helper ----------------
def _auth(event):
    h = event.get("headers",{}) or {}
    auth = h.get("authorization") or h.get("Authorization")
    if not auth or not auth.lower().startswith("bearer "):
        raise Exception("no_token")
    return True

# ---------------- EC2 + SSM (unchanged aside from cosmetic tidy) ----------------
def instances(event, _):
    r = ec2.describe_instances(Filters=[{"Name":"instance-state-name","Values":["running","stopped"]}])
    envs = {e:{"DM":[],"EA":[]} for e in ENV_NAMES}
    summary = {"total":0,"running":0,"stopped":0}
    for res in r.get("Reservations",[]):
        for i in res.get("Instances",[]):
            state=i["State"]["Name"]
            name=next((t["Value"] for t in i.get("Tags",[]) if t["Key"]=="Name"),"")
            if not name: continue
            env=None; lname=name.lower()
            for e in ENV_NAMES:
                if e.lower() in lname: env=e; break
            if not env: continue
            bucket="DM" if any(x in lname for x in ["dmsql","dmsvc","dmweb","dream","sql"]) else "EA"
            envs[env][bucket].append({"id":i["InstanceId"],"name":name,"state":state})
            summary["total"]  += 1
            summary["running"]+= 1 if state=="running" else 0
            summary["stopped"]+= 1 if state=="stopped" else 0
    return ok({"summary":summary,"envs":envs})

def ssm_online(instance_id):
    try:
        r = ssm.describe_instance_information(Filters=[{"Key":"InstanceIds","Values":[instance_id]}])
        items=r.get("InstanceInformationList",[])
        if not items: return False,"not_managed"
        ps=items[0].get("PingStatus","Unknown")
        return ps=="Online", ps
    except ClientError as e:
        if e.response["Error"]["Code"] in ("AccessDenied","AccessDeniedException"):
            return False,"denied"
        return False,"error"

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
if ($Mode -eq "stop")  { Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue }
$svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
if ($null -eq $svc) { Write-Output "{}" } else { $svc | Select-Object Name,DisplayName,Status | ConvertTo-Json }
"""
POWERSHELL_IISRESET = r"iisreset /noforce | Out-Null; Write-Output '{""ok"":true}'"

def _run_ps(instance_id, script, timeout=30):
    try:
        send = ssm.send_command(
            DocumentName="AWS-RunPowerShellScript",
            InstanceIds=[instance_id],
            Parameters={"commands":[script]},
        )
    except ClientError as e:
        code=e.response["Error"]["Code"]
        if code in ("AccessDenied","AccessDeniedException"): return None,"denied"
        return None,"send_failed"
    cmd_id=send["Command"]["CommandId"]
    t0=time.time()
    while time.time()-t0<timeout:
        r=ssm.get_command_invocation(CommandId=cmd_id, InstanceId=instance_id)
        st=r["Status"]
        if st=="Success": return (r.get("StandardOutputContent","").strip() or "[]"), None
        if st in ("Cancelled","TimedOut","Failed"): return None, "invocation_"+st.lower()
        time.sleep(1)
    return None,"timeout"

def services(event,_):
    body=json.loads(event.get("body") or "{}")
    iid=body.get("id"); mode=body.get("mode","list")
    iname=(body.get("instanceName") or "").lower()
    if not iid: return ok({"error":"bad_request"})
    online, reason = ssm_online(iid)
    if not online:
        return ok({"error":"denied" if reason=="denied" else "not_connected","reason":reason})

    if mode=="list":
        if "sql" in iname:
            out, err = _run_ps(iid, POWERSHELL_LIST_SQL)
        else:
            pat = body.get("pattern","")
            scr = f'param([string]$Pattern="{pat}");'+POWERSHELL_LIST_GENERIC.split("\n",1)[1]
            out, err = _run_ps(iid, scr)
        if err: return ok({"error":err})
        try: svcs=json.loads(out or "[]")
        except Exception: svcs=[]
        return ok({"services":svcs})

    if mode in ("start","stop"):
        name=body.get("service")
        if not name: return ok({"error":"bad_request"})
        script = POWERSHELL_SVC.replace('$Mode', f'"{mode}"').replace('$Name', f'"{name}"')
        out, err = _run_ps(iid, script)
        if err: return ok({"error":err})
        try: svc=json.loads(out or "{}")
        except Exception: svc={}
        return ok({"service":svc})

    if mode=="iisreset":
        out, err=_run_ps(iid, POWERSHELL_IISRESET)
        if err: return ok({"error":err})
        return ok({"ok":True})

    return ok({"error":"bad_request"})

# ---------------- Router ----------------
def lambda_handler(event, ctx):
    path = (event.get("rawPath") or event.get("path") or "").lower()
    method = (event.get("requestContext",{}).get("http",{}).get("method") or event.get("httpMethod") or "GET").upper()

    # CORS preflight for HTTP API
    if method == "OPTIONS":
        return ok({"ok": True})

    if path.endswith("/request-otp") and method=="POST":  return request_otp(json.loads(event.get("body") or "{}"))
    if path.endswith("/verify-otp") and method=="POST":   return verify_otp(json.loads(event.get("body") or "{}"))
    if path.endswith("/login") and method=="POST":        return login(json.loads(event.get("body") or "{}"))

    try: _auth(event)
    except Exception: return bad(401,"unauthorized")

    if path.endswith("/instances") and method=="GET":        return instances(event, ctx)
    if path.endswith("/instance-action") and method=="POST": return instances(event, ctx)  # kept for compat
    if path.endswith("/services") and method=="POST":        return services(event, ctx)

    return bad(404,"not_found")
