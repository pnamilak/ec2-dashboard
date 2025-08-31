import os, json, time, uuid, base64, hmac, hashlib, logging
import boto3
from botocore.exceptions import ClientError

log = logging.getLogger()
log.setLevel(logging.INFO)

# ---------- JWT helpers ----------
def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")

def _jwt_for(username: str, role: str, ssm_client, jwt_param_name: str, ttl_seconds: int = 3600) -> str:
    header  = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    now     = int(time.time())
    payload = _b64url(json.dumps({"sub": username, "role": role, "iat": now, "exp": now + ttl_seconds}).encode())
    secret  = ssm_client.get_parameter(Name=jwt_param_name, WithDecryption=True)["Parameter"]["Value"].encode()
    sig     = _b64url(hmac.new(secret, f"{header}.{payload}".encode(), hashlib.sha256).digest())
    return f"{header}.{payload}.{sig}"

REGION             = os.environ.get("REGION", "us-east-2")
OTP_TABLE          = os.environ["OTP_TABLE"]
SES_SENDER         = os.environ["SES_SENDER"]
ALLOWED_DOMAIN     = os.environ.get("ALLOWED_DOMAIN", "example.com")
PARAM_USER_PREFIX  = os.environ["PARAM_USER_PREFIX"]   # e.g. /ec2-dashboard/users
JWT_PARAM          = os.environ["JWT_PARAM"]
ENV_NAMES          = [e.strip() for e in os.environ.get("ENV_NAMES","").split(",") if e.strip()]

ddb   = boto3.resource("dynamodb", region_name=REGION)
ses   = boto3.client("ses", region_name=REGION)
param = boto3.client("ssm", region_name=REGION)      # Parameter Store
ssm   = boto3.client("ssm", region_name=REGION)      # Fleet + RunCommand
ec2   = boto3.client("ec2", region_name=REGION)
table = ddb.Table(OTP_TABLE)

def ok(b):   return {"statusCode":200,"headers":{"content-type":"application/json"},"body":json.dumps(b)}
def bad(c,m): return {"statusCode":c,"headers":{"content-type":"application/json"},"body":json.dumps({"error":m})}

# ---------- OTP ----------
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
    # consume OTP and mint a short-lived one-time verifier token (OVT)
    table.delete_item(Key={"email":email})
    ovt = uuid.uuid4().hex
    table.put_item(Item={"email":f"ovt:{ovt}", "code":email, "expiresAt":int(time.time())+300})
    return ok({"ok":True, "ovt":ovt})

# ---------- Users from SSM ----------
def _read_user(username: str):
    """
    Accepts: 'password|role'   or   'password,role[,email[,name]]'
    """
    p = f"{PARAM_USER_PREFIX.rstrip('/')}/{username}"
    val = param.get_parameter(Name=p, WithDecryption=True)["Parameter"]["Value"].strip()
    if "|" in val:
        pwd, role = (val.split("|",1)+["read"])[:2]
        email, name = "", username
    else:
        f = [x.strip() for x in val.split(",")]
        pwd   = f[0]
        role  = (f[1].lower() if len(f)>1 and f[1] else "read")
        email = f[2] if len(f)>2 else ""
        name  = f[3] if len(f)>3 else username
    return {"password": pwd, "role": role, "name": name, "email": email}

def _consume_ovt(ovt: str) -> str | None:
    """Return verified email if OVT is valid, else None. Consumes the token."""
    k = f"ovt:{ovt}"
    r = table.get_item(Key={"email":k})
    item = r.get("Item")
    if not item: return None
    if int(time.time()) > int(item.get("expiresAt",0)): 
        table.delete_item(Key={"email":k})
        return None
    email = item.get("code")
    table.delete_item(Key={"email":k})
    return email

def login(data):
    u = (data.get("username") or "").strip()
    p = (data.get("password") or "")
    ovt = (data.get("ovt") or "").strip()

    if not u or not p: return bad(400, "missing_credentials")
    if not ovt:        return bad(401, "otp_required")

    try: user = _read_user(u)
    except Exception:
        log.exception("read_user failed"); return bad(401, "invalid_user")

    if user.get("password") != p:
        return bad(401, "invalid_password")

    # server-side OTP enforcement: OVT must exist and match user's email (if configured)
    email_verified = _consume_ovt(ovt)
    if not email_verified:
        return bad(401, "otp_expired")

    user_email = (user.get("email") or "").lower()
    if user_email and user_email != email_verified:
        return bad(401, "otp_email_mismatch")

    role  = user.get("role") or "read"
    token = _jwt_for(u, role, param, JWT_PARAM, ttl_seconds=3600)
    return {
        "statusCode": 200,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "authorization,content-type",
            "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
        },
        "body": json.dumps({"token":token,"role":role,"user":{"username":u,"role":role,"name":user.get("name") or u}}),
    }

# ---------- Auth helper ----------
def _auth(event):
    auth = event.get("headers",{}).get("authorization") or event.get("headers",{}).get("Authorization")
    if not auth or not auth.lower().startswith("bearer "):
        raise Exception("no_token")
    return True

# ---------- EC2 listing ----------
def instances(event, _):
    r = ec2.describe_instances(Filters=[{"Name":"instance-state-name","Values":["running","stopped","stopping","pending","starting","shutting-down"]}])
    envs = {e:{"DM":[],"EA":[]} for e in ENV_NAMES}
    summary = {"total":0,"running":0,"stopped":0}

    for res in r.get("Reservations",[]):
        for i in res.get("Instances",[]):
            state=i["State"]["Name"].lower()
            name=next((t["Value"] for t in i.get("Tags",[]) if t["Key"]=="Name"),"")
            if not name: continue
            env=None; lname=name.lower()
            for e in ENV_NAMES:
                if e.lower() in lname: env=e; break
            if not env: continue
            bucket="DM" if any(x in lname for x in ["dmsql","dmsvc","dmweb","dream","sql"]) else "EA"
            envs[env][bucket].append({"id":i["InstanceId"],"name":name,"state":state})
            summary["total"]+=1
            if state=="running": summary["running"]+=1
            if state=="stopped": summary["stopped"]+=1
    return ok({"summary":summary,"envs":envs})

def instance_action(event, _):
    body=json.loads(event.get("body") or "{}")
    iid=body.get("id"); action=(body.get("action") or "").lower()
    if not iid or action not in ("start","stop"):
        return bad(400,"bad_request")
    try:
        if action=="start": ec2.start_instances(InstanceIds=[iid])
        else:               ec2.stop_instances(InstanceIds=[iid])
        return ok({"ok":True})
    except ClientError as e:
        code=e.response["Error"]["Code"]
        return ok({"error":"ec2_"+code, "reason": e.response["Error"].get("Message","")})

# ---------- SSM helpers ----------
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

_PREAMBLE = r"""
$ErrorActionPreference='SilentlyContinue'
[Console]::OutputEncoding=[System.Text.Encoding]::UTF8
"""

# Cast Status to string so JSON never returns numeric 1/4 etc.
POWERSHELL_LIST_SQL = _PREAMBLE + r"""
$svcs = Get-Service | Where-Object { $_.Name -match '^MSSQL' -or $_.Name -match '^SQLSERVERAGENT' } |
    Select-Object Name,DisplayName,@{n='Status';e={$_.Status.ToString()}}
$svcs | ConvertTo-Json -Depth 4 -Compress
"""

POWERSHELL_LIST_GENERIC = _PREAMBLE + r"""
param([string]$Pattern="")
$svcs = Get-Service | Where-Object { $_.Name -like "*$Pattern*" -or $_.DisplayName -like "*$Pattern*" } |
    Select-Object Name,DisplayName,@{n='Status';e={$_.Status.ToString()}}
$svcs | ConvertTo-Json -Depth 4 -Compress
"""

POWERSHELL_SVC = _PREAMBLE + r"""
param([string]$Name,[string]$Mode)
if ($Mode -eq "start") { Start-Service -Name $Name -ErrorAction SilentlyContinue }
if ($Mode -eq "stop")  { Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue }
$svc = Get-Service -Name $Name -ErrorAction SilentlyContinue |
    Select-Object Name,DisplayName,@{n='Status';e={$_.Status.ToString()}}
if ($null -eq $svc) { Write-Output "{}" } else { $svc | ConvertTo-Json -Depth 4 -Compress }
"""

POWERSHELL_IISRESET = _PREAMBLE + r"iisreset /noforce | Out-Null; Write-Output '{""ok"":true}'"

def _run_ps(instance_id, script, timeout=45):
    try:
        send = ssm.send_command(
            DocumentName="AWS-RunPowerShellScript",
            InstanceIds=[instance_id],
            Parameters={"commands":[script]},
        )
    except ClientError as e:
        code=e.response["Error"]["Code"]
        return None, ("denied" if code in ("AccessDenied","AccessDeniedException") else "send_failed")

    cmd_id=send["Command"]["CommandId"]
    t0=time.time()
    while time.time()-t0<timeout:
        try:
            r=ssm.get_command_invocation(CommandId=cmd_id, InstanceId=instance_id)
        except ClientError:
            time.sleep(1); continue
        st=r["Status"]
        if st=="Success":
            out = (r.get("StandardOutputContent","") or "").strip()
            err = (r.get("StandardErrorContent","") or "").strip()
            if err and not out:
                return None, ("stderr:" + err[:250])
            return (out or "[]"), None
        if st in ("Cancelled","TimedOut","Failed"):
            err = (r.get("StandardErrorContent","") or "").strip()
            return None, ("invocation_"+st.lower() + ((":"+err[:180]) if err else ""))
        time.sleep(1)
    return None,"timeout"

def services(event,_):
    try:
        body=json.loads(event.get("body") or "{}")
        iid=body.get("id"); mode=(body.get("mode") or "list").lower()
        iname=(body.get("instanceName") or "").lower()
        if not iid: return ok({"error":"bad_request"})

        online, reason = ssm_online(iid)
        if not online:
            return ok({"error":"denied" if reason=="denied" else "not_connected","reason":reason})

        if mode=="list":
            if "sql" in iname:
                out, err = _run_ps(iid, POWERSHELL_LIST_SQL)
            else:
                pat = (body.get("pattern","") or "").replace('"','')
                script = f'param([string]$Pattern="{pat}");' + POWERSHELL_LIST_GENERIC.split("\n",1)[1]
                out, err = _run_ps(iid, script)
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
    except Exception as ex:
        log.exception("services handler failed")
        return ok({"error":"exception","reason":str(ex)})

# ---------- Router ----------
def lambda_handler(event, ctx):
    method = (event.get("requestContext",{}).get("http",{}).get("method") or event.get("httpMethod") or "GET").upper()
    path = (event.get("rawPath") or event.get("path") or "").lower()

    if method == "OPTIONS": return ok({"ok": True})

    if path.endswith("/request-otp") and method=="POST":  return request_otp(json.loads(event.get("body") or "{}"))
    if path.endswith("/verify-otp")  and method=="POST":  return verify_otp(json.loads(event.get("body") or "{}"))
    if path.endswith("/login")       and method=="POST":  return login(json.loads(event.get("body") or "{}"))

    try: _auth(event)
    except Exception: return bad(401,"unauthorized")

    if path.endswith("/instances")        and method=="GET":  return instances(event, ctx)
    if path.endswith("/instance-action")  and method=="POST": return instance_action(event, ctx)
    if path.endswith("/services")         and method=="POST": return services(event, ctx)

    return bad(404,"not_found")
