import os, json, time, boto3, base64, uuid, datetime
from botocore.exceptions import ClientError

REGION = os.environ.get("REGION", "us-east-2")
OTP_TABLE = os.environ["OTP_TABLE"]
SES_SENDER = os.environ["SES_SENDER"]
ALLOWED_DOMAIN = os.environ.get("ALLOWED_DOMAIN", "example.com")
PARAM_USER_PREFIX = os.environ["PARAM_USER_PREFIX"]
JWT_PARAM = os.environ["JWT_PARAM"]
ENV_NAMES = [e.strip() for e in os.environ.get("ENV_NAMES","").split(",") if e.strip()]

dynamodb = boto3.resource("dynamodb", region_name=REGION)
ses = boto3.client("ses", region_name=REGION)
ssm = boto3.client("ssm", region_name=REGION)
ec2 = boto3.client("ec2", region_name=REGION)
table = dynamodb.Table(OTP_TABLE)

# -------- helpers --------
def ok(body):   return {"statusCode":200, "headers":{"content-type":"application/json"}, "body":json.dumps(body)}
def bad(code,msg): return {"statusCode":code, "headers":{"content-type":"application/json"}, "body":json.dumps({"error":msg})}

def ssm_check_online(instance_id):
    """Return (True,None) if online, otherwise (False, reason)."""
    try:
        r = ssm.describe_instance_information(
            Filters=[{"Key":"InstanceIds","Values":[instance_id]}]
        )
        items = r.get("InstanceInformationList", [])
        if not items:
            return False, "not_managed"
        ping = items[0].get("PingStatus","Unknown")
        return (ping == "Online"), ping
    except ClientError as e:
        if e.response["Error"]["Code"] in ("AccessDeniedException","AccessDenied"):
            return False, "denied"
        return False, "error"

def _jwt_secret():
    p = ssm.get_parameter(Name=JWT_PARAM, WithDecryption=True)
    return p["Parameter"]["Value"]

def _read_user(u):
    try:
        p = ssm.get_parameter(Name=f"{PARAM_USER_PREFIX}/{u}", WithDecryption=True)
        val = p["Parameter"]["Value"]
        # format: password|role  (role in {admin,read})
        if "|" in val:
            pwd, role = val.split("|",1)
        else:
            pwd, role = val, "admin"
        return {"username":u, "password":pwd, "role":role}
    except ClientError:
        return None

# ----- OTP -----
def request_otp(data):
    email = data.get("email","").strip().lower()
    if not email or not email.endswith("@"+ALLOWED_DOMAIN):
        return bad(403,"not_allowed_domain")
    code = str(uuid.uuid4().int)[-6:]
    expire = int(time.time()) + 300
    table.put_item(Item={"email":email,"code":code,"expiresAt":expire})
    ses.send_email(
        Source=SES_SENDER,
        Destination={"ToAddresses":[email]},
        Message={
            "Subject":{"Data":"Your EC2 Dashboard OTP"},
            "Body":{"Text":{"Data":f"Your OTP code is {code}. It expires in 5 minutes."}}
        }
    )
    return ok({"ok":True})

def verify_otp(data):
    email = data.get("email","").strip().lower()
    code  = data.get("code","").strip()
    r = table.get_item(Key={"email":email})
    item = r.get("Item")
    if not item or item.get("code")!=code or int(time.time())>int(item.get("expiresAt",0)):
        return bad(401,"invalid_otp")
    table.delete_item(Key={"email":email})
    return ok({"ok":True})

# ----- login -----
def login(data):
    u = data.get("username","").strip()
    p = data.get("password","")
    user = _read_user(u)
    if not user or user["password"] != p:
        return bad(401,"bad_credentials")
    # very small non-jwt token for brevity (keep as-is if you used proper JWTs)
    token = base64.b64encode(f"{u}|{user['role']}|{int(time.time())}".encode()).decode()
    return ok({"token":token,"role":user["role"],"user":{"username":u,"role":user["role"],"name":u.capitalize()}})

def _auth(event):
    # Very light token check (match what authorizer returns)
    auth = event["headers"].get("authorization") or event["headers"].get("Authorization")
    if not auth or not auth.lower().startswith("bearer "):
        raise Exception("no_token")
    payload = base64.b64decode(auth.split(" ",1)[1]).decode()
    parts = payload.split("|")
    if len(parts)<2: raise Exception("bad_token")
    return {"username":parts[0], "role":parts[1]}

# ----- instances -----
def instances(_event, _ctx):
    # group by env tags/env name
    # filter: Name like any env token
    r = ec2.describe_instances(
        Filters=[{"Name":"instance-state-name","Values":["running","stopped"]}]
    )
    envs = {e:{"DM":[],"EA":[]} for e in ENV_NAMES}
    summary = {"total":0,"running":0,"stopped":0}
    for res in r.get("Reservations",[]):
        for i in res.get("Instances",[]):
            state = i["State"]["Name"]
            name = ""
            for t in i.get("Tags",[]):
                if t["Key"]=="Name": name = t["Value"]
            if not name: continue
            # find which env the name mentions
            env = None
            lname=name.lower()
            for e in ENV_NAMES:
                if e.lower() in lname:
                    env=e; break
            if not env: continue
            # bucket (DM / EA)
            bucket = "DM" if any(x in lname for x in ["dmsql","dmsvc","dmweb","dream"]) else "EA"
            envs[env][bucket].append({"id":i["InstanceId"],"name":name,"state":state})
            summary["total"]+=1
            if state=="running": summary["running"]+=1
            if state=="stopped": summary["stopped"]+=1
    return ok({"summary":summary,"envs":envs})

# ----- instance actions -----
def instance_action(event, ctx):
    body = json.loads(event.get("body") or "{}")
    id_ = body.get("id")
    action = body.get("action")
    if not id_ or action not in ("start","stop"): return bad(400,"bad_request")
    if action=="start":
        ec2.start_instances(InstanceIds=[id_])
    else:
        ec2.stop_instances(InstanceIds=[id_])
    return ok({"ok":True})

# ----- services via SSM -----
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

def _run_ps(instance_id, script, params=None, timeout=30):
    kwargs = {
        "DocumentName":"AWS-RunPowerShellScript",
        "InstanceIds":[instance_id],
        "Parameters":{"commands":[script]}
    }
    if params:
        # add param block before script
        pass
    try:
        cmd = ssm.send_command(**kwargs)
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("AccessDenied","AccessDeniedException"): return None, "denied"
        return None, "send_failed"

    cmd_id = cmd["Command"]["CommandId"]
    t0 = time.time()
    while time.time()-t0 < timeout:
        r = ssm.get_command_invocation(CommandId=cmd_id, InstanceId=instance_id)
        status = r["Status"]
        if status in ("Success","Cancelled","TimedOut","Failed"):
            if status!="Success":
                return None, "invocation_"+status.lower()
            out = r.get("StandardOutputContent","").strip()
            return out, None
        time.sleep(1)
    return None, "timeout"

def services(event, ctx):
    body = json.loads(event.get("body") or "{}")
    iid = body.get("id")
    mode = body.get("mode","list")
    instance_name = (body.get("instanceName") or "").lower()
    if not iid: return ok({"error":"bad_request"})

    # preflight
    online, reason = ssm_check_online(iid)
    if not online:
        if reason == "denied":
            return ok({"error":"denied"})
        else:
            return ok({"error":"not_connected","reason":reason})

    if mode == "list":
        if "sql" in instance_name:
            out, err = _run_ps(iid, POWERSHELL_LIST_SQL)
        else:
            pattern = body.get("pattern","")
            script = f'param([string]$Pattern=""); {POWERSHELL_LIST_GENERIC}'
            # embed default param
            out, err = _run_ps(iid, script.replace('param([string]$Pattern="")', f'param([string]$Pattern="{pattern}")'))
        if err: return ok({"error":err})
        try:
            services = json.loads(out or "[]")
        except Exception:
            services = []
        return ok({"services":services})

    if mode in ("start","stop"):
        name = body.get("service")
        if not name: return ok({"error":"bad_request"})
        ps = POWERSHELL_SVC.replace('$Mode', f'"{mode}"').replace('$Name', f'"{name}"')
        out, err = _run_ps(iid, ps)
        if err: return ok({"error":err})
        try:
            svc = json.loads(out or "{}")
        except Exception:
            svc = {}
        return ok({"service":svc})

    if mode == "iisreset":
        out, err = _run_ps(iid, POWERSHELL_IISRESET)
        if err: return ok({"error":err})
        return ok({"ok":True})

    return ok({"error":"bad_request"})

# ----- router -----
def lambda_handler(event, ctx):
    path = (event.get("rawPath") or event.get("path") or "").lower()
    meth = (event.get("requestContext",{}).get("http",{}).get("method") or event.get("httpMethod") or "GET").upper()

    if path.endswith("/request-otp") and meth=="POST":
        return request_otp(json.loads(event.get("body") or "{}"))
    if path.endswith("/verify-otp") and meth=="POST":
        return verify_otp(json.loads(event.get("body") or "{}"))
    if path.endswith("/login") and meth=="POST":
        return login(json.loads(event.get("body") or "{}"))

    # protected
    try:
        _auth(event)
    except Exception:
        return bad(401,"unauthorized")

    if path.endswith("/instances") and meth=="GET":
        return instances(event, ctx)
    if path.endswith("/instance-action") and meth=="POST":
        return instance_action(event, ctx)
    if path.endswith("/services") and meth=="POST":
        return services(event, ctx)

    return bad(404,"not_found")
