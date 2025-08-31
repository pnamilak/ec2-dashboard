# lambda/handler.py
# -----------------------------------------------------------------------------
# EC2 Dashboard API (single Lambda) – OTP, login, instances, actions, services.
# This version includes the full SSM Services implementation (SQL / Redis /
# SVC+WEB filter + IIS reset) and keeps the rest of the endpoints intact.
# -----------------------------------------------------------------------------

import os
import re
import json
import time
import hmac
import base64
import hashlib
import random
from datetime import datetime, timedelta, timezone

import boto3
from botocore.exceptions import ClientError

# ---------- Environment ----------
REGION            = os.environ.get("REGION", "us-east-2")
OTP_TABLE_NAME    = os.environ.get("OTP_TABLE", "")
SES_SENDER        = os.environ.get("SES_SENDER", "")
ALLOWED_DOMAIN    = os.environ.get("ALLOWED_DOMAIN", "gmail.com")
PARAM_USER_PREFIX = os.environ.get("PARAM_USER_PREFIX", "/ec2-dashboard/users")
JWT_PARAM         = os.environ.get("JWT_PARAM", "/ec2-dashboard/jwt-secret")
ENV_NAMES_STR     = os.environ.get("ENV_NAMES", "")
ENV_TOKENS        = [e.strip() for e in ENV_NAMES_STR.split(",") if e.strip()]

# ---------- Clients ----------
ec2 = boto3.client("ec2", region_name=REGION)
ssm = boto3.client("ssm", region_name=REGION)
ses = boto3.client("ses", region_name=REGION) if SES_SENDER else None
ddb = boto3.resource("dynamodb", region_name=REGION) if OTP_TABLE_NAME else None
param = boto3.client("ssm", region_name=REGION)

# ---------- Helpers ----------
def _json(status: int, obj: dict):
    return {
        "statusCode": status,
        "headers": {"content-type": "application/json"},
        "body": json.dumps(obj),
    }

def _now_utc():
    return datetime.now(timezone.utc)

def _b64url(b: bytes) -> bytes:
    return base64.urlsafe_b64encode(b).rstrip(b"=")

def _jwt_encode(payload: dict, secret: str) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    head = _b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payl = _b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = head + b"." + payl
    sig = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    token = signing_input + b"." + _b64url(sig)
    return token.decode("utf-8")

def _get_param(name: str) -> str:
    r = param.get_parameter(Name=name, WithDecryption=True)
    return r["Parameter"]["Value"]

def _get_user_secret(username: str) -> str:
    """
    In Parameter Store:
      /ec2-dashboard/users/<username>  => "password,role,email,name"
    """
    p = f"{PARAM_USER_PREFIX}/{username}"
    try:
        return _get_param(p)
    except ClientError:
        return ""

def _send_otp_email(email: str, code: str):
    if not ses:
        return
    ses.send_email(
        Source=SES_SENDER,
        Destination={"ToAddresses": [email]},
        Message={
            "Subject": {"Data": "Your EC2 Dashboard OTP"},
            "Body": {"Text": {"Data": f"Your OTP is: {code}. It expires in 5 minutes."}},
        },
    )

def _gen_code(n=6) -> str:
    return "".join(random.choice("0123456789") for _ in range(n))

def _name_of(tags) -> str:
    for t in tags or []:
        if t.get("Key") == "Name":
            return t.get("Value", "")
    return ""

def _env_hit(name_lower: str) -> list[str]:
    """Return all env tokens present in the given instance name."""
    hits = []
    for token in ENV_TOKENS:
        if token.lower() in name_lower:
            hits.append(token)
    return hits

# ---------- OTP endpoints ----------
def handle_request_otp(body: dict):
    email = (body.get("email") or "").strip().lower()
    if not email or not email.endswith("@" + ALLOWED_DOMAIN):
        return _json(400, {"error": "invalid_email"})

    code = _gen_code(6)
    exp = int((_now_utc() + timedelta(minutes=5)).timestamp())  # epoch seconds

    if not ddb:
        return _json(500, {"error": "otp_store_unavailable"})

    table = ddb.Table(OTP_TABLE_NAME)
    table.put_item(Item={"email": email, "code": code, "exp": exp})

    try:
        _send_otp_email(email, code)
    except Exception as e:
        return _json(500, {"error": f"email_error: {e}"})

    return _json(200, {"ok": True})

def handle_verify_otp(body: dict):
    email = (body.get("email") or "").strip().lower()
    code  = (body.get("code")  or "").strip()
    if not email or not code:
        return _json(400, {"error": "missing"})

    if not ddb:
        return _json(500, {"error": "otp_store_unavailable"})

    table = ddb.Table(OTP_TABLE_NAME)
    resp  = table.get_item(Key={"email": email})
    item  = resp.get("Item")
    if not item:
        return _json(200, {"ok": False, "error": "no_code"})

    if item.get("code") != code:
        return _json(200, {"ok": False, "error": "bad_code"})

    if int(item.get("exp", 0)) < int(_now_utc().timestamp()):
        return _json(200, {"ok": False, "error": "expired"})

    # One-time token back to the client (UI passes it to login)
    ovt = _gen_code(8)
    return _json(200, {"ok": True, "ovt": ovt})

def handle_login(body: dict):
    """
    body: {email, username, password, ovt}
    Validates against SSM param: "/<project>/users/<username>" => "password,role,email,name"
    Creates a JWT signed with secret at JWT_PARAM.
    """
    email    = (body.get("email")    or "").strip().lower()
    username = (body.get("username") or "").strip()
    password = (body.get("password") or "").strip()
    # ovt is accepted from UI; we don't store it server-side here.

    if not username or not password or not email.endswith("@" + ALLOWED_DOMAIN):
        return _json(400, {"error": "bad_credentials"})

    raw = _get_user_secret(username)  # "pwd,role,email,name"
    if not raw:
        return _json(401, {"error": "user_not_found"})

    try:
        upwd, role, uemail, name = [s.strip() for s in raw.split(",", 3)]
    except Exception:
        return _json(500, {"error": "user_param_malformed"})

    if password != upwd or email != uemail:
        return _json(401, {"error": "invalid"})

    secret = _get_param(JWT_PARAM)
    now = int(_now_utc().timestamp())
    payload = {
        "sub": username,
        "name": name,
        "role": role,
        "email": email,
        "iat": now,
        "exp": now + 8 * 3600,  # 8 hours
    }
    token = _jwt_encode(payload, secret)
    return _json(200, {"token": token, "role": role, "user": name})

# ---------- Instances & actions ----------
def _shape_instance(i: dict) -> dict:
    iid  = i["InstanceId"]
    name = _name_of(i.get("Tags"))
    st   = (i.get("State") or {}).get("Name", "")
    return {"id": iid, "name": name, "state": st}

def handle_instances():
    """
    Response:
    {
      summary: { total, running, stopped },
      envs: { <ENV> : { DM:[...], EA:[...] }, ... }
    }
    """
    res = ec2.describe_instances(
        Filters=[
            {"Name": "instance-state-name", "Values": ["pending","running","stopping","stopped"]},
        ]
    )
    envs: dict[str, dict[str, list]] = {}
    all_items = []

    for r in res.get("Reservations", []):
        for i in r.get("Instances", []):
            it = _shape_instance(i)
            if not it["name"]:
                continue
            nl = it["name"].lower()
            hits = _env_hit(nl)
            if not hits:
                # put under a "DevMini" tab if "dev" in name
                if "dev" in nl:
                    hits = ["DevMini"]
                else:
                    continue
            # DM vs EA blocks by name token
            block = "DM" if "dm" in nl else ("EA" if "ea" in nl else "DM")

            for env in hits:
                envs.setdefault(env, {"DM": [], "EA": []})
                envs[env][block].append(it)
                all_items.append(it)

    running = sum(1 for x in all_items if x["state"] == "running")
    stopped = sum(1 for x in all_items if x["state"] == "stopped")
    return _json(200, {"summary": {"total": len(all_items), "running": running, "stopped": stopped}, "envs": envs})

def handle_instance_action(body: dict):
    iid    = (body.get("id") or "").strip()
    action = (body.get("action") or "").strip().lower()
    if not iid or action not in ("start","stop"):
        return _json(400, {"error": "bad_request"})
    try:
        if action == "start":
            ec2.start_instances(InstanceIds=[iid])
        else:
            ec2.stop_instances(InstanceIds=[iid])
        return _json(200, {"ok": True})
    except ClientError as e:
        return _json(200, {"ok": False, "error": str(e)})

def handle_bulk(body: dict):
    ids    = body.get("ids") or []
    action = (body.get("action") or "").strip().lower()
    if not ids or action not in ("start","stop"):
        return _json(400, {"error":"bad_request"})
    try:
        if action == "start":
            ec2.start_instances(InstanceIds=ids)
        else:
            ec2.stop_instances(InstanceIds=ids)
        return _json(200, {"ok": True})
    except ClientError as e:
        return _json(200, {"ok": False, "error": str(e)})

# ---------- SSM Services (SQL / Redis / SVC+WEB / IIS reset) ----------
def _ssm_is_online(iid: str) -> bool:
    """True if the instance is registered and online in SSM."""
    try:
        info = ssm.describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": [iid]}]
        )
        lst = info.get("InstanceInformationList", [])
        if not lst:
            return False
        return lst[0].get("PingStatus") == "Online"
    except Exception:
        return False

def _run_ssm_ps(instance_id: str, commands: list[str], timeout=60):
    """Run PowerShell on the instance. Returns (ok, data|error_text)."""
    # fast fail when the target is not online in SSM
    if not _ssm_is_online(instance_id):
        return False, "not_connected"

    try:
        resp = ssm.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunPowerShellScript",
            Parameters={"commands": commands},
            TimeoutSeconds=timeout,
        )
    except ssm.exceptions.InvalidInstanceId:
        return False, "invalid_instance"
    except Exception as e:
        msg = str(e)
        if "TargetNotConnected" in msg:
            return False, "not_connected"
        return False, msg

    cmd_id = resp["Command"]["CommandId"]
    end_by = time.time() + timeout
    while time.time() < end_by:
        out = ssm.get_command_invocation(CommandId=cmd_id, InstanceId=instance_id)
        st = out.get("Status")
        if st in ("Success", "Cancelled", "Failed", "TimedOut"):
            if st != "Success":
                return False, (out.get("StandardErrorContent") or out.get("StandardOutputContent") or st)
            return True, out.get("StandardOutputContent") or "[]"
        time.sleep(1.0)
    return False, "timeout"

def _ps_json_list_sql():
    # emit lowercase keys + lowercase status
    return [r'''
$names = @('MSSQL*','SQLSERVERAGENT*','SQLBrowser','SQL*')
$svcs = Get-Service -Name $names -ErrorAction SilentlyContinue |
  Select-Object @{n='name';e={$_.Name}},
                @{n='display';e={$_.DisplayName}},
                @{n='status';e={$_.Status.ToString().ToLower()}}
$svcs | ConvertTo-Json -Compress
''']

def _ps_json_list_redis():
    return [r'''
$svcs = Get-Service -Name 'Redis*' -ErrorAction SilentlyContinue |
  Select-Object @{n='name';e={$_.Name}},
                @{n='display';e={$_.DisplayName}},
                @{n='status';e={$_.Status.ToString().ToLower()}}
$svcs | ConvertTo-Json -Compress
''']

def _ps_json_list_pattern(pattern:str):
    p = re.sub(r"'", "''", pattern)
    return [rf'''
$pat = '{p}'
$svcs = Get-Service | Where-Object {{ $_.Name -match $pat -or $_.DisplayName -match $pat }} |
  Select-Object @{n='name';e={{$_.Name}}},
                @{n='display';e={{$_.DisplayName}}},
                @{n='status';e={{$_.Status.ToString().ToLower()}}}
$svcs | ConvertTo-Json -Compress
''']

def _ps_start(name:str):
    n = name.replace("'", "''")
    return [rf'''
try {{
  $s = Get-Service -Name '{n}' -ErrorAction Stop
  if ($s.Status -ne 'Running') {{
    Start-Service -Name '{n}'
    (Get-Service -Name '{n}').WaitForStatus('Running','00:00:20')
  }}
  $s = Get-Service -Name '{n}'
  [pscustomobject]@{{ name=$s.Name; display=$s.DisplayName; status=$s.Status.ToString().ToLower() }} |
    ConvertTo-Json -Compress
}} catch {{
  [pscustomobject]@{{ name='{n}'; display='{n}'; status='error' }} | ConvertTo-Json -Compress
}}
''']

def _ps_stop(name:str):
    n = name.replace("'", "''")
    return [rf'''
try {{
  $s = Get-Service -Name '{n}' -ErrorAction Stop
  if ($s.Status -ne 'Stopped') {{
    Stop-Service -Name '{n}' -Force
    (Get-Service -Name '{n}').WaitForStatus('Stopped','00:00:20')
  }}
  $s = Get-Service -Name '{n}'
  [pscustomobject]@{{ name=$s.Name; display=$s.DisplayName; status=$s.Status.ToString().ToLower() }} |
    ConvertTo-Json -Compress
}} catch {{
  [pscustomobject]@{{ name='{n}'; display='{n}'; status='error' }} | ConvertTo-Json -Compress
}}
''']

def _ps_iis_reset():
    # we don't need JSON here; caller just returns a message
    return [r"iisreset /noforce"]

def _normalize_services(arr):
    """Return list of items containing BOTH key styles the UI might expect."""
    out = []
    for s in (arr or []):
        name = s.get("name") or s.get("Name")
        display = s.get("display") or s.get("DisplayName")
        status = (s.get("status") or s.get("Status") or "").lower()
        out.append({
            "name": name,
            "display": display,
            "status": status,
            # legacy/camel variants to be safe with the front-end
            "Name": name,
            "DisplayName": display,
            "Status": status,
        })
    return out

def handle_services(body: dict):
    """
    body: { id, mode: list|start|stop|iisreset, service?, instanceName?, kind?, pattern? }
    """
    iid = (body.get("id") or "").strip()
    mode = (body.get("mode") or "list").lower()
    inst_name = (body.get("instanceName") or "").lower()
    kind = (body.get("kind") or "").lower()
    pattern = (body.get("pattern") or "").strip()

    if not iid:
        return _json(400, {"error": "missing_instance_id"})

    # Derive kind from name if not provided by UI
    if not kind:
        kind = "svcweb" if ("svc" in inst_name or "web" in inst_name) else \
               ("sql" if "sql" in inst_name else ("redis" if "redis" in inst_name else "generic"))

    try:
        if mode == "list":
            if kind == "sql":
                commands = _ps_json_list_sql()
            elif kind == "redis":
                commands = _ps_json_list_redis()
            elif kind == "svcweb":
                if len(pattern) < 2:
                    return _json(200, {"services": [], "error": "enter_filter"})
                commands = _ps_json_list_pattern(pattern)
            else:
                return _json(200, {"services": [], "error": "unsupported"})

            ok, out = _run_ssm_ps(iid, commands)
            if not ok:
                return _json(200, {"services": [], "error": out})

            try:
                arr = json.loads(out) if out else []
                if isinstance(arr, dict):
                    arr = [arr]
                return _json(200, {"services": _normalize_services(arr)})
            except Exception:
                return _json(200, {"services": [], "error": "parse_error"})

        elif mode in ("start","stop"):
            svc = (body.get("service") or "").strip()
            if not svc:
                return _json(400, {"error": "missing_service"})
            commands = _ps_start(svc) if mode == "start" else _ps_stop(svc)
            ok, out = _run_ssm_ps(iid, commands)
            if not ok:
                return _json(200, {"services": [], "error": out})
            try:
                obj = json.loads(out) if out else {}
                arr = [obj] if isinstance(obj, dict) else (obj or [])
                return _json(200, {"services": _normalize_services(arr)})
            except Exception:
                return _json(200, {"services": [], "error": "parse_error"})

        elif mode == "iisreset":
            ok, out = _run_ssm_ps(iid, _ps_iis_reset())
            if not ok:
                return _json(200, {"services": [], "error": out})
            msg = (out or "").strip() or "IIS reset issued"
            return _json(200, {"ok": True, "message": msg})

        else:
            return _json(400, {"error": "bad_mode"})

    except Exception as e:
        return _json(500, {"error": str(e)})

# ---------- Router ----------
def lambda_handler(event, context):
    path   = event.get("rawPath") or event.get("requestContext", {}).get("http", {}).get("path", "")
    method = event.get("requestContext", {}).get("http", {}).get("method", "GET")

    body = {}
    if event.get("body"):
        try:
            body = json.loads(event["body"])
        except Exception:
            body = {}

    # Public
    if path == "/request-otp" and method == "POST":
        return handle_request_otp(body)
    if path == "/verify-otp" and method == "POST":
        return handle_verify_otp(body)
    if path == "/login" and method == "POST":
        return handle_login(body)

    # Protected (API Gateway custom authorizer checks JWT)
    if path == "/instances" and method == "GET":
        return handle_instances()
    if path == "/instance-action" and method == "POST":
        return handle_instance_action(body)
    if path == "/bulk-action" and method
