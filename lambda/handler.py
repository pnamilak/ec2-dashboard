# lambda/handler.py
# -----------------------------------------------------------------------------
# EC2 Dashboard API (single Lambda) – OTP, login, instances, actions, services.
# Includes SSM Services (SQL / Redis / SVC+WEB filter + IIS reset).
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
    Response: { summary:{total,running,stopped}, envs:{ ENV:{DM:[...],EA:[...]}, ... } }
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
                if "dev" in nl:
                    hits = ["DevMini"]
                else:
                    continue
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

def _run_ssm_ps(instance_id: str, commands: list[str], timeout=120):
    """
    Run PowerShell on the instance. Returns (ok, data|error_text).
    Longer timeout to handle slow SQL stops.
    """
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
    start = time.time()
    while time.time() - start < timeout:
        try:
            out = ssm.get_command_invocation(CommandId=cmd_id, InstanceId=instance_id)
        except Exception:
            time.sleep(1.0)
            continue

        st = out.get("Status")
        if st in ("Success", "Cancelled", "Failed", "TimedOut"):
            if st != "Success":
                err = out.get("StandardErrorContent") or out.get("StandardOutputContent") or st
                return False, (err or "").strip()
            return True, (out.get("StandardOutputContent") or "[]")
        time.sleep(1.2)

    return False, "timeout"

def _ps_json_list_sql():
    # emit lowercase keys + lowercase status
    return [rf"""
$names = @('MSSQL*','SQLSERVERAGENT*','SQLBrowser','SQL*')
$svcs = Get-Service -Name $names -ErrorAction SilentlyContinue |
  Select-Object @{{n='name';e={{$_.Name}}}},
                @{{n='display';e={{$_.DisplayName}}}},
                @{{n='status';e={{$_.Status.ToString().ToLower()}}}}
$svcs | ConvertTo-Json -Compress
"""]

def _ps_json_list_redis():
    return [rf"""
$svcs = Get-Service -Name 'Redis*' -ErrorAction SilentlyContinue |
  Select-Object @{{n='name';e={{$_.Name}}}},
                @{{n='display';e={{$_.DisplayName}}}},
                @{{n='status';e={{$_.Status.ToString().ToLower()}}}}
$svcs | ConvertTo-Json -Compress
"""]

def _ps_json_list_pattern(pattern: str):
    p = re.sub(r"'", "''", pattern)
    return [rf"""
$pat = '{p}'
$svcs = Get-Service | Where-Object {{ $_.Name -match $pat -or $_.DisplayName -match $pat }} |
  Select-Object @{{n='name';e={{$_.Name}}}},
                @{{n='display';e={{$_.DisplayName}}}},
                @{{n='status';e={{$_.Status.ToString().ToLower()}}}}
$svcs | ConvertTo-Json -Compress
"""]

def _ps_start(name: str):
    n = name.replace("'", "''")
    return [rf"""
$ErrorActionPreference = 'Stop'
try {{
  $svc = Get-Service -Name '{n}'
  if ($svc.Status -ne 'Running') {{
    Start-Service -Name '{n}'
    $svc = Get-Service -Name '{n}'
    $svc.WaitForStatus('Running','00:00:40')
  }}
  Start-Sleep -Seconds 1
  $svc = Get-Service -Name '{n}'
  [pscustomobject]@{{ name=$svc.Name; display=$svc.DisplayName; status=$svc.Status.ToString().ToLower() }} |
    ConvertTo-Json -Compress
}} catch {{
  [pscustomobject]@{{ name='{n}'; display='{n}'; status='error'; error=$_.Exception.Message }} |
    ConvertTo-Json -Compress
}}
"""]

def _ps_stop(name: str):
    n = name.replace("'", "''")
    return [rf"""
$ErrorActionPreference = 'Stop'
try {{
  $svc = Get-Service -Name '{n}'
  if ($svc.Status -ne 'Stopped') {{
    Stop-Service -Name '{n}' -Force
    $svc = Get-Service -Name '{n}'
    $svc.WaitForStatus('Stopped','00:01:20')
  }}
  Start-Sleep -Seconds 1
  $svc = Get-Service -Name '{n}'
  [pscustomobject]@{{ name=$svc.Name; display=$svc.DisplayName; status=$svc.Status.ToString().ToLower() }} |
    ConvertTo-Json -Compress
}} catch {{
  [pscustomobject]@{{ name='{n}'; display='{n}'; status='error'; error=$_.Exception.Message }} |
    ConvertTo-Json -Compress
}}
"""]

def _ps_iis_reset():
    return [r"""
$ErrorActionPreference = 'Stop'
try {
  iisreset /noforce
  @{ ok = $true; message = 'IIS reset issued' } | ConvertTo-Json -Compress
} catch {
  @{ ok = $false; error = $_.Exception.Message } | ConvertTo-Json -Compress
}
"""]

def _normalize_services(arr):
    """Return list of items containing BOTH key styles the UI might expect."""
    out = []
    for s in (arr or []):
        name = s.get("name") or s.get("Name")
        display = s.get("display") or s.get("DisplayName")
        status = (s.get("status") or s.get("Status") or "").lower()
        item = {
            "name": name,
            "display": display,
            "status": status,
            "Name": name,
            "DisplayName": display,
            "Status": status,
        }
        if "error" in s:
            item["error"] = s["error"]
        out.append(item)
    return out

def handle_services(body: dict):
    """
    UI contract (login.js):
      { instanceId, op: 'list'|'start'|'stop'|'iisreset', mode?: 'sql'|'redis'|'filter', query?, serviceName? }

    Backward compatible with old shape:
      { id, mode: 'list'|'start'|'stop'|'iisreset', pattern?, service?, instanceName?, kind? }
    """
    iid = (body.get("instanceId") or body.get("id") or "").strip()
    op  = (body.get("op") or body.get("mode") or "list").lower()  # operation
    # "mode" in the UI means list kind; accept several synonyms
    list_kind = (body.get("mode") or body.get("kind") or "").lower()
    instance_name = (body.get("instanceName") or "").lower()
    pattern = (body.get("query") or body.get("pattern") or "").strip()
    service = (body.get("serviceName") or body.get("service") or "").strip()

    if not iid:
        return _json(200, {"ok": False, "error": "missing_instance_id"})

    # derive list_kind if not provided
    if not list_kind:
        list_kind = (
            "filter" if ("svc" in instance_name or "web" in instance_name)
            else ("sql" if "sql" in instance_name else ("redis" if "redis" in instance_name else "generic"))
        )

    try:
        if op == "list":
            if list_kind == "sql":
                commands = _ps_json_list_sql()
            elif list_kind == "redis":
                commands = _ps_json_list_redis()
            elif list_kind in ("filter", "svcweb"):
                if len(pattern) < 2:
                    return _json(200, {"ok": False, "error": "enter_filter", "services": []})
                commands = _ps_json_list_pattern(pattern)
            else:
                return _json(200, {"ok": False, "error": "unsupported", "services": []})

            ok, out = _run_ssm_ps(iid, commands)
            if not ok:
                if out == "not_connected":
                    return _json(200, {"ok": False, "note": "not_connected", "services": []})
                return _json(200, {"ok": False, "error": out, "services": []})

            try:
                arr = json.loads(out) if out else []
                if isinstance(arr, dict):
                    arr = [arr]
                return _json(200, {"ok": True, "services": _normalize_services(arr)})
            except Exception:
                return _json(200, {"ok": False, "error": "parse_error", "services": []})

        elif op in ("start", "stop"):
            if not service:
                return _json(200, {"ok": False, "error": "missing_service", "services": []})
            commands = _ps_start(service) if op == "start" else _ps_stop(service)
            ok, out = _run_ssm_ps(iid, commands)
            if not ok:
                if out == "not_connected":
                    return _json(200, {"ok": False, "note": "not_connected", "services": []})
                return _json(200, {"ok": False, "error": out, "services": []})
            try:
                obj = json.loads(out) if out else {}
                arr = [obj] if isinstance(obj, dict) else (obj or [])
                return _json(200, {"ok": True, "services": _normalize_services(arr)})
            except Exception:
                return _json(200, {"ok": False, "error": "parse_error", "services": []})

        elif op == "iisreset":
            ok, out = _run_ssm_ps(iid, _ps_iis_reset())
            if not ok:
                if out == "not_connected":
                    return _json(200, {"ok": False, "note": "not_connected"})
                return _json(200, {"ok": False, "error": out})
            try:
                payload = json.loads(out) if out else {"ok": True}
                if "ok" not in payload:
                    payload["ok"] = True
                return _json(200, payload)
            except Exception:
                return _json(200, {"ok": True, "message": "IIS reset issued"})

        else:
            return _json(200, {"ok": False, "error": "bad_mode"})

    except Exception as e:
        return _json(200, {"ok": False, "error": str(e)})

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
    if path == "/bulk-action" and method == "POST":
        return handle_bulk(body)
    if path == "/services" and method == "POST":
        return handle_services(body)

    return _json(404, {"error": "not_found", "path": path, "method": method})
