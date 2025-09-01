# lambda/handler.py
# -----------------------------------------------------------------------------
# EC2 Dashboard API (single Lambda) – OTP, login, instances, actions, services.
# This version includes a tolerant Services API (SQL / Redis / SVC+WEB filter
# + IIS reset) that accepts both the new and legacy request shapes.
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
from botocore.exceptions import ClientError, EndpointConnectionError

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
ses = boto3.client("ses", region_name=REGION)
dynamodb = boto3.resource("dynamodb", region_name=REGION)
ssm_param = boto3.client("ssm", region_name=REGION)

# ---------- Globals ----------
JWT_SECRET_CACHE = None


# ---------- Helpers ----------
def _now():
    return datetime.now(timezone.utc)

def _json(status, body, headers=None):
    h = {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"}
    if headers:
        h.update(headers)
    return {"statusCode": status, "headers": h, "body": json.dumps(body, default=str)}

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def _unpad_b64url(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def _jwt_secret():
    global JWT_SECRET_CACHE
    if JWT_SECRET_CACHE:
        return JWT_SECRET_CACHE
    p = ssm_param.get_parameter(Name=JWT_PARAM, WithDecryption=True)
    JWT_SECRET_CACHE = p["Parameter"]["Value"].encode()
    return JWT_SECRET_CACHE

def _sign_jwt(claims: dict, ttl_minutes=60):
    header = {"alg": "HS256", "typ": "JWT"}
    now = int(time.time())
    claims = {**claims, "iat": now, "exp": now + ttl_minutes * 60}
    h64 = _b64url(json.dumps(header, separators=(",", ":"), sort_keys=True).encode())
    p64 = _b64url(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode())
    msg = f"{h64}.{p64}".encode()
    sig = hmac.new(_jwt_secret(), msg, hashlib.sha256).digest()
    return f"{h64}.{p64}.{_b64url(sig)}"


def _read_body(event):
    body = event.get("body")
    if body and event.get("isBase64Encoded"):
        body = base64.b64decode(body).decode()
    try:
        return json.loads(body) if body else {}
    except Exception:
        return {}

def _ok(ok=True, **extra):
    return {"ok": ok, **extra}

def _err(code, **extra):
    return {"ok": False, "error": code, **extra}


# ---------- OTP + Login ----------
def handle_request_otp(body):
    email = (body.get("email") or "").strip().lower()
    if not email or "@" not in email:
        return _json(200, _err("invalid_email"))
    if ALLOWED_DOMAIN and not email.endswith("@" + ALLOWED_DOMAIN):
        return _json(200, _err("domain_not_allowed"))

    code = f"{random.randint(0, 999999):06d}"
    expires_at = int((_now() + timedelta(minutes=10)).timestamp())

    if not OTP_TABLE_NAME:
        return _json(500, _err("server_not_configured"))

    tbl = dynamodb.Table(OTP_TABLE_NAME)
    tbl.put_item(Item={"email": email, "code": code, "expires": expires_at})

    # Send email via SES
    if SES_SENDER:
        try:
            ses.send_email(
                Source=SES_SENDER,
                Destination={"ToAddresses": [email]},
                Message={
                    "Subject": {"Data": "Your EC2 Dashboard OTP"},
                    "Body": {"Text": {"Data": f"Your OTP is {code}. It expires in 10 minutes."}},
                },
            )
        except ClientError as e:
            # Fall through; for dev, return code in response
            return _json(200, _ok(dev=True, code=code))

    # In non-SES environments, return OTP for dev use (comment this out in prod)
    return _json(200, _ok(dev=True, code=code))

def handle_verify_otp(body):
    email = (body.get("email") or "").strip().lower()
    code  = (body.get("code") or "").strip()
    if not (email and code):
        return _json(200, _err("missing_params"))

    tbl = dynamodb.Table(OTP_TABLE_NAME)
    res = tbl.get_item(Key={"email": email}).get("Item")
    if not res:
        return _json(200, _err("not_found"))

    if int(res.get("expires", 0)) < int(time.time()):
        return _json(200, _err("expired"))

    if res.get("code") != code:
        return _json(200, _err("invalid_code"))

    return _json(200, _ok())

def handle_login(body):
    email = (body.get("email") or "").strip().lower()
    code  = (body.get("code") or "").strip()
    # Optionally re-verify inline:
    tbl = dynamodb.Table(OTP_TABLE_NAME)
    res = tbl.get_item(Key={"email": email}).get("Item")
    if not res or res.get("code") != code or int(res.get("expires", 0)) < int(time.time()):
        return _json(200, _err("invalid_login"))

    token = _sign_jwt({"sub": email})
    return _json(200, _ok(token=token))


# ---------- EC2: list + actions ----------
def _name_tag(tags):
    for t in tags or []:
        if t.get("Key") == "Name":
            return t.get("Value")
    return ""

def handle_instances():
    # Optionally filter by env tokens if provided in ENV_NAMES
    filters = [{"Name": "instance-state-name", "Values": ["running", "stopped", "pending", "stopping"]}]
    if ENV_TOKENS:
        # Match env in Name tag, e.g., NAQA6, NAQA3, etc.
        name_filters = [{"Name": "tag:Name", "Values": [f"*{tok}*" for tok in ENV_TOKENS]}]
        filters.extend(name_filters)

    resp = ec2.describe_instances(Filters=filters)
    items = []
    for r in resp.get("Reservations", []):
        for i in r.get("Instances", []):
            items.append({
                "id": i["InstanceId"],
                "name": _name_tag(i.get("Tags")),
                "state": i.get("State", {}).get("Name"),
                "type": i.get("InstanceType"),
                "publicIp": i.get("PublicIpAddress"),
                "privateIp": i.get("PrivateIpAddress"),
                "platform": "windows" if i.get("Platform") == "windows" or i.get("PlatformDetails","").lower().startswith("windows") else "linux",
            })
    # Sort by name, then id
    items.sort(key=lambda x: (x["name"] or "", x["id"]))
    return _json(200, _ok(instances=items))

def _ec2_action(instance_id, op):
    if op == "start":
        ec2.start_instances(InstanceIds=[instance_id])
    elif op == "stop":
        ec2.stop_instances(InstanceIds=[instance_id])
    elif op == "reboot":
        ec2.reboot_instances(InstanceIds=[instance_id])
    else:
        return _err("unsupported_action")
    return _ok()

def handle_instance_action(body):
    iid = (body.get("instanceId") or body.get("id") or "").strip()
    op  = (body.get("op") or body.get("action") or "").strip().lower()
    if not iid or not op:
        return _json(200, _err("missing_params"))
    try:
        return _json(200, _ec2_action(iid, op))
    except ClientError as e:
        return _json(200, _err("aws_error", message=str(e)))

def handle_bulk(body):
    ids = body.get("instanceIds") or body.get("ids") or []
    op  = (body.get("op") or "").lower()
    if not ids or not op:
        return _json(200, _err("missing_params"))

    try:
        if op == "start":
            ec2.start_instances(InstanceIds=ids)
        elif op == "stop":
            ec2.stop_instances(InstanceIds=ids)
        elif op == "reboot":
            ec2.reboot_instances(InstanceIds=ids)
        else:
            return _json(200, _err("unsupported_action"))
        return _json(200, _ok())
    except ClientError as e:
        return _json(200, _err("aws_error", message=str(e)))


# ---------- SSM Services (list / start / stop / IIS reset) ----------
PS_LIST_SQL = r"""
$svcs = Get-Service | Where-Object {
    $_.Name -like 'MSSQL*' -or $_.Name -like 'SQLSERVERAGENT*' -or $_.Name -like 'SQLBrowser' -or $_.Name -like 'SQL*'
}
$svcs | Select-Object Name, DisplayName, Status | ConvertTo-Json
"""

PS_LIST_REDIS = r"""
$svcs = Get-Service | Where-Object { $_.Name -like 'Redis*' -or $_.DisplayName -like 'Redis*' }
$svcs | Select-Object Name, DisplayName, Status | ConvertTo-Json
"""

PS_LIST_FILTER = r"""
param([string]$Pattern)
$svcs = Get-Service | Where-Object { $_.Name -match $Pattern -or $_.DisplayName -match $Pattern }
$svcs | Select-Object Name, DisplayName, Status | ConvertTo-Json
"""

PS_START = r"""
param([string]$Name)
Start-Service -Name $Name -ErrorAction Stop
Get-Service -Name $Name | Select-Object Name, DisplayName, Status | ConvertTo-Json
"""

PS_STOP = r"""
param([string]$Name)
Stop-Service -Name $Name -Force -ErrorAction Stop
Get-Service -Name $Name | Select-Object Name, DisplayName, Status | ConvertTo-Json
"""

PS_IISRESET = r"""
iisreset /restart
"OK"
"""

def _send_ps(instance_id: str, script: str, params=None, timeout=60):
    try:
        resp = ssm.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunPowerShellScript",
            Parameters={"commands": [script], **({} if not params else params)},
            TimeoutSeconds=timeout,
        )
    except ClientError as e:
        # Target might not be connected or not managed
        if "InvalidInstanceId" in str(e) or "TargetNotConnected" in str(e):
            raise RuntimeError("ssm_not_connected")
        raise

    cid = resp["Command"]["CommandId"]
    time.sleep(1.0)

    for _ in range(30):
        inv = ssm.get_command_invocation(CommandId=cid, InstanceId=instance_id)
        status = inv.get("Status")
        if status in ("Success", "Cancelled", "TimedOut", "Failed"):
            stdout = inv.get("StandardOutputContent", "").strip()
            stderr = inv.get("StandardErrorContent", "").strip()
            return status, stdout, stderr
        time.sleep(1.0)

    return "TimedOut", "", ""

def _normalize_services_payload(body):
    """
    Accept both the new and legacy shapes and infer a sensible list 'mode'.
    New shape (preferred):
      { instanceId, op:'list'|'start'|'stop'|'iisreset', mode:'sql'|'redis'|'filter', query?, serviceName? }
    Legacy examples:
      { id, mode:'list'|'start'|'stop'|'iisreset', pattern?, service?, instanceName?, kind? }
    """
    iid = (body.get("instanceId") or body.get("id") or "").strip()
    op  = (body.get("op") or body.get("mode") or "list").lower()
    mode = (body.get("mode") or body.get("kind") or "").lower()
    instance_name = (body.get("instanceName") or "").lower()
    query = (body.get("query") or body.get("pattern") or "").strip()
    service = (body.get("serviceName") or body.get("service") or "").strip()

    # Back-compat: if mode is '' or 'list' or generic, infer from name/query
    if mode in ("", "list", "services", "service", "generic"):
        if query:
            mode = "filter"
        elif "sql" in instance_name:
            mode = "sql"
        elif "redis" in instance_name:
            mode = "redis"
        elif ("svc" in instance_name) or ("web" in instance_name):
            mode = "filter"   # typical app/IIS svc hosts
        else:
            mode = "filter"   # safe default

    return iid, op, mode, query, service

def handle_services(body):
    try:
        iid, op, mode, query, service = _normalize_services_payload(body)
        if not iid:
            return _json(200, _err("missing_instance_id"))

        if op == "iisreset":
            status, out, err = _send_ps(iid, PS_IISRESET)
            if status != "Success":
                return _json(200, _err("ssm_error", status=status, stderr=err))
            return _json(200, _ok(result="OK"))

        if op == "list":
            if mode == "sql":
                status, out, err = _send_ps(iid, PS_LIST_SQL)
            elif mode == "redis":
                status, out, err = _send_ps(iid, PS_LIST_REDIS)
            elif mode == "filter":
                if not query:
                    # Empty query → list all services (trim to common/interesting)
                    script = r"""Get-Service | Select-Object -First 200 Name, DisplayName, Status | ConvertTo-Json"""
                    status, out, err = _send_ps(iid, script)
                else:
                    status, out, err = _send_ps(iid, PS_LIST_FILTER, params={"executionTimeout": ["3600"], "commands": [PS_LIST_FILTER], "param.PPattern": [query]})
                    # Above param wiring differs across accounts; safe path:
                    if status == "Success" and not out.strip():
                        # Try explicit param binding
                        status, out, err = _send_ps(iid, PS_LIST_FILTER + f'\n#\n$Pattern="{query}"\n' + PS_LIST_FILTER)
            else:
                return _json(200, _err("unsupported", details={"mode": mode}))

            if status != "Success":
                return _json(200, _err("ssm_error", status=status, stderr=err))

            try:
                arr = json.loads(out) if out else []
            except Exception:
                arr = []
            # Normalize to array of {name, displayName, status}
            result = []
            if isinstance(arr, dict):
                arr = [arr]
            for s in arr or []:
                result.append({
                    "name": s.get("Name") or s.get("name"),
                    "displayName": s.get("DisplayName") or s.get("displayName"),
                    "status": s.get("Status") or s.get("status"),
                })
            return _json(200, _ok(services=result, mode=mode))

        if op in ("start", "stop"):
            if not service:
                return _json(200, _err("missing_service_name"))
            ps = PS_START if op == "start" else PS_STOP
            status, out, err = _send_ps(iid, ps + f'\n#\n$Name="{service}"\n' + ps)
            if status != "Success":
                return _json(200, _err("ssm_error", status=status, stderr=err))
            try:
                obj = json.loads(out)
            except Exception:
                obj = {"Name": service, "DisplayName": service, "Status": "Unknown"}
            return _json(200, _ok(service={
                "name": obj.get("Name") or service,
                "displayName": obj.get("DisplayName") or service,
                "status": obj.get("Status") or "Unknown",
            }))

        return _json(200, _err("unsupported", details={"op": op}))
    except RuntimeError as e:
        if str(e) == "ssm_not_connected":
            return _json(200, _err("ssm_not_connected"))
        return _json(200, _err("runtime_error", message=str(e)))
    except (ClientError, EndpointConnectionError) as e:
        msg = str(e)
        if "TargetNotConnected" in msg:
            return _json(200, _err("ssm_not_connected"))
        return _json(200, _err("aws_error", message=msg))


# ---------- Lambda entry ----------
def lambda_handler(event, context):
    path = (event.get("rawPath") or event.get("path") or "").strip()
    method = (event.get("requestContext", {}).get("http", {}).get("method") or event.get("httpMethod") or "GET").upper()
    body = _read_body(event)

    # Public
    if path == "/request-otp" and method == "POST":
        return handle_request_otp(body)
    if path == "/verify-otp" and method == "POST":
        return handle_verify_otp(body)
    if path == "/login" and method == "POST":
        return handle_login(body)

    # Protected (via custom authorizer in API Gateway; no JWT parsing here)
    if path == "/instances" and method == "GET":
        return handle_instances()
    if path == "/instance-action" and method == "POST":
        return handle_instance_action(body)
    if path == "/bulk-action" and method == "POST":
        return handle_bulk(body)
    if path == "/services" and method == "POST":
        return handle_services(body)

    return _json(404, {"error": "not_found", "path": path, "method": method})
