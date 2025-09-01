# lambda/handler.py
# -----------------------------------------------------------------------------
# EC2 Dashboard API – OTP, login, instances, actions, services.
# Hardened for robust error reporting (no API Gateway 500 bubbles).
# -----------------------------------------------------------------------------

import os
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
ENV_TOKENS        = [e.strip() for e in (ENV_NAMES_STR or "").split(",") if e.strip()]

# ---------- Clients ----------
ec2 = boto3.client("ec2", region_name=REGION)
ssm = boto3.client("ssm", region_name=REGION)
ses = boto3.client("ses", region_name=REGION)
dynamodb = boto3.resource("dynamodb", region_name=REGION)
ssm_param = boto3.client("ssm", region_name=REGION)

# ---------- Globals ----------
JWT_SECRET_CACHE = None
USERS_CACHE = {}  # cache SSM user records for the runtime

# ---------- Utils ----------
def _now():
    return datetime.now(timezone.utc)

def _json(status, body, headers=None):
    h = {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"}
    if headers:
        h.update(headers)
    return {"statusCode": status, "headers": h, "body": json.dumps(body, default=str)}

def _b64url(data_bytes):
    return base64.urlsafe_b64encode(data_bytes).rstrip(b"=").decode()

def _jwt_secret():
    global JWT_SECRET_CACHE
    if JWT_SECRET_CACHE:
        return JWT_SECRET_CACHE
    p = ssm_param.get_parameter(Name=JWT_PARAM, WithDecryption=True)
    JWT_SECRET_CACHE = p["Parameter"]["Value"].encode()
    return JWT_SECRET_CACHE

def _sign_jwt(claims, ttl_minutes=60):
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

# ---------- SSM users ----------
def _ssm_get(name, decrypt=True):
    return ssm_param.get_parameter(Name=name, WithDecryption=decrypt)["Parameter"]["Value"]

def _get_user_record(username):
    """
    Load from SSM as:
    A) JSON SecureString at {PREFIX}/{username}
       {"password":"plain:...|sha256:<hex>", "role":"admin|reader|user", "email":"user@..."}
    B) Split params at {PREFIX}/{username}/password, /role, /email
    """
    if not username:
        return None
    if username in USERS_CACHE:
        return USERS_CACHE[username]

    base = f"{PARAM_USER_PREFIX}/{username}"
    rec = None

    # Try JSON secret
    try:
        raw = _ssm_get(base, decrypt=True)
        try:
            obj = json.loads(raw)
            if isinstance(obj, dict) and ("password" in obj or "hash" in obj):
                pwd   = obj.get("password") or obj.get("hash")
                role  = (obj.get("role") or "user").strip() or "user"
                email = (obj.get("email") or "").strip().lower() or None
                rec = {"username": username, "password": pwd, "role": role, "email": email}
            else:
                rec = {"username": username, "password": raw, "role": "user", "email": None}
        except Exception:
            rec = {"username": username, "password": raw, "role": "user", "email": None}
    except ClientError:
        # Try split params
        try:
            pwd = _ssm_get(f"{base}/password", decrypt=True)
            try:
                role = _ssm_get(f"{base}/role", decrypt=False) or "user"
            except ClientError:
                role = "user"
            try:
                email = (_ssm_get(f"{base}/email", decrypt=False) or "").strip().lower() or None
            except ClientError:
                email = None
            rec = {"username": username, "password": pwd, "role": role, "email": email}
        except ClientError:
            rec = None

    if rec:
        rec["role"] = (rec.get("role") or "user").strip() or "user"
        USERS_CACHE[username] = rec
    return rec

def _verify_password(stored, provided):
    if not isinstance(stored, str):
        return False
    s = stored.strip()
    if s.lower().startswith("sha256:"):
        want = s.split(":", 1)[1].strip().lower()
        got = hashlib.sha256(provided.encode()).hexdigest()
        return got == want
    if s.lower().startswith("plain:"):
        return provided == s.split(":", 1)[1]
    return provided == s  # back-compat literal

# ---------- OVT helpers (scan & filter in Python; no Attr import) ----------
def _issue_ovt_for_email(email):
    if not OTP_TABLE_NAME:
        return None, None
    ovt = base64.urlsafe_b64encode(os.urandom(24)).rstrip(b"=").decode()
    exp_ms = int(time.time() * 1000) + 10 * 60 * 1000
    tbl = dynamodb.Table(OTP_TABLE_NAME)
    tbl.update_item(
        Key={"email": email},
        UpdateExpression="SET ovt=:o, ovt_exp_ms=:e",
        ExpressionAttributeValues={":o": ovt, ":e": exp_ms},
    )
    return ovt, exp_ms

def _ovt_record(ovt):
    if not (OTP_TABLE_NAME and ovt):
        return None
    tbl = dynamodb.Table(OTP_TABLE_NAME)
    # small table → ok to scan; filter in python to avoid Attr import
    scan = tbl.scan(ProjectionExpression="email, code, expires, ovt, ovt_exp_ms")
    items = scan.get("Items", []) or []
    now_ms = int(time.time() * 1000)
    for it in items:
        if (it.get("ovt") == ovt) and int(it.get("ovt_exp_ms", 0)) > now_ms:
            return it
    return None

def _validate_ovt(ovt):
    return _ovt_record(ovt) is not None

def _ovt_get_email(ovt):
    rec = _ovt_record(ovt)
    if not rec:
        return None
    return (rec.get("email") or "").strip().lower() or None

# ---------- OTP ----------
def handle_request_otp(body):
    try:
        email = (body.get("email") or "").strip().lower()
        if not email or "@" not in email:
            return _json(200, _err("invalid_email"))
        if ALLOWED_DOMAIN and not email.endswith("@" + ALLOWED_DOMAIN):
            return _json(200, _err("domain_not_allowed"))

        code = f"{random.randint(0, 999999):06d}"
        expires_at = int((_now() + timedelta(minutes=10)).timestamp())

        if not OTP_TABLE_NAME:
            return _json(200, _err("server_not_configured", hint="OTP_TABLE env var is empty"))

        tbl = dynamodb.Table(OTP_TABLE_NAME)
        tbl.put_item(Item={"email": email, "code": code, "expires": expires_at})

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
                return _json(200, _ok(dev=True, code=code, ses_error=str(e)))

        return _json(200, _ok(dev=True, code=code))
    except ClientError as e:
        return _json(200, _err("ddb_or_ses_error", message=str(e)))
    except Exception as e:
        return _json(200, _err("unexpected", message=str(e)))

def handle_verify_otp(body):
    try:
        email = (body.get("email") or "").strip().lower()
        code  = (body.get("code") or "").strip()
        if not (email and code):
            return _json(200, _err("missing_params"))

        if not OTP_TABLE_NAME:
            return _json(200, _err("server_not_configured", hint="OTP_TABLE env var is empty"))

        tbl = dynamodb.Table(OTP_TABLE_NAME)
        res = tbl.get_item(Key={"email": email}).get("Item")
        if not res:
            return _json(200, _err("not_found"))
        if int(res.get("expires", 0)) < int(time.time()):
            return _json(200, _err("expired"))
        if res.get("code") != code:
            return _json(200, _err("invalid_code"))

        ovt, ovt_exp_ms = _issue_ovt_for_email(email)
        if not ovt:
            return _json(200, _err("ovt_issue_failed"))
        return _json(200, _ok(ovt=ovt, ovt_exp=ovt_exp_ms))
    except ClientError as e:
        return _json(200, _err("ddb_error", message=str(e)))
    except Exception as e:
        return _json(200, _err("unexpected", message=str(e)))

# ---------- Login (dual-mode) ----------
def handle_login(body):
    try:
        # Mode A: OTP login
        email = (body.get("email") or "").strip().lower()
        code  = (body.get("code") or "").strip()
        if email and code:
            tbl = dynamodb.Table(OTP_TABLE_NAME)
            res = tbl.get_item(Key={"email": email}).get("Item")
            if not res or res.get("code") != code or int(res.get("expires", 0)) < int(time.time()):
                return _json(200, _err("invalid_login"))
            role = "user"
            token = _sign_jwt({"sub": email, "role": role})
            return _json(200, _ok(token=token, role=role, user={"username": email}))

        # Mode B: username/password (+ optional OVT)
        username = (body.get("username") or "").strip()
        password = (body.get("password") or "")
        ovt      = (body.get("ovt") or "").strip()
        if not (username and password):
            return _json(200, _err("invalid_login"))

        ovt_email = None
        if ovt:
            ovt_email = _ovt_get_email(ovt)
            if not ovt_email:
                return _json(200, _err("ovt_invalid"))

        rec = _get_user_record(username)
        if not rec or not _verify_password(rec.get("password", ""), password):
            return _json(200, _err("invalid_login"))

        assigned_email = (rec.get("email") or "").strip().lower() if rec else None
        if assigned_email and ovt_email and assigned_email != ovt_email:
            return _json(200, _err("email_mismatch", message="Assigned email does not match OTP email"))

        role = rec.get("role", "user")
        token = _sign_jwt({"sub": username, "role": role})
        return _json(200, _ok(token=token, role=role, user={"username": username}))
    except Exception as e:
        return _json(200, _err("unexpected", message=str(e)))

# ---------- EC2 ----------
def _name_tag(tags):
    for t in tags or []:
        if t.get("Key") == "Name":
            return t.get("Value")
    return ""

def handle_instances():
    filters = [{"Name": "instance-state-name", "Values": ["running", "stopped", "pending", "stopping"]}]
    if ENV_TOKENS:
        filters.append({"Name": "tag:Name", "Values": [f"*{tok}*" for tok in ENV_TOKENS]})
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

# ---------- Services via SSM (unchanged from your working version) ----------
PS_LIST_SQL = r"""
$svcs = Get-Service | Where-Object {
    $_.Name -like 'MSSQL*' -or
    $_.Name -like 'SQLSERVERAGENT*' -or
    $_.DisplayName -match 'SQL Server'
}
$svcs | Select-Object Name, DisplayName, @{Name='Status';Expression={$_.Status.ToString()}} | ConvertTo-Json
"""
PS_LIST_REDIS = r"""
$svcs = Get-Service | Where-Object { $_.Name -like 'Redis*' -or $_.DisplayName -like 'Redis*' }
$svcs | Select-Object Name, DisplayName, @{Name='Status';Expression={$_.Status.ToString()}} | ConvertTo-Json
"""
PS_LIST_FILTER = r"""
$svcs = Get-Service | Where-Object { $_.Name -match $Pattern -or $_.DisplayName -match $Pattern }
$svcs | Select-Object Name, DisplayName, @{Name='Status';Expression={$_.Status.ToString()}} | ConvertTo-Json
"""
PS_START = r"""
param([string]$Name)
Start-Service -Name $Name -ErrorAction Stop
Get-Service -Name $Name | Select-Object Name, DisplayName, @{Name='Status';Expression={$_.Status.ToString()}} | ConvertTo-Json
"""
PS_STOP = r"""
param([string]$Name)
Stop-Service -Name $Name -Force -ErrorAction Stop
Get-Service -Name $Name | Select-Object Name, DisplayName, @{Name='Status';Expression={$_.Status.ToString()}} | ConvertTo-Json
"""
PS_IISRESET = r"""
iisreset /restart
"OK"
"""

def _send_ps(instance_id, script, params=None, timeout=60):
    try:
        resp = ssm.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunPowerShellScript",
            Parameters={"commands": [script]},
            TimeoutSeconds=timeout,
        )
    except ClientError as e:
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
    iid = (body.get("instanceId") or body.get("id") or "").strip()
    raw_op = (body.get("op") or "").lower().strip()
    raw_mode = (body.get("mode") or body.get("kind") or "").lower().strip()
    op = raw_op if raw_op in ("list", "start", "stop", "iisreset") else "list"
    instance_name = (body.get("instanceName") or "").lower()
    query = (body.get("query") or body.get("pattern") or "").strip()
    service = (body.get("serviceName") or body.get("service") or "").strip()
    mode = raw_mode
    if mode in ("", "list", "services", "service", "generic"):
        if query:
            mode = "filter"
        elif "sql" in instance_name:
            mode = "sql"
        elif "redis" in instance_name:
            mode = "redis"
        elif ("svc" in instance_name) or ("web" in instance_name):
            mode = "filter"
        else:
            mode = "filter"
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
                    script = r"""Get-Service | Select-Object -First 200 Name, DisplayName, @{Name='Status';Expression={$_.Status.ToString()}} | ConvertTo-Json"""
                    status, out, err = _send_ps(iid, script)
                else:
                    pat = (query or "").replace('"', '`"')
                    script = f'$Pattern = "{pat}";\n{PS_LIST_FILTER}'
                    status, out, err = _send_ps(iid, script)
            else:
                return _json(200, _err("unsupported", details={"mode": mode}))

            if status != "Success":
                return _json(200, _err("ssm_error", status=status, stderr=err))

            try:
                arr = json.loads(out) if out else []
            except Exception:
                arr = []
            if isinstance(arr, dict):
                arr = [arr]
            result = []
            for s in arr or []:
                result.append({
                    "name": s.get("Name") or s.get("name"),
                    "displayName": s.get("DisplayName") or s.get("displayName"),
                    "status": s.get("Status") or "Unknown",
                })
            return _json(200, _ok(services=result, mode=mode))

        if op in ("start", "stop"):
            if not service:
                return _json(200, _err("missing_service_name"))
            ps = PS_START if op == "start" else PS_STOP
            name_esc = service.replace('"', '`"')
            script = f'$Name = "{name_esc}";\n{ps}'
            status, out, err = _send_ps(iid, script)
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

# ---------- Router (top-level try/except) ----------
def lambda_handler(event, context):
    try:
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

        # Protected (custom authorizer on API Gateway; JWT not parsed here)
        if path == "/instances" and method == "GET":
            return handle_instances()
        if path == "/instance-action" and method == "POST":
            return handle_instance_action(body)
        if path == "/bulk-action" and method == "POST":
            return handle_bulk(body)
        if path == "/services" and method == "POST":
            return handle_services(body)

        return _json(404, {"error": "not_found", "path": path, "method": method})
    except Exception as e:
        # Convert any routing error to JSON (avoid API Gateway 500)
        return _json(200, _err("unexpected_top", message=str(e)))
