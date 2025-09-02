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
sts = boto3.client("sts")
ACCOUNT_ID = sts.get_caller_identity()["Account"]
SENDER_ID_ARN = f"arn:aws:ses:{REGION}:{ACCOUNT_ID}:identity/{SES_SENDER}"

# ---------- Globals ----------
JWT_SECRET_CACHE = None
USERS_CACHE = {}

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
    if not username:
        return None
    if username in USERS_CACHE:
        return USERS_CACHE[username]

    base = f"{PARAM_USER_PREFIX}/{username}"
    rec = None

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
    return provided == s

# ---------- OVT helpers ----------
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
        expires_at = int((datetime.now(timezone.utc) + timedelta(minutes=10)).timestamp())

        if not OTP_TABLE_NAME:
            return _json(200, _err("server_not_configured", hint="OTP_TABLE env var is empty"))

        tbl = dynamodb.Table(OTP_TABLE_NAME)
        tbl.put_item(Item={"email": email, "code": code, "expires": expires_at})

        if SES_SENDER:
            try:
                ses.send_email(
                    Source=SES_SENDER,
                    SourceArn=SENDER_ID_ARN,   # <-- PINNED
                    ReturnPath=SES_SENDER,
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

def _detect_env(name: str) -> str:
  n = (name or "").lower()
  for tok in ENV_TOKENS or []:
    if tok.lower() in n:
      return tok.upper()
  return "ALL" if not ENV_TOKENS else "MISC"

def _detect_role(name: str) -> str:
  return "DM" if "dm" in (name or "").lower() else "EA"

def handle_instances():
  filters = [{"Name": "instance-state-name", "Values": ["running","stopped","pending","stopping"]}]
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
  summary = {
    "total":   len(items),
    "running": sum(1 for x in items if (x.get("state") or "").lower() == "running"),
    "stopped": sum(1 for x in items if (x.get("state") or "").lower() == "stopped"),
  }

  envs = {}
  for it in items:
    env  = _detect_env(it["name"])
    role = _detect_role(it["name"])
    envs.setdefault(env, {"DM": [], "EA": []})
    envs[env][role].append(it)

  return _json(200, _ok(instances=items, summary=summary, envs=envs))

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

# ---------- Services via SSM (unchanged) ----------
# ... (unchanged code you already had) ...

# ---------- Router ----------
def lambda_handler(event, context):
  try:
    path = (event.get("rawPath") or event.get("path") or "").strip()
    method = (event.get("requestContext", {}).get("http", {}).get("method") or event.get("httpMethod") or "GET").upper()
    body = _read_body(event)

    if path == "/request-otp" and method == "POST":
      return handle_request_otp(body)
    if path == "/verify-otp" and method == "POST":
      return handle_verify_otp(body)
    if path == "/login" and method == "POST":
      return handle_login(body)

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
    return _json(200, _err("unexpected_top", message=str(e)))
