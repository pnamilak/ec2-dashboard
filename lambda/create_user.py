# lambda/create_user.py
import json
import os
import boto3
import base64
from botocore.exceptions import ClientError

REGION = os.environ.get("REGION") or os.environ.get("AWS_REGION", "us-east-2")
PARAM_USER_PREFIX = os.environ.get("PARAM_USER_PREFIX", "/ec2-dashboard/users")

ssm = boto3.client("ssm", region_name=REGION)

def _json(payload, code=200):
    return {
        "statusCode": code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "authorization,content-type",
            "Access-Control-Allow-Methods": "OPTIONS,POST,GET"
        },
        "body": json.dumps(payload, separators=(",", ":"))
    }

def _lower(s): return (s or "").strip().lower()

def _authorizer_role(event):
    # Works with HTTP API Request authorizer (simple responses) or lambda payload
    ctx = event.get("requestContext", {}).get("authorizer", {}) or {}
    if isinstance(ctx, dict):
        if "role" in ctx:
            return _lower(ctx.get("role"))
        lam = ctx.get("lambda", {})
        if isinstance(lam, dict) and "role" in lam:
            return _lower(lam.get("role"))
    return ""

def _get_body(event):
    raw = event.get("body") or "{}"
    if event.get("isBase64Encoded"):
        raw = base64.b64decode(raw).decode("utf-8", "ignore")
    try:
        return json.loads(raw)
    except Exception:
        return None

def _param_name(username: str) -> str:
    return f"{PARAM_USER_PREFIX}/{username}"

def _exists(name: str) -> bool:
    try:
        ssm.get_parameter(Name=name, WithDecryption=False)
        return True
    except ssm.exceptions.ParameterNotFound:
        return False
    except ClientError:
        # treat any other access problem as not existing to avoid leaking info
        return False

def handler(event, _context):
    if event.get("requestContext", {}).get("http", {}).get("method") == "OPTIONS":
        return _json({"ok": True})

    role = _authorizer_role(event)
    if role in ("readonly", "viewer", "ro"):
        return _json({"ok": False, "error": "forbidden"}, 403)

    body = _get_body(event)
    if body is None:
        return _json({"ok": False, "error": "invalid_json"}, 400)

    # Inputs
    username  = (body.get("username") or "").strip()
    email     = (body.get("email") or "").strip()
    access    = _lower(body.get("access") or body.get("role") or "readonly")
    password  = (body.get("password") or "").strip()
    name      = (body.get("name") or "").strip()
    overwrite = bool(body.get("overwrite") or False)
    checkOnly = bool(body.get("checkOnly") or False)

    if not username:
        return _json({"ok": False, "error": "missing_username"}, 400)

    pname = _param_name(username)

    # 1) Existence probe (used by UI first)
    if checkOnly:
        return _json({"ok": True, "exists": _exists(pname), "param": pname})

    # 2) Validate required fields for create/update
    if not email or not password:
        return _json({"ok": False, "error": "missing_fields"}, 400)

    if not password.startswith("plain:"):
        password = "plain:" + password

    if access not in ("admin", "readonly"):
        access = "readonly"

    payload = {
        "username": username,
        "email": email,
        "role": access,
        "password": password
    }
    if name:
        payload["name"] = name

    exists_now = _exists(pname)
    if exists_now and not overwrite:
        return _json(
            {"ok": False, "error": "exists", "param": pname, "message": "User already exists; pass overwrite=true to replace."},
            409
        )

    try:
        ssm.put_parameter(
            Name=pname,
            Type="SecureString",
            Value=json.dumps(payload, separators=(",", ":")),
            Overwrite=True  # we still send true; logic gate above controls behavior
        )
        return _json({"ok": True, "param": pname, "stored": payload, "replaced": exists_now})
    except ClientError as e:
        return _json({"ok": False, "error": "ssm_error", "detail": str(e)}, 500)
