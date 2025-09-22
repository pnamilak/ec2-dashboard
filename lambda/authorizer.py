import os, json, base64, hmac, hashlib, time, boto3

REGION    = os.environ.get("REGION","us-east-2")
JWT_PARAM = os.environ["JWT_PARAM"]
ssm = boto3.client("ssm", region_name=REGION)

def _b64pad(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "===")

def verify_jwt(token: str):
    try:
        h, p, s = token.split(".")
        secret = ssm.get_parameter(Name=JWT_PARAM, WithDecryption=True)["Parameter"]["Value"].encode()
        exp_sig = base64.urlsafe_b64encode(hmac.new(secret, f"{h}.{p}".encode(), hashlib.sha256).digest()).rstrip(b"=")
        if exp_sig.decode() != s: return None
        payload = json.loads(_b64pad(p))
        if int(time.time()) >= int(payload.get("exp",0)): return None
        return payload
    except Exception:
        return None

def allow(principal_id, ctx):
    return {
        "isAuthorized": True,
        "context": ctx
    }

def deny():
    return {"isAuthorized": False}


MUTATING = {("POST", "/instance-action"), ("POST", "/bulk-action")}

def _is_mutating(method, path, body):
    if (method, path) in MUTATING:
        return True
    if path == "/services" and method == "POST":
        op = (body.get("op") or "list").lower()
        return op in ("start", "stop", "iisreset")
    return False

def _norm_role(raw: str) -> str:
    r = (raw or "").lower()
    if r in ("readonly", "read", "viewer", "ro"):
        return "readonly"
    return r or "user"


# --- REPLACE your existing lambda_handler with this function ---
def lambda_handler(event, _context):
    # Get bearer
    headers = event.get("headers") or {}
    auth = headers.get("authorization") or headers.get("Authorization")
    if not auth or not auth.lower().startswith("bearer "):
        return deny()

    claims = verify_jwt(auth.split(" ", 1)[1])
    if not claims:
        return deny()

    role = _norm_role(claims.get("role"))
    sub  = claims.get("sub", "")

    # Method/path/body for route decision
    http   = (event.get("requestContext") or {}).get("http") or {}
    method = (http.get("method") or "").upper()
    path   = event.get("rawPath") or http.get("path") or ""

    try:
        body = json.loads(event.get("body") or "{}")
    except Exception:
        body = {}

    # Hard block non-admins on mutating routes
    if _is_mutating(method, path, body) and role not in ("admin", "owner"):
        return {"isAuthorized": False, "context": {"role": role, "sub": sub}}

    # Otherwise allow and pass role/sub to the API
    return {"isAuthorized": True, "context": {"role": role, "sub": sub}}
