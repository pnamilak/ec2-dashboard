import os, json, time, uuid, base64, hmac, hashlib
import boto3
from botocore.exceptions import ClientError

# ---------- env ----------
REGION            = os.environ.get("REGION", "us-east-2")
OTP_TABLE         = os.environ["OTP_TABLE"]
SES_SENDER        = os.environ["SES_SENDER"]
ALLOWED_DOMAIN    = os.environ.get("ALLOWED_DOMAIN", "example.com").lower().strip()
PARAM_USER_PREFIX = os.environ["PARAM_USER_PREFIX"]            # e.g. /ec2-dashboard/users
JWT_PARAM         = os.environ["JWT_PARAM"]
ENV_NAMES         = [e.strip() for e in os.environ.get("ENV_NAMES", "").split(",") if e.strip()]

# ---------- clients / resources ----------
ddb   = boto3.resource("dynamodb", region_name=REGION)
ses   = boto3.client("ses", region_name=REGION)
ssm   = boto3.client("ssm", region_name=REGION)
ec2   = boto3.client("ec2", region_name=REGION)
table = ddb.Table(OTP_TABLE)

# ---------- helpers ----------
def _ok(data):      return {"statusCode": 200, "headers": {"content-type": "application/json"}, "body": json.dumps(data)}
def _bad(code, msg): return {"statusCode": code, "headers": {"content-type": "application/json"}, "body": json.dumps({"error": msg})}

def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")

def _jwt_for(username: str, role: str, ttl_seconds: int = 3600) -> str:
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    now    = int(time.time())
    payload = _b64url(json.dumps({"sub": username, "role": role, "iat": now, "exp": now + ttl_seconds}).encode())
    secret = ssm.get_parameter(Name=JWT_PARAM, WithDecryption=True)["Parameter"]["Value"].encode()
    sig    = _b64url(hmac.new(secret, f"{header}.{payload}".encode(), hashlib.sha256).digest())
    return f"{header}.{payload}.{sig}"

def _read_user(username: str):
    """
    Reads SSM parameter /<prefix>/<username> that contains either:
       password|role|email|display   OR   password,role,email,display
    Returns dict: {password, role, email, display}
    """
    name = f"{PARAM_USER_PREFIX.rstrip('/')}/{username}"
    val  = ssm.get_parameter(Name=name, WithDecryption=True)["Parameter"]["Value"]
    # Accept both separators
    parts = [p.strip() for p in (val.split("|") if "|" in val else val.split(","))]
    parts += ["", "", "", ""]  # pad
    password, role, email, display = parts[:4]
    role   = (role or "read").strip().lower()
    email  = (email or "").strip().lower()
    return {"password": password, "role": role, "email": email, "display": display or username}

def _normalize_email(s: str) -> str:
    return (s or "").strip().lower()

# ---------- OTP ----------
def request_otp(data):
    email = _normalize_email(data.get("email"))
    if not email or not email.endswith("@"+ALLOWED_DOMAIN):
        return _bad(403, "not_allowed_domain")
    code = str(uuid.uuid4().int)[-6:]
    table.put_item(Item={"email": email, "code": code, "expiresAt": int(time.time()) + 300})
    ses.send_email(
        Source=SES_SENDER,
        Destination={"ToAddresses": [email]},
        Message={
            "Subject": {"Data": "Your EC2 Dashboard OTP"},
            "Body": {"Text": {"Data": f"Your OTP code is {code}. It expires in 5 minutes."}}
        }
    )
    return _ok({"ok": True})

def verify_otp(data):
    email = _normalize_email(data.get("email"))
    code  = (data.get("code") or "").strip()
    it = table.get_item(Key={"email": email}).get("Item")
    if not it or it.get("code") != code or int(time.time()) > int(it.get("expiresAt", 0)):
        return _bad(401, "invalid_otp")
    # OTP checked once → remove it
    table.delete_item(Key={"email": email})
    return _ok({"ok": True, "email": email})

# ---------- login ----------
def login(data):
    username   = (data.get("username") or "").strip()
    password   = (data.get("password") or "")
    otp_email  = _normalize_email(data.get("otp_email"))

    if not username or not password:
        return _bad(400, "missing_credentials")
    if not otp_email:
        return _bad(400, "missing_verified_otp")

    try:
        u = _read_user(username)
    except Exception:
        return _bad(401, "invalid_user")

    # domain enforcement and email match
    if not otp_email.endswith("@"+ALLOWED_DOMAIN):
        return _bad(403, "not_allowed_domain")
    if u["email"] and _normalize_email(u["email"]) != otp_email:
        return _bad(401, "otp_email_mismatch")

    if u["password"] != password:
        return _bad(401, "invalid_password")

    role  = u["role"] or "read"
    token = _jwt_for(username, role, 3600)
    body  = {"token": token, "role": role, "user": {"username": username, "name": u["display"] or username, "role": role}}
    return {
        "statusCode": 200,
        "headers": {
            "content-type": "application/json",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "authorization,content-type",
            "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
        },
        "body": json.dumps(body),
    }

# ---------- simple auth guard for protected endpoints ----------
def _auth(event):
    h = event.get("headers") or {}
    auth = h.get("authorization") or h.get("Authorization")
    if not auth or not auth.lower().startswith("bearer "):
        raise Exception("no_token")

# ---------- EC2 (unchanged from your working version) ----------
def instances(event, ctx):
    r = ec2.describe_instances(Filters=[{"Name":"instance-state-name","Values":["running","stopped"]}])
    envs = {e: {"DM": [], "EA": []} for e in ENV_NAMES}
    summary = {"total": 0, "running": 0, "stopped": 0}
    for res in r.get("Reservations", []):
        for inst in res.get("Instances", []):
            st   = inst["State"]["Name"]
            name = next((t["Value"] for t in inst.get("Tags", []) if t["Key"] == "Name"), "")
            if not name: 
                continue
            env = None; lname = name.lower()
            for e in ENV_NAMES:
                if e.lower() in lname:
                    env = e; break
            if not env: 
                continue
            bucket = "DM" if any(x in lname for x in ["dmsql","dmsvc","dmweb","dream","sql"]) else "EA"
            envs[env][bucket].append({"id": inst["InstanceId"], "name": name, "state": st})
            summary["total"]   += 1
            summary["running"] += (st == "running")
            summary["stopped"] += (st == "stopped")
    return _ok({"summary": summary, "envs": envs})

# ---------- (rest of your services/SSM code stays as you currently have it) ----------

def lambda_handler(event, ctx):
    path   = (event.get("rawPath") or event.get("path") or "").lower()
    method = (event.get("requestContext",{}).get("http",{}).get("method") or event.get("httpMethod") or "GET").upper()

    if method == "OPTIONS":
        return _ok({"ok": True})

    if path.endswith("/request-otp") and method == "POST": return request_otp(json.loads(event.get("body") or "{}"))
    if path.endswith("/verify-otp")  and method == "POST": return verify_otp(json.loads(event.get("body") or "{}"))
    if path.endswith("/login")       and method == "POST": return login(json.loads(event.get("body") or "{}"))

    try:
        _auth(event)
    except Exception:
        return _bad(401, "unauthorized")

    if path.endswith("/instances")       and method == "GET":  return instances(event, ctx)
    if path.endswith("/services")        and method == "POST": return services(event, ctx)          # your existing function
    if path.endswith("/instance-action") and method == "POST": return instance_action(event, ctx)   # your existing function

    return _bad(404, "not_found")
