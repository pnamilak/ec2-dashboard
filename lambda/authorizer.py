import os, json, base64, hmac, hashlib, boto3

REGION    = os.environ.get("REGION","us-east-2")
JWT_PARAM = os.environ.get("JWT_PARAM")

ssm = boto3.client("ssm", region_name=REGION)

def _b64pad(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "===")

def verify_jwt(token: str):
    try:
        h, p, s = token.split(".")
        secret = ssm.get_parameter(Name=JWT_PARAM, WithDecryption=True)["Parameter"]["Value"].encode()
        exp_sig = base64.urlsafe_b64encode(hmac.new(secret, f"{h}.{p}".encode(), hashlib.sha256).digest()).rstrip(b"=")
        if exp_sig.decode() != s:
            return None
        payload = json.loads(_b64pad(p))
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

def lambda_handler(event, _context):
    auth = (event.get("headers",{}) or {}).get("authorization") or event.get("headers",{}).get("Authorization")
    if not auth or not auth.lower().startswith("bearer "):
        return deny()
    payload = verify_jwt(auth.split(" ",1)[1])
    if not payload:
        return deny()
    return allow(payload.get("sub","user"), {"role": payload.get("role","read")})
