import os, json, base64, hmac, hashlib, time
import boto3

REGION = os.environ.get("REGION", "us-east-2")
JWT_PARAM = os.environ.get("JWT_PARAM")

ssm = boto3.client("ssm", region_name=REGION)

def _b64url_decode(s: str) -> bytes:
    pad = '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)

def _sign(msg: bytes, secret: bytes) -> str:
    return base64.urlsafe_b64encode(hmac.new(secret, msg, hashlib.sha256).digest()).rstrip(b"=").decode()

def verify_jwt(token: str) -> dict:
    secret = ssm.get_parameter(Name=JWT_PARAM, WithDecryption=True)["Parameter"]["Value"].encode()
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("bad jwt")
    h, p, s = parts
    expect = _sign(f"{h}.{p}".encode(), secret)
    if not hmac.compare_digest(expect, s):
        raise ValueError("sig mismatch")
    payload = json.loads(_b64url_decode(p).decode())
    now = int(time.time())
    if payload.get("iat", 0) < now - 43200:
        raise ValueError("jwt too old")
    return payload

def lambda_handler(event, context):
    auth_hdr = (event.get("headers") or {}).get("authorization") or (event.get("headers") or {}).get("Authorization")
    if not auth_hdr or not auth_hdr.lower().startswith("bearer "):
        return {"isAuthorized": False}
    token = auth_hdr.split(" ", 1)[1].strip()
    try:
        claims = verify_jwt(token)
        ctx = {k: (str(v) if not isinstance(v, str) else v) for k, v in claims.items()}
        return {"isAuthorized": True, "context": ctx}
    except Exception:
        return {"isAuthorized": False}
