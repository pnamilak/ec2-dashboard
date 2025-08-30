import os, json, base64, hmac, hashlib
import boto3

REGION    = os.environ.get("REGION", "us-east-2")
JWT_PARAM = os.environ["JWT_PARAM"]

ssm = boto3.client("ssm", region_name=REGION)

def _pad(b64s: str) -> str:
    return b64s + '='*((4 - len(b64s) % 4) % 4)

def _verify(token: str) -> dict:
    h, p, s = token.split(".")
    secret = ssm.get_parameter(Name=JWT_PARAM, WithDecryption=True)["Parameter"]["Value"].encode()
    sig = base64.urlsafe_b64encode(hmac.new(secret, f"{h}.{p}".encode(), hashlib.sha256).digest()).rstrip(b"=").decode()
    if sig != s:
        raise ValueError("bad sig")
    payload = json.loads(base64.urlsafe_b64decode(_pad(p)).decode())
    return payload

def lambda_handler(event, ctx):
    hdrs = event.get("headers") or {}
    auth = hdrs.get("Authorization") or hdrs.get("authorization") or ""
    if not auth.lower().startswith("bearer "):
        return {"isAuthorized": False}
    try:
        claims = _verify(auth.split(" ", 1)[1])
    except Exception:
        return {"isAuthorized": False}

    return {
        "isAuthorized": True,
        "context": {
            "sub":  str(claims.get("sub","")),
            "name": str(claims.get("name","")),
            "role": str(claims.get("role","user"))  # "admin" or "read"
        }
    }
