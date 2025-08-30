import os, json, base64, hmac, hashlib, boto3

REGION     = os.environ.get("REGION", "us-east-2")
JWT_PARAM  = os.environ.get("JWT_PARAM")
ssm        = boto3.client("ssm", region_name=REGION)

def _b64pad(s):
    return s + "=" * (-len(s) % 4)

def verify_jwt(token: str):
    secret = ssm.get_parameter(Name=JWT_PARAM, WithDecryption=True)["Parameter"]["Value"].encode()
    try:
        h, p, sig = token.split(".")
        msg = f"{h}.{p}".encode()
        exp = base64.urlsafe_b64decode(_b64pad(sig))
        mac = hmac.new(secret, msg, hashlib.sha256).digest()
        if not hmac.compare_digest(exp, mac):
            return None
        payload = json.loads(base64.urlsafe_b64decode(_b64pad(p)))
        return payload
    except Exception:
        return None

def lambda_handler(event, context):
    auth = (event.get("headers",{}) or {}).get("authorization") or event.get("headers",{}).get("Authorization")
    if not auth or not auth.lower().startswith("bearer "):
        return {"isAuthorized": False}
    payload = verify_jwt(auth.split(" ",1)[1])
    if not payload:
        return {"isAuthorized": False}
    # Simple responses for HTTP API
    return {
        "isAuthorized": True,
        "context": {
            "sub":  str(payload.get("sub","")),
            "role": str(payload.get("role","read"))
        }
    }
