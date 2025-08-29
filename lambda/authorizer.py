import os, json, base64, hmac, hashlib, boto3, time

region    = os.environ.get("REGION")
jwt_param = os.environ.get("JWT_PARAM")
ssm = boto3.client("ssm", region_name=region)

def _read_secret():
    p = ssm.get_parameter(Name=jwt_param, WithDecryption=True)
    return p["Parameter"]["Value"].encode()

def _verify(token: str):
    try:
        body_b64, sig_b64 = token.split(".")
        body = base64.urlsafe_b64decode(body_b64 + "==")
        sig  = base64.urlsafe_b64decode(sig_b64 + "==")
        secret = _read_secret()
        good = hmac.compare_digest(sig, hmac.new(secret, body, hashlib.sha256).digest())
        if not good: return None
        payload = json.loads(body)
        if payload.get("exp",0) < time.time():
            return None
        return payload
    except Exception:
        return None

def lambda_handler(event, context):
    # HTTP API "simple response" authorizer
    token = (event.get("headers") or {}).get("authorization") or (event.get("headers") or {}).get("Authorization")
    if token and token.lower().startswith("bearer "):
        token = token.split(" ",1)[1]
    else:
        token = None

    payload = _verify(token) if token else None
    if payload:
        return {"isAuthorized": True, "context": {"sub": payload.get("sub","")}}
    else:
        return {"isAuthorized": False}
