import os, json, hmac, hashlib, base64, time, boto3

REGION = os.environ.get("REGION","us-east-1")
JWT_PARAM = os.environ["JWT_PARAM"]
ssm = boto3.client("ssm", region_name=REGION)

def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "==")

def _verify(token: str, secret: str) -> bool:
    try:
        parts = token.split(".")
        if len(parts) != 3: return False
        header_b64, payload_b64, sig_b64 = parts
        signing_input = f"{header_b64}.{payload_b64}".encode()
        expected = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
        if not hmac.compare_digest(expected, _b64url_decode(sig_b64)):
            return False
        payload = json.loads(_b64url_decode(payload_b64))
        if "exp" in payload and time.time() > int(payload["exp"]):
            return False
        return True
    except Exception:
        return False

def lambda_handler(event, context):
    # HTTP API simple responses
    auth = (event.get("headers") or {}).get("authorization") or (event.get("headers") or {}).get("Authorization")
    if not auth or not auth.lower().startswith("bearer "):
        return {"isAuthorized": False}
    token = auth.split(" ",1)[1]
    secret = ssm.get_parameter(Name=JWT_PARAM, WithDecryption=True)["Parameter"]["Value"]
    ok = _verify(token, secret)
    return {"isAuthorized": bool(ok)}
