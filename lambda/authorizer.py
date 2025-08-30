import os, json, base64, hmac, hashlib, time
import boto3

REGION = os.environ.get("REGION", "us-east-2")
JWT_PARAM = os.environ.get("JWT_PARAM")
ssm = boto3.client("ssm", region_name=REGION)

def _b64pad(s):
    return s + "=" * (-len(s) % 4)

def verify_jwt(token: str):
    secret = ssm.get_parameter(Name=JWT_PARAM, WithDecryption=True)["Parameter"]["Value"].encode()
    try:
        p1, p2, sig = token.split(".")
    except ValueError:
        return None
    msg = f"{p1}.{p2}".encode()
    exp_sig = base64.urlsafe_b64encode(hmac.new(secret, msg, hashlib.sha256).digest()).rstrip(b"=").decode()
    if not hmac.compare_digest(exp_sig, sig):
        return None
    payload = json.loads(base64.urlsafe_b64decode(_b64pad(p2)))
    return payload

def lambda_handler(event, context):
    auth = event.get("headers", {}).get("authorization") or event.get("headers", {}).get("Authorization")
    if not auth or not auth.lower().startswith("bearer "):
        return {"isAuthorized": False}

    payload = verify_jwt(auth.split(" ",1)[1])
    if not payload:
        return {"isAuthorized": False}

    role = str(payload.get("role","user"))
    name = str(payload.get("name", payload.get("sub","user")))

    # Pass context to routes
    return {
        "isAuthorized": True,
        "context": {
            "sub": payload.get("sub",""),
            "role": role,
            "name": name,
            "iat": str(payload.get("iat", int(time.time())))
        }
    }
