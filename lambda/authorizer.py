import os, json, time, base64, hmac, hashlib
import boto3

ssm = boto3.client("ssm")
_SECRET = None

def _pad(s: str) -> str:
    return s + "=" * ((4 - len(s) % 4) % 4)

def _get_secret():
    global _SECRET
    if _SECRET:
        return _SECRET
    name = os.environ.get("JWT_SECRET_PARAM", "/ec2-dashboard/auth/jwt_secret")
    try:
        r = ssm.get_parameter(Name=name, WithDecryption=True)
        _SECRET = r["Parameter"]["Value"].encode("utf-8")
    except Exception:
        _SECRET = None
    return _SECRET

def _verify_jwt(tok: str):
    try:
        h_b, p_b, s_b = tok.split(".")
        signing_input = (h_b + "." + p_b).encode("utf-8")
        secret = _get_secret()
        if not secret:
            return None
        sig_expect = hmac.new(secret, signing_input, hashlib.sha256).digest()
        sig = base64.urlsafe_b64decode(_pad(s_b))
        if not hmac.compare_digest(sig, sig_expect):
            return None
        payload = json.loads(base64.urlsafe_b64decode(_pad(p_b)).decode("utf-8"))
        if int(payload.get("exp", 0)) < int(time.time()):
            return None
        return payload
    except Exception:
        return None

def allow(pid: str):
    return {"isAuthorized": True, "context": {"principalId": pid}}

def deny():
    return {"isAuthorized": False}

def lambda_handler(event, _ctx):
    headers = event.get("headers") or {}
    auth = headers.get("authorization") or headers.get("Authorization") or ""
    domain = (os.environ.get("ALLOWED_EMAIL_DOMAIN", "domain.com") or "").lower()

    # 1) Bearer JWT (OTP flow)
    if auth.lower().startswith("bearer "):
        payload = _verify_jwt(auth.split(" ", 1)[1])
        if payload:
            email = (payload.get("email") or payload.get("sub") or "").lower()
            if email.endswith("@" + domain):
                return allow(email)
        return deny()

    # 2) Optional Basic fallback (for real dashboard API)
    if auth.lower().startswith("basic "):
        try:
            up = base64.b64decode(auth.split(" ", 1)[1]).decode("utf-8")
        except Exception:
            up = ""
        if os.environ.get("AUTH_FALLBACK") and up == os.environ["AUTH_FALLBACK"]:
            return allow(up.split(":", 1)[0])

    return deny()
