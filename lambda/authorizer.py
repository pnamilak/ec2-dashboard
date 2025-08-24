import base64
import boto3
import os

ssm = boto3.client("ssm")

# Cache credentials across invocations
_EXPECTED = None

def _get_expected():
    global _EXPECTED
    if _EXPECTED:
        return _EXPECTED
    names = [
        "/ec2dash/auth/username", "/ec2dash/auth/password",
        "/ec2-auth/username", "/ec2-auth/password"
    ]
    # Pull in one call (unknown which exist)
    resp = ssm.get_parameters(Names=names, WithDecryption=True)
    vals = {p["Name"]: p["Value"] for p in resp.get("Parameters", [])}
    user = vals.get("/ec2dash/auth/username") or vals.get("/ec2-auth/username")
    pwd  = vals.get("/ec2dash/auth/password") or vals.get("/ec2-auth/password")
    _EXPECTED = (user or "", pwd or "")
    return _EXPECTED

def lambda_handler(event, _ctx):
    try:
        auth = (event.get("headers") or {}).get("authorization") or (event.get("headers") or {}).get("Authorization")
        if not auth or not auth.lower().startswith("basic "):
            return {"isAuthorized": False}

        raw = base64.b64decode(auth.split(" ",1)[1]).decode("utf-8", "ignore")
        user, _, pwd = raw.partition(":")
        exp_user, exp_pwd = _get_expected()

        ok = (user == exp_user) and (pwd == exp_pwd) and exp_user and exp_pwd
        return {"isAuthorized": bool(ok), "context": {"user": user if ok else ""}}
    except Exception:
        # On any error, fail closed
        return {"isAuthorized": False}
