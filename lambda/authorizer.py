# lambda/authorizer.py
import base64, json, boto3

ssm = boto3.client("ssm")

def _get(name):
    try:
        return ssm.get_parameter(Name=name, WithDecryption=True)["Parameter"]["Value"]
    except ssm.exceptions.ParameterNotFound:
        return None

def _pw(val: str):
    v = (val or "").strip()
    if not v:
        return None
    if v.startswith("{"):
        try:
            obj = json.loads(v)
            p = str(obj.get("password", "")).strip()
            return p or None
        except Exception:
            return None
    return v

def lambda_handler(event, _ctx):
    hdrs = event.get("headers") or {}
    auth = hdrs.get("authorization") or hdrs.get("Authorization")
    if not auth or not auth.lower().startswith("basic "):
        print("AUTHZ: missing Basic header")
        return {"isAuthorized": False, "context": {"reason": "missing_basic"}}

    try:
        userpass = base64.b64decode(auth.split(" ", 1)[1]).decode("utf-8", "ignore")
        username, password = userpass.split(":", 1)
    except Exception as e:
        print(f"AUTHZ: bad Basic format: {e}")
        return {"isAuthorized": False, "context": {"reason": "bad_basic_format"}}

    username, password = username.strip(), password.strip()
    print(f"AUTHZ: user={username}")

    # 👉 Search ALL three prefixes
    prefixes = ["/ec2-auth/", "/ec2dash/auth/", "/ec2-dashboard/auth/"]

    used, stored = None, None
    for pref in prefixes:
        name = pref + username
        raw = _get(name)
        if raw is None:
            print(f"AUTHZ: not found: {name}")
            continue
        pw = _pw(raw)
        if not pw:
            print(f"AUTHZ: unparsable value at {name} (expect plain or {{\"password\":\"...\"}})")
            continue
        used, stored = name, pw
        break

    if not stored:
        print("AUTHZ: no usable credential found")
        return {"isAuthorized": False, "context": {"reason": "user_not_found_or_bad_value"}}

    ok = (password == stored)
    print(f"AUTHZ: compare={ok} param={used}")
    if not ok:
        return {"isAuthorized": False, "context": {"reason": "bad_password", "param": used or ""}}

    return {"isAuthorized": True, "context": {"principalId": username, "param": used or ""}}
