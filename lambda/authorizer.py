# lambda/authorizer.py
import base64, json, os, boto3

VERSION = "v5"
ssm = boto3.client("ssm")

def _get(name: str):
    try:
        return ssm.get_parameter(Name=name, WithDecryption=True)["Parameter"]["Value"]
    except ssm.exceptions.ParameterNotFound:
        return None
    except Exception as e:
        # If you see AccessDenied here, you need kms:Decrypt on the SSM key
        print(f"AUTHZ[{VERSION}]: SSM error for {name}: {e}")
        return None

def _pw(val: str | None):
    v = (val or "").strip()
    if not v:
        return None
    if v.startswith("{"):
        try:
            obj = json.loads(v)
            p = str(obj.get("password", "")).strip()
            return p or None
        except Exception as e:
            print(f"AUTHZ[{VERSION}]: JSON parse error: {e}")
            return None
    return v

def lambda_handler(event, _ctx):
    hdrs = event.get("headers") or {}
    auth = hdrs.get("authorization") or hdrs.get("Authorization")
    if not auth or not auth.lower().startswith("basic "):
        print(f"AUTHZ[{VERSION}]: missing Basic header")
        return {"isAuthorized": False, "context": {"reason": "missing_basic"}}

    try:
        userpass = base64.b64decode(auth.split(" ", 1)[1]).decode("utf-8", "ignore")
        username, password = userpass.split(":", 1)
    except Exception as e:
        print(f"AUTHZ[{VERSION}]: bad Basic format: {e}")
        return {"isAuthorized": False, "context": {"reason": "bad_basic_format"}}

    username, password = username.strip(), password.strip()
    print(f"AUTHZ[{VERSION}]: user={username}")

    # Optional temporary override for diagnostics
    fb = (os.environ.get("AUTH_FALLBACK") or "").strip()
    if fb:
        try:
            fu, fp = fb.split(":", 1)
            if username == fu and password == fp:
                print(f"AUTHZ[{VERSION}]: override matched (AUTH_FALLBACK)")
                return {"isAuthorized": True, "context": {"user": username, "param": "AUTH_FALLBACK"}}
        except Exception:
            pass

    # Look under all known prefixes
    prefixes = ["/ec2-auth/", "/ec2dash/auth/", "/ec2-dashboard/auth/"]
    used, stored = None, None
    for pref in prefixes:
        name = pref + username
        raw = _get(name)
        if raw is None:
            print(f"AUTHZ[{VERSION}]: not found: {name}")
            continue
        pw = _pw(raw)
        if not pw:
            print(f"AUTHZ[{VERSION}]: unparsable at {name} (expect plain or {{\"password\":\"...\"}})")
            continue
        used, stored = name, pw
        break

    if not stored:
        print(f"AUTHZ[{VERSION}]: no usable credential for {username}")
        return {"isAuthorized": False, "context": {"reason": "user_not_found_or_bad_value"}}

    ok = (password == stored)
    print(f"AUTHZ[{VERSION}]: compare={ok} param={used}")
    if not ok:
        return {"isAuthorized": False, "context": {"reason": "bad_password", "param": used or ""}}

    return {"isAuthorized": True, "context": {"user": username, "param": used or ""}}
