import base64, json, os
import boto3

ssm = boto3.client('ssm')

def _get_param(name: str):
    try:
        resp = ssm.get_parameter(Name=name, WithDecryption=True)
        return resp['Parameter']['Value']
    except ssm.exceptions.ParameterNotFound:
        return None

def _password_from_value(val: str):
    # Accept a plain password, or {"password": "..."} JSON
    v = val.strip()
    if not v:
        return None
    if v.startswith('{'):
        try:
            obj = json.loads(v)
            pwd = str(obj.get('password', '')).strip()
            return pwd or None
        except Exception:
            return None
    return v

def lambda_handler(event, _ctx):
    # We’re a REQUEST authorizer with simple responses.
    # Expect Basic auth in header.
    auth = (event.get('headers') or {}).get('authorization') or (event.get('headers') or {}).get('Authorization')
    if not auth or not auth.lower().startswith('basic '):
        return {"isAuthorized": False, "context": {"reason": "missing_basic"}}

    try:
        decoded = base64.b64decode(auth.split(' ',1)[1]).decode('utf-8', 'ignore')
        username, password = decoded.split(':', 1)
    except Exception:
        return {"isAuthorized": False, "context": {"reason": "bad_basic_format"}}

    username = username.strip()
    password = password.strip()

    # Try both prefixes
    prefixes = ["/ec2-auth/", "/ec2dash/auth/"]
    param_name_used = None
    stored_pwd = None

    for pref in prefixes:
        name = pref + username
        v = _get_param(name)
        if v is None:
            continue
        p = _password_from_value(v)
        if p:
            stored_pwd = p
            param_name_used = name
            break

    if not stored_pwd:
        # User not found or value unparsable
        return {"isAuthorized": False, "context": {"reason": "user_not_found_or_bad_value"}}

    if password != stored_pwd:
        return {"isAuthorized": False, "context": {"reason": "bad_password", "param": param_name_used or ""}}

    # Authorized
    # You can add arbitrary items to context; handler can read them.
    return {
        "isAuthorized": True,
        "context": {
            "principalId": username,
            "param": param_name_used or ""
        }
    }
