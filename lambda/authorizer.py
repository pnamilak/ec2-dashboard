import base64
import boto3
import os

_ssm = boto3.client('ssm')

PARAM_USER = os.environ.get('PARAM_USER')
PARAM_PASS = os.environ.get('PARAM_PASS')

FALLBACK_USERS = ['/ec2-auth/username', '/ec2dash/auth/username']
FALLBACK_PASSW = ['/ec2-auth/password', '/ec2dash/auth/password']

def _get_param_first(candidates):
    for name in candidates:
        try:
            return _ssm.get_parameter(Name=name, WithDecryption=True)['Parameter']['Value']
        except Exception:
            continue
    raise RuntimeError('no_param')

def _resp(allow: bool, route_arn: str, reason: str = ''):
    return {"isAuthorized": allow, "context": {"reason": reason} if reason else {}, "routeArn": route_arn}

def lambda_handler(event, context):
    route_arn = event.get('routeArn')
    headers = (event.get('headers') or {})
    auth = headers.get('authorization') or headers.get('Authorization')

    if not auth or not auth.startswith('Basic '):
        return _resp(False, route_arn, 'missing_basic')

    try:
        enc = auth.split(' ', 1)[1]
        user, pwd = base64.b64decode(enc).decode('utf-8').split(':', 1)
    except Exception:
        return _resp(False, route_arn, 'bad_header')

    try:
        u = PARAM_USER or _get_param_first(FALLBACK_USERS)
        p = PARAM_PASS or _get_param_first(FALLBACK_PASSW)
        ok = (user == u and pwd == p)
        return _resp(ok, route_arn, 'ok' if ok else 'invalid_creds')
    except Exception:
        return _resp(False, route_arn, 'ssm_error')
