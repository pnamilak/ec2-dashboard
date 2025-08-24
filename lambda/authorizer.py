import base64
import boto3
import os

_ssm = boto3.client('ssm')

# Defaults align with your IAM policy ("parameter/ec2-auth/*")
PARAM_USER = os.environ.get('PARAM_USER', '/ec2-auth/username')
PARAM_PASS = os.environ.get('PARAM_PASS', '/ec2-auth/password')

def _get_param(name):
    return _ssm.get_parameter(Name=name, WithDecryption=True)['Parameter']['Value']

def _resp(allow: bool, route_arn: str, reason: str = ''):
    # HTTP API simple responses
    return {
        "isAuthorized": allow,
        "context": {"reason": reason} if reason else {},
        "routeArn": route_arn
    }

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
        u = _get_param(PARAM_USER)
        p = _get_param(PARAM_PASS)
        if user == u and pwd == p:
            return _resp(True, route_arn, 'ok')
        return _resp(False, route_arn, 'invalid_creds')
    except Exception:
        # Fail closed, but do NOT bubble as 500 — return unauthorized
        return _resp(False, route_arn, 'ssm_error')
