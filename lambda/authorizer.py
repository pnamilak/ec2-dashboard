import base64
import boto3
import os

_ssm = boto3.client('ssm')

PARAM_USER = os.environ.get('PARAM_USER','/ec2dash/auth/username')
PARAM_PASS = os.environ.get('PARAM_PASS','/ec2dash/auth/password')

def _get_param(name):
    return _ssm.get_parameter(Name=name, WithDecryption=True)['Parameter']['Value']

def _deny(routeArn):
    return {'isAuthorized': False, 'context': {'reason': 'unauthorized'}, 'routeArn': routeArn}

def _allow(routeArn):
    return {'isAuthorized': True, 'context': {'scope': 'basic'}, 'routeArn': routeArn}

def authorizer(event, context):
    routeArn = event.get('routeArn')
    hdrs = (event.get('headers') or {})
    hdr = hdrs.get('authorization') or hdrs.get('Authorization')
    if not hdr or not hdr.startswith('Basic '):
        return _deny(routeArn)
    try:
        enc = hdr.split(' ',1)[1]
        user, pwd = base64.b64decode(enc).decode('utf-8').split(':',1)
    except Exception:
        return _deny(routeArn)

    try:
        u = _get_param(PARAM_USER)
        p = _get_param(PARAM_PASS)
        return _allow(routeArn) if (user == u and pwd == p) else _deny(routeArn)
    except Exception:
        return _deny(routeArn)
