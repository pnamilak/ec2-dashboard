# lambda/authorizer.py
import base64
import json

HARDCODED_USERNAME = "pnamilak"
HARDCODED_PASSWORD = "Pravan@12"

def lambda_handler(event, context):
    # Debug log (shows up in CloudWatch)
    print("EVENT:", json.dumps(event))

    headers = event.get("headers") or {}
    # normalize header keys to lowercase to avoid casing issues
    headers_lc = { (k or "").lower(): v for k, v in headers.items() }
    token = headers_lc.get("authorization", "")

    if not token:
        return _deny("Missing Authorization header")

    # accept both "Basic <b64>" and raw base64 (some clients send raw)
    if token.lower().startswith("basic "):
        token = token[6:].strip()

    try:
        decoded = base64.b64decode(token).decode("utf-8", errors="strict")
        # allow ':' inside password
        username, password = decoded.split(":", 1)
        print(f"DECODED user={username}")

        if username == HARDCODED_USERNAME and password == HARDCODED_PASSWORD:
            print("AUTHORIZED")
            return _allow(event.get("routeArn", ""), username)

        print("INVALID_CREDENTIALS")
        return _deny("Invalid credentials")

    except Exception as e:
        print("EXCEPTION:", str(e))
        return _deny(str(e))

def _allow(method_arn, principal):
    return {
        "isAuthorized": True,
        "context": {"user": principal}
    }

def _deny(reason):
    return {
        "isAuthorized": False,
        "context": {"error": reason}
    }
