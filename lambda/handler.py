# lambda/handler.py
# -----------------------------------------------------------------------------
# EC2 Dashboard API – OTP, login, instances, actions, services.
# No UI/flow changes. /services now supports Windows (PowerShell) AND Linux (systemd).
# Also: IIS reset is blocked for SQL/Redis/Rabbit instances (name heuristic).
# + Linux services fallback for redis/rabbit when first pass returns no rows.
# -----------------------------------------------------------------------------
import json, re, shlex, subprocess
import os, time, hmac, base64, hashlib, random
from datetime import datetime, timedelta, timezone

import boto3
from botocore.exceptions import ClientError, EndpointConnectionError


# ---- extras used only by services stdout parsing ----
import io, csv, re

# ---------- Environment ----------
REGION            = os.environ.get("REGION", "us-east-2")
OTP_TABLE_NAME    = os.environ.get("OTP_TABLE", "")
SES_SENDER        = os.environ.get("SES_SENDER", "")
ALLOWED_DOMAIN    = os.environ.get("ALLOWED_DOMAIN", "gmail.com")
PARAM_USER_PREFIX = os.environ.get("PARAM_USER_PREFIX", "/ec2-dashboard/users")
JWT_PARAM         = os.environ.get("JWT_PARAM", "/ec2-dashboard/jwt-secret")
ENV_NAMES_STR     = os.environ.get("ENV_NAMES", "")  # comma separated

# normalize ENV tokens once, but keep originals for display
ENV_TOKENS        = [e.strip() for e in (ENV_NAMES_STR or "").split(",") if e.strip()]
ENV_TOKENS_LOWER  = [e.lower() for e in ENV_TOKENS]

# ---------- Clients ----------
ec2       = boto3.client("ec2", region_name=REGION)
ssm       = boto3.client("ssm", region_name=REGION)
ses       = boto3.client("ses", region_name=REGION)
ddb       = boto3.resource("dynamodb", region_name=REGION)
ssm_param = boto3.client("ssm", region_name=REGION)

# ---------- Globals ----------
JWT_SECRET_CACHE = None
USERS_CACHE = {}

# ---------- Utils ----------
def _now():           return datetime.now(timezone.utc)
def _b64url(b):       return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def _ok(ok=True, **k):  return {"ok": ok, **k}
def _err(code, **k):    return {"ok": False, "error": code, **k}

def _json(status, body, headers=None):
    h = {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Headers": "authorization, Authorization, content-type, Content-Type",
        "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    }
    if headers:
        h.update(headers)
    return {
        "statusCode": status,
        "headers": h,
        "body": json.dumps(body, default=str),
    }


# --- RBAC helpers ---
def _auth_ctx(event):
    a = (event.get("requestContext") or {}).get("authorizer") or {}
    return a.get("lambda") or a

def _caller_role(event) -> str:
    return (_auth_ctx(event).get("role") or "").lower()

def _require_admin(event):
    role = _caller_role(event)
    if role not in ("admin", "owner"):
        return _json(403, {"ok": False, "error": "forbidden (readonly user)"})
    return None

def _read_body(event):
    body = event.get("body")
    if body and event.get("isBase64Encoded"):
        body = base64.b64decode(body).decode()
    try:
        return json.loads(body) if body else {}
    except Exception:
        return {}

def _jwt_secret():
    global JWT_SECRET_CACHE
    if JWT_SECRET_CACHE: return JWT_SECRET_CACHE
    p = ssm_param.get_parameter(Name=JWT_PARAM, WithDecryption=True)
    JWT_SECRET_CACHE = p["Parameter"]["Value"].encode()
    return JWT_SECRET_CACHE

def _sign_jwt(claims, ttl_minutes=60):
    header = {"alg":"HS256","typ":"JWT"}
    now = int(time.time())
    claims = {**claims, "iat": now, "exp": now + ttl_minutes*60}
    h64 = _b64url(json.dumps(header, separators=(",",":"), sort_keys=True).encode())
    p64 = _b64url(json.dumps(claims, separators=(",",":"), sort_keys=True).encode())
    msg = f"{h64}.{p64}".encode()
    sig = hmac.new(_jwt_secret(), msg, hashlib.sha256).digest()
    return f"{h64}.{p64}.{_b64url(sig)}"

# ---------- Users from SSM ----------
def _ssm_get(name, decrypt=True):
    return ssm_param.get_parameter(Name=name, WithDecryption=decrypt)["Parameter"]["Value"]

def _get_user_record(username):
    if not username: return None
    if username in USERS_CACHE: return USERS_CACHE[username]

    base = f"{PARAM_USER_PREFIX}/{username}"
    rec = None

    try:
        raw = _ssm_get(base, True)
        try:
            obj = json.loads(raw)
            if isinstance(obj, dict) and ("password" in obj or "hash" in obj):
                rec = {
                    "username": username,
                    "password": obj.get("password") or obj.get("hash"),
                    "role": (obj.get("role") or "user").strip() or "user",
                    "email": (obj.get("email") or "").strip().lower() or None,
                    "name": (obj.get("name") or obj.get("displayName") or "").strip() or None,
                }
            else:
                rec = {"username": username, "password": raw, "role": "user", "email": None}
        except Exception:
            rec = {"username": username, "password": raw, "role": "user", "email": None}
    except ClientError:
        try:
            pwd = _ssm_get(f"{base}/password", True)
            try: role = _ssm_get(f"{base}/role", False) or "user"
            except ClientError: role = "user"
            try: email = (_ssm_get(f"{base}/email", False) or "").strip().lower() or None
            except ClientError: email = None
            try: name = (_ssm_get(f"{base}/name", False) or "").strip() or None
            except ClientError: pass
            rec = {"username": username, "password": pwd, "role": role, "email": email, "name": name if "name" in locals() else None}
        except ClientError:
            rec = None

    if rec:
        rec["role"] = (rec.get("role") or "user").strip() or "user"
        USERS_CACHE[username] = rec
    return rec

def _verify_password(stored, provided):
    if not isinstance(stored, str): return False
    s = stored.strip()
    if s.lower().startswith("sha256:"):
        want = s.split(":",1)[1].strip().lower()
        got  = hashlib.sha256(provided.encode()).hexdigest()
        return got == want
    if s.lower().startswith("plain:"):
        return provided == s.split(":",1)[1]
    return provided == s

# ---------- OTP ----------
def _issue_ovt_for_email(email):
    if not OTP_TABLE_NAME: return None, None
    ovt = base64.urlsafe_b64encode(os.urandom(24)).rstrip(b"=").decode()
    exp_ms = int(time.time()*1000) + 10*60*1000
    tbl = ddb.Table(OTP_TABLE_NAME)
    tbl.update_item(
        Key={"email": email},
        UpdateExpression="SET ovt=:o, ovt_exp_ms=:e",
        ExpressionAttributeValues={":o": ovt, ":e": exp_ms},
    )
    return ovt, exp_ms

def _ovt_record(ovt):
    if not (OTP_TABLE_NAME and ovt): return None
    tbl = ddb.Table(OTP_TABLE_NAME)
    scan = tbl.scan(ProjectionExpression="email, code, expires, ovt, ovt_exp_ms")
    items = scan.get("Items", []) or []
    now_ms = int(time.time()*1000)
    for it in items:
        if (it.get("ovt") == ovt) and int(it.get("ovt_exp_ms", 0)) > now_ms:
            return it
    return None

def _ovt_get_email(ovt):
    rec = _ovt_record(ovt)
    return (rec.get("email") or "").strip().lower() if rec else None

def handle_request_otp(body):
    try:
        email = (body.get("email") or "").strip().lower()
        if not email or "@" not in email:
            return _json(200, _err("invalid_email"))
        if ALLOWED_DOMAIN and not email.endswith("@"+ALLOWED_DOMAIN):
            return _json(200, _err("domain_not_allowed"))

        code = f"{random.randint(0, 999999):06d}"
        expires_at = int((_now() + timedelta(minutes=10)).timestamp())

        if not OTP_TABLE_NAME:
            return _json(200, _err("server_not_configured", hint="OTP_TABLE env var is empty"))

        ddb.Table(OTP_TABLE_NAME).put_item(Item={"email": email, "code": code, "expires": expires_at})

        if SES_SENDER:
            try:
                ses.send_email(
                    Source=SES_SENDER,
                    Destination={"ToAddresses": [email]},
                    Message={
                        "Subject": {"Data": "Your EC2 Dashboard OTP"},
                        "Body": {"Text": {"Data": f"Your OTP is {code}. It expires in 10 minutes."}},
                    },
                )
            except ClientError as e:
                return _json(200, _ok(dev=True, code=code, ses_error=str(e)))

        return _json(200, _ok(dev=True, code=code))
    except ClientError as e:
        return _json(200, _err("ddb_or_ses_error", message=str(e)))
    except Exception as e:
        return _json(200, _err("unexpected", message=str(e)))

def handle_verify_otp(body):
    try:
        email = (body.get("email") or "").strip().lower()
        code  = (body.get("code") or "").strip()
        if not (email and code):
            return _json(200, _err("missing_params"))

        if not OTP_TABLE_NAME:
            return _json(200, _err("server_not_configured", hint="OTP_TABLE env var is empty"))

        res = ddb.Table(OTP_TABLE_NAME).get_item(Key={"email": email}).get("Item")
        if not res:
            return _json(200, _err("not_found"))
        if int(res.get("expires", 0)) < int(time.time()):
            return _json(200, _err("expired"))
        if res.get("code") != code:
            return _json(200, _err("invalid_code"))

        ovt, ovt_exp_ms = _issue_ovt_for_email(email)
        if not ovt:
            return _json(200, _err("ovt_issue_failed"))
        return _json(200, _ok(ovt=ovt, ovt_exp=ovt_exp_ms))
    except ClientError as e:
        return _json(200, _err("ddb_error", message=str(e)))
    except Exception as e:
        return _json(200, _err("unexpected", message=str(e)))

def handle_login(body):
    try:
        # ---------------- Mode A: OTP ----------------
        email = (body.get("email") or "").strip().lower()
        code  = (body.get("code") or "").strip()
        if email and code:
            res = ddb.Table(OTP_TABLE_NAME).get_item(Key={"email": email}).get("Item")
            if (not res) or (res.get("code") != code) or (int(res.get("expires", 0)) < int(time.time())):
                return _json(200, _err("invalid_login"))

            # Name = local-part of email
            otp_name = email.split("@")[0]

            token = _sign_jwt({
                "sub": email,
                "username": email,
                "role": "user",
                "access": "user",
                "email": email,
                "name": otp_name
            })

            return _json(200, _ok(
                token=token,
                role="user",
                user={"username": email, "email": email, "name": otp_name}
            ))

        # ------------- Mode B: user/pass (+ optional OVT) -------------
        username = (body.get("username") or "").strip()
        password = (body.get("password") or "")
        ovt      = (body.get("ovt") or "").strip()
        if not (username and password):
            return _json(200, _err("invalid_login"))

        if ovt and not _ovt_get_email(ovt):
            return _json(200, _err("ovt_invalid"))

        rec = _get_user_record(username)
        if not rec or not _verify_password(rec.get("password", ""), password):
            return _json(200, _err("invalid_login"))

        role  = (rec.get("access") or rec.get("role") or "user")
        email = (rec.get("email") or "")
        name  = (rec.get("name")  or username)

        token = _sign_jwt({
                "sub": username,
                "username": username,
                "role": role,
                "access": role,
                "email": email,
                "name": name
        })

        return _json(200, _ok(
            token=token,
            role=role,
            user={"username": username, "email": email, "name": name}
        ))
    except Exception as e:
        return _json(200, _err("unexpected", message=str(e)))


# ---------- EC2 ----------
def _name_tag(tags):
    for t in tags or []:
        if t.get("Key") == "Name":
            return t.get("Value") or ""
    return ""

def _detect_env(name: str) -> str:
    if not ENV_TOKENS:
        return "ALL"
    n = (name or "").lower()
    for tok in ENV_TOKENS_LOWER:
        if tok in n:
            return tok.upper()
    return "MISC"

def _detect_role(name: str) -> str:
    n = (name or "").lower()
    return "DM" if "dm" in n else "EA"

def handle_instances():
    paginator = ec2.get_paginator("describe_instances")
    filters = [{"Name":"instance-state-name","Values":["running","stopped","pending","stopping"]}]
    pages = paginator.paginate(Filters=filters)

    items = []
    for page in pages:
        for r in page.get("Reservations", []):
            for i in r.get("Instances", []):
                items.append({
                    "id": i["InstanceId"],
                    "name": _name_tag(i.get("Tags")),
                    "state": i.get("State", {}).get("Name"),
                    "type": i.get("InstanceType"),
                    "publicIp": i.get("PublicIpAddress"),
                    "privateIp": i.get("PrivateIpAddress"),
                    "platform": "windows" if (i.get("Platform") == "windows" or i.get("PlatformDetails","").lower().startswith("windows")) else "linux",
                })

    items.sort(key=lambda x: (x["name"] or "", x["id"]))

    summary = {
        "total":   len(items),
        "running": sum(1 for x in items if (x.get("state") or "").lower() == "running"),
        "stopped": sum(1 for x in items if (x.get("state") or "").lower() == "stopped"),
    }

    envs = {}
    for it in items:
        env  = _detect_env(it["name"])
        role = _detect_role(it["name"])
        envs.setdefault(env, {"DM": [], "EA": []})
        envs[env][role].append(it)

    return _json(200, _ok(instances=items, summary=summary, envs=envs))

def _ec2_action(instance_id, op):
    if op == "start":
        ec2.start_instances(InstanceIds=[instance_id])
    elif op == "stop":
        ec2.stop_instances(InstanceIds=[instance_id])
    elif op == "reboot":
        ec2.reboot_instances(InstanceIds=[instance_id])
    else:
        return _err("unsupported_action")
    return _ok()

def handle_instance_action(body):
    iid = (body.get("instanceId") or body.get("id") or "").strip()
    op  = (body.get("op") or body.get("action") or "").strip().lower()
    if not iid or not op:
        return _json(200, _err("missing_params"))
    try:
        return _json(200, _ec2_action(iid, op))
    except ClientError as e:
        return _json(200, _err("aws_error", message=str(e)))

def handle_bulk(body):
    ids = (body.get("instanceIds") or body.get("ids") or []) or []
    op  = (body.get("op") or body.get("action") or "").strip().lower()
    if not ids or not op:
        return _json(200, _err("missing_params"))
    try:
        if op == "start":
            ec2.start_instances(InstanceIds=ids)
        elif op == "stop":
            ec2.stop_instances(InstanceIds=ids)
        elif op == "reboot":
            ec2.reboot_instances(InstanceIds=ids)
        else:
            return _json(200, _err("unsupported_action"))
        return _json(200, _ok())
    except ClientError as e:
        return _json(200, _err("aws_error", message=str(e)))

# ---------- Services via SSM (Windows + Linux) ----------
def _is_windows_instance(instance_id: str) -> bool:
    """
    Decide Windows vs Linux/mac. Prefer SSM (PlatformType), then fall back to EC2 metadata.
    """
    # 1) SSM is authoritative when the agent is registered
    try:
        info = ssm.describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
        )
        lst = info.get("InstanceInformationList") or []
        if lst:
            ptype = (lst[0].get("PlatformType") or "").lower()   # "windows" | "linux" | "macos"
            # tiny debug breadcrumb in logs
            try: print(f"DBG/osdetect SSM PlatformType for {instance_id}: {ptype}")
            except: pass
            if ptype:
                return ptype == "windows"
    except ClientError:
        pass

    # 2) Fallback to EC2 fields (older images sometimes don’t set Platform)
    try:
        res = ec2.describe_instances(InstanceIds=[instance_id])
        for r in res.get("Reservations", []):
            for inst in r.get("Instances", []):
                plat = (inst.get("Platform") or "").lower()                 # "windows" or ""
                platd = (inst.get("PlatformDetails") or "").lower()         # e.g. "linux/unix", "windows"
                try: print(f"DBG/osdetect EC2 Platform='{plat}' PlatformDetails='{platd}' for {instance_id}")
                except: pass
                if plat == "windows" or "windows" in platd:
                    return True
    except ClientError:
        pass

    # default assume non-Windows
    return False


def _instance_name(instance_id: str) -> str:
    """Best-effort EC2 Name tag lookup (empty if not found)."""
    try:
        res = ec2.describe_instances(InstanceIds=[instance_id])
        for r in res.get("Reservations", []):
            for inst in r.get("Instances", []):
                for t in inst.get("Tags", []) or []:
                    if t.get("Key") == "Name":
                        return t.get("Value") or ""
    except ClientError:
        pass
    return ""

def _ssm_online(instance_id: str) -> bool:
    try:
        res = ssm.describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
        )
        infos = res.get("InstanceInformationList", [])
        if not infos:
            return False
        return infos[0].get("PingStatus") == "Online"
    except ClientError:
        return False

def _run_powershell(instance_id: str, commands: list[str], timeout=60) -> tuple[bool, str, str]:
    try:
        send = ssm.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunPowerShellScript",
            Parameters={"commands": commands},
            TimeoutSeconds=timeout,
        )
        cmd_id = send["Command"]["CommandId"]
    except ClientError as e:
        return False, "", f"send_command_error: {e}"

    end_by = time.time() + timeout
    while time.time() < end_by:
        try:
            inv = ssm.get_command_invocation(CommandId=cmd_id, InstanceId=instance_id)
            status = inv.get("Status")
            if status in ("Success","Cancelled","TimedOut","Failed"):
                return (
                    status == "Success",
                    (inv.get("StandardOutputContent") or "").strip(),
                    (inv.get("StandardErrorContent") or "").strip(),
                )
        except ClientError:
            pass
        time.sleep(1.0)

    return False, "", "timeout"
def parse_services_text(txt: str):
    """
    Convert text like:
      Name: redis-sentinel.service
      DisplayName: Advanced key-value store
      Status: failed
      Name: redis-server.service
      DisplayName: Advanced key-value store
      Status: active
    into: [{'name':..., 'display':..., 'status':...}, ...]
    """
    if not txt:
        return []
    items, cur = [], {}
    for raw in txt.splitlines():
        s = raw.strip()
        if not s:
            continue

        m = re.search(r'Name\s*:\s*(.+)$', s, re.I)
        if m:
            if cur:
                items.append(cur)
            cur = {'name': m.group(1).strip()}
            continue

        m = re.search(r'DisplayName\s*:\s*(.+)$', s, re.I)
        if m:
            cur['display'] = m.group(1).strip()
            continue

        m = re.search(r'Status\s*:\s*(.+)$', s, re.I)
        if m:
            st = m.group(1).strip().lower()
            if st in ('failed', 'inactive', 'dead'):
                st = 'stopped'
            cur['status'] = st
            continue

    if cur:
        items.append(cur)
    return items

def _run_shell(instance_id: str, commands: list[str], timeout=60) -> tuple[bool, str, str]:
    """Run POSIX shell commands via SSM on Linux instances."""
    try:
        send = ssm.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunShellScript",
            Parameters={"commands": commands},
            TimeoutSeconds=timeout,
        )
        cmd_id = send["Command"]["CommandId"]
    except ClientError as e:
        return False, "", f"send_command_error: {e}"

    end_by = time.time() + timeout
    while time.time() < end_by:
        try:
            inv = ssm.get_command_invocation(CommandId=cmd_id, InstanceId=instance_id)
            status = inv.get("Status")
            if status in ("Success","Cancelled","TimedOut","Failed"):
                return (
                    status == "Success",
                    (inv.get("StandardOutputContent") or "").strip(),
                    (inv.get("StandardErrorContent") or "").strip(),
                )
        except ClientError:
            pass
        time.sleep(1.0)
    return False, "", "timeout"

# tolerant parsers for whatever the instance prints
def _parse_json_services(text):
    try:
        obj = json.loads(text)
        if isinstance(obj, dict): return [obj]
        if isinstance(obj, list): return obj
    except Exception:
        pass
    return []

def _parse_csv_services(text):
    try:
        # Only treat as CSV if the first non-empty line contains a comma
        first = next((ln for ln in (text or "").splitlines() if ln.strip()), "")
        if "," not in first:
            return []
        f = io.StringIO(text)
        rdr = csv.DictReader(f)
        # Must have at least two headers to be meaningful CSV
        if not rdr.fieldnames or len(rdr.fieldnames) < 2:
            return []
        rows = [{(k or "").strip(): (v or "").strip() for k, v in row.items()} for row in rdr]
        return rows if rows else []
    except Exception:
        return []


def _parse_keyvals_services(text):
    lines = (text or "").splitlines()
    out, row = [], {}

    for ln in lines:
        m = re.match(r"^\s*([A-Za-z][\w ]+)\s*[:=]\s*(.+?)\s*$", ln)
        if not m:
            continue
        key, val = m.group(1).strip(), m.group(2).strip()

        # start a new record whenever we see "Name:" again
        if key.lower() == "name" and row:
            out.append(row)
            row = {}

        row[key] = val

    if row:
        out.append(row)
    return out




def _parse_table_services(text):
    lines = [ln for ln in (text or "").splitlines() if ln.strip()]
    if len(lines) < 2: return []
    hdr = lines[0]
    if not (("Status" in hdr) and ("Name" in hdr) and ("DisplayName" in hdr)): return []
    out = []
    for ln in lines[1:]:
        parts = re.split(r"\s{2,}", ln.strip())
        if len(parts) >= 3:
            status, name, display = parts[0], parts[1], "  ".join(parts[2:])
            out.append({"Status": status, "Name": name, "DisplayName": display})
    return out

def _parse_services_stdout(text):
    # Prefer our key:value blocks first; CSV last to avoid false positives
    for fn in (_parse_json_services, _parse_keyvals_services, _parse_table_services, _parse_csv_services):
        rows = fn(text)
        if rows:
            return rows
    return []


def _norm_status(s):
    s = (s or "").strip().lower()
    if s in ("running","started","startpending","active","activating"): return "running"
    if s in ("stopped","stoppped","stoppending","inactive","failed","deactivating"): return "stopped"
    return s or "unknown"

def _mk_row(src: dict):
    name = src.get("name") or src.get("Name") or src.get("service") or src.get("ServiceName") or src.get("Service") or ""
    disp = src.get("display") or src.get("display_name") or src.get("DisplayName") or src.get("displayName") or src.get("Description") or name
    stat = _norm_status(src.get("status") or src.get("Status") or src.get("state") or src.get("State") or src.get("ActiveState"))
    return {
        "name": name,
        "display": disp,         # what your UI reads
        "displayName": disp,     # extra for safety
        "status": stat
    }

# ---- Windows service listing (existing behavior) ----
def _ps_list(mode: str, query: str):
    if mode == "sql":
        return [
            '$sv = Get-Service | Where-Object { '
            '$_.Name -like "MSSQL*" -or '
            '$_.Name -like "SQLSERVERAGENT*" -or '
            '$_.Name -like "SQLAgent*" -or '
            '$_.Name -eq "SQLBrowser" -or '
            '$_.Name -eq "SQLWriter" -or '
            '$_.DisplayName -match "SQL Server" }',
        ]
    elif mode == "redis":
        return [
            '$sv = Get-Service | Where-Object { $_.Name -match "redis" -or $_.DisplayName -match "redis" }',
        ]
    elif mode == "rabbit":
        return [
            '$sv = Get-Service | Where-Object { $_.Name -match "rabbit" -or $_.DisplayName -match "rabbit" }',
        ]
    else:
        q = (query or "").replace("'", "''")
        return [
            f"$q = '{q}'",
            '$sv = Get-Service | Where-Object { $_.Name -like ("*" + $q + "*") -or $_.DisplayName -like ("*" + $q + "*") }',
        ]
def _linux_candidates(mode: str, query: str) -> list[str]:
    q = (query or "")
    want_redis  = (mode == "redis")  or re.search(r"redis", q, re.I) is not None
    want_rabbit = (mode == "rabbit") or re.search(r"^ra|rabbit|rabbitmq|\bmq\b", q, re.I) is not None
    cands: list[str] = []
    if want_redis:
        cands += ["redis-server.service", "redis.service", "redis-sentinel.service"]
    if want_rabbit:
        cands += ["rabbitmq-server.service", "rabbitmq.service"]
    # as a last resort, try both families
    if not cands:
        cands = [
            "redis-server.service", "redis.service", "redis-sentinel.service",
            "rabbitmq-server.service", "rabbitmq.service",
        ]
    return cands


def _linux_probe_script(units: list[str]) -> str:
    # Tries systemd first; if missing, tries legacy sysvinit `service ... status`
    # Prints key:value blocks that our tolerant parser already supports.
    quoted = " ".join(shlex.quote(u) for u in units)
    return r"""#!/bin/sh
set +e

_print_row () {
  U="$1"; DESC="$2"; STATE="$3"
  [ -n "$STATE" ] || return 0
  printf "Name: %s\n" "$U"
  printf "DisplayName: %s\n" "${DESC:-$U}"
  printf "Status: %s\n\n" "$STATE"
}

have_systemctl=0
if command -v systemctl >/dev/null 2>&1; then have_systemctl=1; fi

for U in {UNITS}; do
  [ -n "$U" ] || continue
  UNIT="$U"
  case "$UNIT" in
    *.service) S="$UNIT" ;;
    *) S="$UNIT.service" ;;
  esac

  STATE=""; DESC=""
  if [ "$have_systemctl" -eq 1 ]; then
    STATE=$(systemctl show -p ActiveState "$S" 2>/dev/null | sed 's/^ActiveState=//')
    DESC=$(systemctl show -p Description "$S" 2>/dev/null | sed 's/^Description=//')
  fi

  # If systemctl didn't return anything, try old `service` style (best-effort)
  if [ -z "$STATE" ] && command -v service >/dev/null 2>&1; then
    NAME="${S%.service}"
    OUT=$(service "$NAME" status 2>/dev/null)
    case "$OUT" in
      *"is running"*|*"start/running"*|*"active (running)"*) STATE="running" ;;
      *"is stopped"*|*"stop/waiting"*|*"inactive (dead)"*|*"not running"*) STATE="stopped" ;;
      *) STATE="" ;;
    esac
    [ -z "$DESC" ] && DESC="$NAME"
  fi

  if [ -n "$STATE" ]; then
    _print_row "$S" "$DESC" "$STATE"
  fi
done

exit 0
""".replace("{UNITS}", quoted)

# ---- Linux (systemd) service listing ----
def _sh_list(mode: str, query: str):
    # unchanged from your latest version
    if mode == "redis":
        grep_expr = "redis|redis-server"
    elif mode == "rabbit":
        grep_expr = "rabbit|rabbitmq|rabbitmq-server"
    else:
        grep_expr = (query or "").strip()

    grep_cmd = ""
    if grep_expr:
        grep_cmd = f" | grep -iE {shlex.quote(grep_expr)} || true"

    return [r"""#!/bin/sh
set +e
if ! command -v systemctl >/dev/null 2>&1; then
  exit 0
fi

LIST=$(systemctl list-unit-files --type=service --no-legend --no-pager | awk '{print $1}'""" + (grep_cmd or "") + r""")
ACTIVE=$(systemctl list-units --type=service --all --no-legend --no-pager | awk '{print $1}'""" + (grep_cmd or "") + r""")

COMBINED=$(printf "%s\n%s\n" "$LIST" "$ACTIVE" | awk 'NF' | sort -u)

IFS='
'
for S in $COMBINED; do
  case "$S" in
    *.service) UNIT="$S" ;;
    *) UNIT="$S.service" ;;
  esac

  DESC=$(systemctl show -p Description "$UNIT" 2>/dev/null | sed 's/^Description=//')
  STATE=$(systemctl show -p ActiveState  "$UNIT" 2>/dev/null | sed 's/^ActiveState=//')

  if [ -n "$STATE" ]; then
    printf "Name: %s\n" "$UNIT"
    printf "DisplayName: %s\n" "${DESC:-$UNIT}"
    printf "Status: %s\n\n" "$STATE"
  fi
done

exit 0
"""]

def list_services(instance_id: str, mode: str, query: str | None = None):
    """
    Windows: PowerShell Get-Service
    Linux:   try list (regex) -> strong-kind fallback -> targeted probe (systemd/sysv)
    """
    is_win = _is_windows_instance(instance_id)

    if not _ssm_online(instance_id):
        return {"ok": True, "services": [], "note": "not_connected"}

    # ---- Windows path (unchanged) ----
    if is_win:
        ps = _ps_list(mode, query or "")
        ps += [
            '$out = @()',
            '$sv | ForEach-Object { $out += [pscustomobject]@{ name=$_.Name; display=$_.DisplayName; status=$_.Status.ToString().ToLower() } }',
            '$out | ConvertTo-Json -Compress'
        ]
        ok, stdout, stderr = _run_powershell(instance_id, ps)
        if not ok:
            return {"ok": False, "error": stderr or stdout or "ssm_failed"}
        rows = _parse_services_stdout(stdout)
        return {"ok": True, "services": [_mk_row(r) for r in rows]}

    # ---- Linux path ----
    q = (query or "")

    # 1) regex list using user query or mode
    sh = _sh_list(mode, q)
    ok, stdout, stderr = _run_shell(instance_id, sh)
    # Debug: capture raw stdout/stderr
    try:
        print("DBG/Linux services raw stdout:", (stdout or "")[:1500])
        print("DBG/Linux services raw stderr:", (stderr or "")[:1500])
    except Exception:
        pass

    if not ok:
        return {"ok": False, "error": stderr or stdout or "ssm_failed"}
    rows = _parse_services_stdout(stdout)

    # 2) fallback: force kind regex (redis/rabbit) if the user typed a hint
    if not rows:
        want_redis  = (mode == "redis")  or re.search(r"redis", q, re.I) is not None
        want_rabbit = (mode == "rabbit") or re.search(r"^ra|rabbit|rabbitmq|\bmq\b", q, re.I) is not None
        if want_redis or want_rabbit:
            kind = "redis" if want_redis else "rabbit"
            ok2, stdout2, stderr2 = _run_shell(instance_id, _sh_list(kind, ""))
            if ok2:
                rows = _parse_services_stdout(stdout2)

    # 3) final targeted probe of well-known unit names + sysv fallback
    if not rows:
        cands = _linux_candidates(mode, q)
        probe = _linux_probe_script(cands)
        ok3, stdout3, stderr3 = _run_shell(instance_id, [probe])
        if ok3:
            rows = _parse_services_stdout(stdout3)

    if not rows:
        return {"ok": True, "services": []}

    return {"ok": True, "services": [_mk_row(r) for r in rows]}



def control_service(instance_id: str, service_name: str, op: str):
    """
    Start/stop a service on the target instance via SSM.
    - Windows: PowerShell Get-Service / Start-Service / Stop-Service
    - Linux:   systemctl start|stop <unit>; echoes Name/DisplayName/Status
    """
    if not _ssm_online(instance_id):
        return {"ok": False, "error": "not_connected"}

    is_win = _is_windows_instance(instance_id)

    # -------- Windows (unchanged) --------
    svc = service_name.replace("'", "''")  # PS single-quote escaping
    if is_win:
        if op == "start":
            action = [
                f"$n = '{svc}'",
                'try {',
                '  $s = Get-Service -Name $n -ErrorAction Stop;',
                '  if ($s.Status -ne "Running") { Start-Service -Name $n; $s.WaitForStatus("Running","00:00:20") }',
                '  $s = Get-Service -Name $n;',
                '  $out = [pscustomobject]@{ name=$s.Name; display=$s.DisplayName; status=$s.Status.ToString().ToLower() }',
                '} catch { $out = [pscustomobject]@{ error=$_.Exception.Message } }',
                '$out | ConvertTo-Json -Compress'
            ]
        else:  # stop
            action = [
                f"$n = '{svc}'",
                'try {',
                '  $s = Get-Service -Name $n -ErrorAction Stop;',
                '  if ($s.Status -ne "Stopped") { Stop-Service -Name $n -Force; $s.WaitForStatus("Stopped","00:00:20") }',
                '  $s = Get-Service -Name $n;',
                '  $out = [pscustomobject]@{ name=$s.Name; display=$s.DisplayName; status=$s.Status.ToString().ToLower() }',
                '} catch { $out = [pscustomobject]@{ error=$_.Exception.Message } }',
                '$out | ConvertTo-Json -Compress'
            ]
        ok, stdout, stderr = _run_powershell(instance_id, action)
        if not ok:
            return {"ok": False, "error": stderr or stdout or "ssm_failed"}
        try:
            data = json.loads(stdout) if stdout else {}
        except Exception:
            return {"ok": False, "error": "parse_error", "raw": stdout}
        if isinstance(data, dict) and "error" in data:
            return {"ok": False, "error": data["error"]}
        return {"ok": True, "service": _mk_row(data)}

    # -------- Linux (systemd) --------
    if op not in ("start", "stop"):
        return {"ok": False, "error": "unsupported_action"}

    # Build a safe double-quoted string for the shell
    svc_safe = (service_name or "").replace('"', '').replace('`', '').replace('\n', ' ').replace('\r', ' ').strip()

    # IMPORTANT: use f-string and escape the ${...} braces as ${{...}} so Python
    # doesn't treat them as f-string expressions.
    sh = [f"""set -e
UNIT="{svc_safe}"
case "$UNIT" in
  *.service) S="$UNIT" ;;
  *) S="$UNIT.service" ;;
esac

# Try sudo first (if allowed), then plain systemctl
if command -v sudo >/dev/null 2>&1; then
  sudo systemctl {op} "$S" || true
else
  systemctl {op} "$S" || true
fi

DESC=$(systemctl show -p Description "$S" 2>/dev/null | sed 's/^Description=//')
STATE=$(systemctl show -p ActiveState  "$S" 2>/dev/null | sed 's/^ActiveState=//')

printf "Name: %s\\n" "$S"
printf "DisplayName: %s\\n" "${{DESC:-$S}}"
printf "Status: %s\\n" "$STATE"
"""]

    ok, stdout, stderr = _run_shell(instance_id, sh)
    if not ok:
        return {"ok": False, "error": stderr or stdout or "ssm_failed"}

    rows = _parse_services_stdout(stdout)
    if not rows:
        return {"ok": True, "service": {"name": svc_safe, "display": svc_safe, "status": "unknown"}}
    return {"ok": True, "service": _mk_row(rows[0])}

# ---------- HTTP entrypoint ----------
def lambda_handler(event, context):
    path   = (event.get("requestContext", {}).get("http", {}).get("path") or
              event.get("rawPath") or event.get("path") or "").strip()
    method = (event.get("requestContext", {}).get("http", {}).get("method") or
              event.get("httpMethod") or "GET").upper()
    body   = _read_body(event)
    
        # CORS preflight
    if method == "OPTIONS":
        return _json(204, {"ok": True})


    # Public
    if path == "/request-otp" and method == "POST": return handle_request_otp(body)
    if path == "/verify-otp"  and method == "POST": return handle_verify_otp(body)
    if path == "/login"       and method == "POST": return handle_login(body)

    # Protected (read OK for all roles)
    if path == "/instances" and method == "GET":
        return handle_instances()

    # Mutating endpoints — require admin
    if path == "/instance-action" and method == "POST":
        guard = _require_admin(event)
        if guard: return guard
        return handle_instance_action(body)

    if path == "/bulk-action" and method == "POST":
        guard = _require_admin(event)
        if guard: return guard
        return handle_bulk(body)

    # Services (list = read-only; start/stop/iisreset = admin)
    if path == "/services" and method == "POST":
        iid = (body.get("instanceId") or body.get("id"))
        if not iid:
            try: print("ERR /services: missing instanceId. Body:", str(body)[:400])
            except Exception: pass
            return _json(200, _err("instanceId required"))

        op = (body.get("op") or "list").lower()
        if op == "list":
            mode = (body.get("mode") or "filter").lower()
            query = (body.get("query") or "").strip()

            # If a query is typed, always honor it
            if len(query) >= 2:
                mode = "filter"

            # Special-case: Rabbit heuristics (if user typed ra/rabbit/mq etc.)
            if mode == "filter" and re.search(r"^ra|rabbit|rabbitmq|\bmq\b", query, re.I):
                mode = "rabbit"

            return _json(200, list_services(iid, mode, query))

        if op in ("start", "stop", "iisreset"):
            guard = _require_admin(event)
            if guard: return guard

            if op in ("start", "stop"):
                svc = body.get("serviceName")
                if not svc:
                    return _json(200, _err("serviceName required"))
                return _json(200, control_service(iid, svc, op))

            if op == "iisreset":
                # Block IIS reset for SQL / Redis / Rabbit instances by name heuristic
                # Prefer instanceName from body; else EC2 Name tag lookup.
                iname = (body.get("instanceName") or body.get("instance") or "") or _instance_name(iid)
                nm = (iname or "").lower()
                if any(k in nm for k in ("sql", "redis", "rabbit")):
                    return _json(200, _err("IIS reset not allowed for SQL/Redis/Rabbit instances"))
                return _json(200, iis_reset(iid))

        return _json(200, _err("unknown op"))

    return _json(404, {"error":"not_found","path":path,"method":method})
