import json, os, time, hmac, hashlib, base64, boto3, random, string, re

region       = os.environ.get("REGION")
otp_table    = os.environ.get("OTP_TABLE")
ses_sender   = os.environ.get("SES_SENDER")
allowed_dom  = os.environ.get("ALLOWED_DOMAIN", "gmail.com").lower()
param_prefix = os.environ.get("PARAM_USER_PREFIX", "/ec2-dashboard/users")
jwt_param    = os.environ.get("JWT_PARAM")
env_names    = os.environ.get("ENV_NAMES", "")

ddb  = boto3.client("dynamodb", region_name=region)
ses  = boto3.client("ses", region_name=region)
ssm  = boto3.client("ssm", region_name=region)
ec2  = boto3.client("ec2", region_name=region)
ssm_ec2 = boto3.client("ssm", region_name=region)

def _read_jwt_secret():
    p = ssm.get_parameter(Name=jwt_param, WithDecryption=True)
    return p["Parameter"]["Value"].encode()

def _sign(payload: dict, ttl=3600):
    secret = _read_jwt_secret()
    payload = {**payload, "exp": int(time.time()) + ttl}
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    sig  = hmac.new(secret, body, hashlib.sha256).digest()
    tok  = base64.urlsafe_b64encode(body).decode().rstrip("=") + "." + base64.urlsafe_b64encode(sig).decode().rstrip("=")
    return tok

def _verify(token: str):
    try:
        body_b64, sig_b64 = token.split(".")
        body = base64.urlsafe_b64decode(body_b64 + "==")
        sig  = base64.urlsafe_b64decode(sig_b64 + "==")
        secret = _read_jwt_secret()
        if not hmac.compare_digest(sig, hmac.new(secret, body, hashlib.sha256).digest()):
            return None
        payload = json.loads(body)
        if payload.get("exp", 0) < time.time():
            return None
        return payload
    except Exception:
        return None

def _resp(status=200, body=None):
    return {"statusCode": status, "headers": {"Content-Type": "application/json"}, "body": json.dumps(body or {})}

def _json(event):
    try:
        return json.loads(event.get("body") or "{}")
    except Exception:
        return {}

def _get_name(tags):
    for t in tags or []:
        if t.get("Key")=="Name":
            return t.get("Value")
    return ""

def _env_from_name(name):
    for e in (env_names.split(",") if env_names else []):
        if e and e.upper() in name.upper():
            return e
    return "UNKNOWN"

def lambda_handler(event, context):
    route = event.get("rawPath") or ""
    method = event.get("requestContext", {}).get("http", {}).get("method", "GET")

    if route == "/request-otp" and method == "POST":
        d = _json(event)
        email = (d.get("email") or "").strip().lower()
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            return _resp(400, {"error": "Invalid email"})
        if not email.endswith(f"@{allowed_dom}"):
            return _resp(403, {"error": f"Email domain not allowed. Use @{allowed_dom}"})
        code = "".join(random.choices(string.digits, k=6))
        expires = int(time.time()) + 300
        ddb.put_item(TableName=otp_table, Item={
            "email": {"S": email},
            "code": {"S": code},
            "expiresAt": {"N": str(expires)}
        })
        ses.send_email(
            Source=ses_sender,
            Destination={"ToAddresses": [email]},
            Message={
                "Subject": {"Data": "Your OTP Code"},
                "Body": {"Text": {"Data": f"Your EC2 Dashboard OTP is: {code}\nValid for 5 minutes."}}
            }
        )
        return _resp(200, {"status": "sent"})

    if route == "/verify-otp" and method == "POST":
        d = _json(event)
        email = (d.get("email") or "").strip().lower()
        code  = (d.get("code") or "").strip()
        r = ddb.get_item(TableName=otp_table, Key={"email": {"S": email}})
        item = r.get("Item")
        if not item: return _resp(400, {"error":"No OTP. Request again."})
        if int(item["expiresAt"]["N"]) < time.time():
            return _resp(400, {"error":"OTP expired"})
        if item["code"]["S"] != code:
            return _resp(403, {"error":"Invalid OTP"})
        # success
        return _resp(200, {"status":"ok"})

    if route == "/login" and method == "POST":
        d = _json(event)
        username = (d.get("username") or "").strip()
        password = (d.get("password") or "").strip()
        try:
            p = ssm.get_parameter(Name=f"{param_prefix}/{username}", WithDecryption=True)["Parameter"]["Value"]
        except Exception:
            return _resp(403, {"error":"Invalid credentials"})
        if p != password:
            return _resp(403, {"error":"Invalid credentials"})
        token = _sign({"sub": username})
        return _resp(200, {"token": token})

    if route == "/instances" and method == "GET":
        # auth already checked by authorizer, but we can also soft-check if header present
        data = ec2.describe_instances()
        envs = {e: {"DM": [], "EA": []} for e in (env_names.split(",") if env_names else [])}
        total=running=stopped=0
        for res in data.get("Reservations", []):
            for i in res.get("Instances", []):
                name = _get_name(i.get("Tags"))
                state = i.get("State", {}).get("Name")
                iid   = i.get("InstanceId")
                total += 1
                if state=="running": running += 1
                if state=="stopped": stopped += 1
                env = _env_from_name(name)
                block = "DM" if "DM" in name.upper() else ("EA" if "EA" in name.upper() else None)
                if env in envs and block:
                    envs[env][block].append({
                        "id": iid, "name": name, "state": state
                    })
        return _resp(200, {"summary":{"total":total,"running":running,"stopped":stopped}, "envs": envs})

    if route == "/instance-action" and method == "POST":
        d = _json(event)
        action = d.get("action")  # start|stop
        if "id" in d:
            ids = [d["id"]]
        else:
            # group operation: require env + block
            env = d.get("env"); block = d.get("block") # DM or EA
            flt = [{
                "Name":"tag:Name",
                "Values":[f"*{env}*{block}*"]
            }]
            r = ec2.describe_instances(Filters=flt)
            ids=[]
            for res in r["Reservations"]:
                for i in res["Instances"]:
                    ids.append(i["InstanceId"])
        if not ids: return _resp(400, {"error":"No instances found"})
        if action=="start":
            ec2.start_instances(InstanceIds=ids)
        elif action=="stop":
            ec2.stop_instances(InstanceIds=ids)
        else:
            return _resp(400, {"error":"Invalid action"})
        return _resp(200, {"status":"ok", "ids": ids})

    if route == "/services" and method == "POST":
        d = _json(event)
        instance_id = d.get("id")
        mode = d.get("mode","list")  # list|start|stop|iisreset
        svc  = d.get("service")
        pattern = d.get("pattern","")
        name_hint = (d.get("instanceName") or "").lower()

        if mode == "iisreset":
            cmd = ["iisreset"]
        elif mode in ("start","stop"):
            if not svc: return _resp(400, {"error":"service required"})
            ps = f'{("Start-Service" if mode=="start" else "Stop-Service")} -Name "{svc}"'
            cmd = [ps]
        else:
            # LIST
            if "sql" in name_hint:
                ps = 'Get-Service -Name "MSSQLSERVER","SQLSERVERAGENT","SQLBrowser" | Select-Object Name,Status | ConvertTo-Json'
            elif "redis" in name_hint:
                ps = 'Get-Service -Name "Redis*" | Select-Object Name,Status | ConvertTo-Json'
            else:
                # text filter from UI
                patt = pattern if pattern else "*"
                ps = f'Get-Service -Name "*{patt}*" | Select-Object Name,Status | ConvertTo-Json'
            cmd = [ps]

        resp = ssm_ec2.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunPowerShellScript",
            Parameters={"commands": cmd},
        )
        cid = resp["Command"]["CommandId"]
        # simple wait loop (short)
        for _ in range(30):
            out = ssm_ec2.get_command_invocation(CommandId=cid, InstanceId=instance_id)
            if out["Status"] in ("Success","Failed","Cancelled","TimedOut"):
                break
            time.sleep(2)

        if mode == "list":
            try:
                data = json.loads(out.get("StandardOutputContent") or "[]")
            except Exception:
                data = []
            return _resp(200, {"services": data})
        else:
            return _resp(200, {"status": out.get("Status"), "stdout": out.get("StandardOutputContent",""), "stderr": out.get("StandardErrorContent","")})

    return _resp(404, {"error": "Not found"})
