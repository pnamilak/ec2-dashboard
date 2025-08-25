# lambda/handler.py
import boto3, json, os, time, base64, re

ec2 = boto3.client("ec2")
ssm = boto3.client("ssm")

ENV_RE = re.compile(r"(DEV|DEMO|QA|UAT|SIT|STG|STAGE|PPE|PROD|PRD|DR|TEST)", re.I)

def _tag(tags, key):
    for t in tags or []:
        if t.get("Key","").lower() == key.lower():
            return t.get("Value","")
    return ""

def _env_from_name(name):
    m = ENV_RE.search(name or "")
    return (m.group(1).upper() if m else "OTHER")

def _list_instances():
    out = []
    paginator = ec2.get_paginator("describe_instances")
    for page in paginator.paginate():
        for r in page.get("Reservations", []):
            for i in r.get("Instances", []):
                iid   = i["InstanceId"]
                state = i["State"]["Name"]
                name  = _tag(i.get("Tags"), "Name")
                plat  = (i.get("PlatformDetails") or i.get("Platform") or "").lower()
                env   = _env_from_name(name)
                out.append({
                    "id": iid,
                    "name": name or iid,
                    "state": state,
                    "env": env,
                    "platform": "windows" if "windows" in plat else ("linux" if plat else "unknown"),
                    "privateIp": i.get("PrivateIpAddress"),
                    "publicIp":  i.get("PublicIpAddress")
                })
    return out

def _wait_cmd(command_id, instance_id, timeout=60):
    t0 = time.time()
    while True:
        resp = ssm.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
        st = resp.get("Status")
        if st in ("Success", "Failed", "Cancelled", "TimedOut"):
            return resp
        if time.time() - t0 > timeout:
            return {"Status": "TimedOut", "StandardOutputContent": "", "StandardErrorContent": "Timeout"}
        time.sleep(1.5)

def _send_ps(instance_id, lines, comment="dashboard"):
    resp = ssm.send_command(
        InstanceIds=[instance_id],
        DocumentName="AWS-RunPowerShellScript",
        Parameters={"commands": lines if isinstance(lines, list) else [lines]},
        Comment=comment
    )
    cmd_id = resp["Command"]["CommandId"]
    return _wait_cmd(cmd_id, instance_id)

def _services_query_windows(instance_id, patterns):
    pats = [p for p in [x.strip() for x in (patterns or [])] if p]
    if not pats:
        pats = ["SQL","SQLServer","SQLSERVERAGENT","ServiceManagement"]

    esc = "|".join([r"({})".format(re.escape(p)) for p in pats])
    script = f'''
$ErrorActionPreference = "SilentlyContinue"
$re = [regex]"{esc}"
$svcs = Get-Service | Where-Object {{ $_.Name -match $re -or $_.DisplayName -match $re }} |
  Select-Object Name, DisplayName, Status

# Windows & SQL info
$osKey = Get-ItemProperty "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
$os = $osKey.ProductName
if ($osKey.DisplayVersion) {{ $os = "$os $($osKey.DisplayVersion)" }}
elseif ($osKey.ReleaseId) {{ $os = "$os $($osKey.ReleaseId)" }}

# SQL via registry (works even without sqlcmd)
$sqlVers = @()
try {{
  $instRoot = Get-ItemProperty "HKLM:\\SOFTWARE\\Microsoft\\Microsoft SQL Server\\Instance Names\\SQL"
  foreach ($p in $instRoot.PSObject.Properties) {{
    $id = $p.Value
    $verKey = "HKLM:\\SOFTWARE\\Microsoft\\Microsoft SQL Server\\$id\\MSSQLServer\\CurrentVersion"
    $cv = Get-ItemProperty -Path $verKey -ErrorAction SilentlyContinue
    if ($cv) {{ $sqlVers += "$($p.Name) $($cv.CurrentVersion)" }}
  }}
}} catch {{ }}

# Fallback to sqlcmd if available
if (-not $sqlVers -and (Get-Command sqlcmd -ErrorAction SilentlyContinue)) {{
  try {{
    $txt = sqlcmd -S . -Q "SET NOCOUNT ON; SELECT @@VERSION" -W -h-1 2>$null
    if ($txt) {{ $sqlVers = @($txt) }}
  }} catch {{}}
}}

$body = [PSCustomObject]@{{
  os = $os
  sql = ($sqlVers -join '; ')
  services = $svcs
}}

$body | ConvertTo-Json -Depth 4 -Compress
'''
    res = _send_ps(instance_id, script, "services-query")
    if res.get("Status") != "Success":
        raise Exception(res.get("StandardErrorContent") or "SSM command failed")
    payload = res.get("StandardOutputContent","").strip()
    try:
        data = json.loads(payload) if payload else {}
    except Exception:
        data = {"raw": payload}
    return data

def _service_control_windows(instance_id, name, op):
    name = name.strip()
    if op == "start":
        ps = f'($s=Start-Service -Name "{name}" -PassThru -ErrorAction Stop; Get-Service -Name "{name}") | Select Name,DisplayName,Status | ConvertTo-Json -Compress'
    else:
        ps = f'($s=Stop-Service -Name "{name}" -Force -PassThru -ErrorAction Stop; Get-Service -Name "{name}") | Select Name,DisplayName,Status | ConvertTo-Json -Compress'
    res = _send_ps(instance_id, ps, f"service-{op}")
    if res.get("Status") != "Success":
        raise Exception(res.get("StandardErrorContent") or "SSM command failed")
    return json.loads(res.get("StandardOutputContent","{}") or "{}")

def _iis_reset(instance_id):
    ps = 'iisreset'
    res = _send_ps(instance_id, ps, "iis-reset")
    ok = res.get("Status") == "Success"
    return {"ok": ok, "stdout": res.get("StandardOutputContent",""), "stderr": res.get("StandardErrorContent","")}

def _json(status=200, body=None):
    return {
        "statusCode": status,
        "headers": { "Content-Type": "application/json" },
        "body": json.dumps(body or {})
    }

def lambda_handler(event, _ctx):
    method = (event.get("requestContext",{}).get("http",{}).get("method") or event.get("httpMethod") or "GET").upper()
    path   = (event.get("requestContext",{}).get("http",{}).get("path") or event.get("rawPath") or "/")
    user   = (event.get("requestContext",{}).get("authorizer",{}).get("user") or "")

    try:
        if method == "GET" and path.endswith("/instances"):
            items = _list_instances()
            total   = len(items)
            running = sum(1 for x in items if x["state"] == "running")
            stopped = sum(1 for x in items if x["state"] == "stopped")
            envs    = sorted(sorted(set(x["env"] for x in items)))
            return _json(200, {"items": items, "summary": {"total": total, "running": running, "stopped": stopped}, "envs": envs})

        if method == "POST" and path.endswith("/instances"):
            body = json.loads(event.get("body") or "{}")
            action = body.get("action","").lower()

            if action in ("start","stop","reboot"):
                iid = body.get("instanceId")
                if not iid:
                    return _json(400, {"error":"instanceId required"})
                if action == "start":
                    ec2.start_instances(InstanceIds=[iid])
                elif action == "stop":
                    ec2.stop_instances(InstanceIds=[iid])
                else:
                    ec2.reboot_instances(InstanceIds=[iid])
                return _json(200, {"ok": True})

            if action == "services_query":
                iid = body.get("instanceId")
                pats = body.get("patterns") or []
                data = _services_query_windows(iid, pats)
                return _json(200, {"ok": True, "data": data})

            if action in ("service_start","service_stop"):
                iid = body.get("instanceId")
                name = body.get("name")
                if not (iid and name):
                    return _json(400, {"error":"instanceId and name required"})
                op = "start" if action=="service_start" else "stop"
                data = _service_control_windows(iid, name, op)
                return _json(200, {"ok": True, "service": data})

            if action == "iis_reset":
                iid = body.get("instanceId")
                data = _iis_reset(iid)
                return _json(200, data)

            return _json(400, {"error":"unknown action"})

        return _json(404, {"error":"not found"})
    except Exception as e:
        return _json(500, {"error": str(e)})
