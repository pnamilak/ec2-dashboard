import json
import time
import boto3

# ---- AWS clients ----
ec2 = boto3.client("ec2")
ssm = boto3.client("ssm")

# ---- Helpers ----
def _resp(body, code=200):
    """Uniform API Gateway response with CORS."""
    return {
        "statusCode": code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "Authorization,Content-Type",
            "Access-Control-Allow-Methods": "GET,OPTIONS"
        },
        "body": json.dumps(body)
    }

def _q(event):
    return (event.get("queryStringParameters") or {}) if isinstance(event, dict) else {}

# ---- EC2: list by env ----
def list_instances(env):
    """
    Return instances whose:
      - Environment/Env tag == env (case-insensitive), OR
      - Name tag CONTAINS env (case-insensitive).
    """
    if not env:
        return _resp({"error": "env required"}, 400)

    env_upper = env.upper()
    out = []
    paginator = ec2.get_paginator("describe_instances")

    for page in paginator.paginate():
        for r in page.get("Reservations", []):
            for i in r.get("Instances", []):
                tags = {t.get("Key"): t.get("Value", "") for t in i.get("Tags", [])}
                name = tags.get("Name", "")

                env_tag_val = (
                    tags.get("Environment")
                    or tags.get("Env")
                    or tags.get("environment")
                    or tags.get("env")
                    or ""
                )

                match = False
                if env_tag_val:
                    match = env_tag_val.upper() == env_upper
                if not match and name:
                    match = env_upper in name.upper()

                if match:
                    out.append({
                        "InstanceId": i["InstanceId"],
                        "Name": name,
                        "State": i.get("State", {}).get("Name", "")
                    })

    return _resp(out)

def start_instance(instance_id):
    if not instance_id:
        return _resp({"error": "instance_id required"}, 400)
    try:
        ec2.start_instances(InstanceIds=[instance_id])
    except Exception as e:
        return _resp({"error": f"start failed: {e}"}, 500)
    return _resp({"ok": True, "action": "start", "InstanceId": instance_id})

def stop_instance(instance_id):
    if not instance_id:
        return _resp({"error": "instance_id required"}, 400)
    try:
        ec2.stop_instances(InstanceIds=[instance_id])
    except Exception as e:
        return _resp({"error": f"stop failed: {e}"}, 500)
    return _resp({"ok": True, "action": "stop", "InstanceId": instance_id})

# ---- SSM / Service helpers ----
def _is_windows(instance_id: str) -> bool:
    """Detect Windows even when Platform is blank (use PlatformDetails)."""
    di = ec2.describe_instances(InstanceIds=[instance_id])
    inst = di["Reservations"][0]["Instances"][0]
    plat = (inst.get("Platform") or "").lower()                # 'windows' or ''
    pdet = (inst.get("PlatformDetails") or "").lower()         # may contain 'windows'
    return plat == "windows" or "windows" in pdet

def _send_ssm(instance_id: str, commands, is_windows: bool):
    """
    Send an SSM command and wait up to ~40s.
    Returns either a normal GetCommandInvocation dict or a dict with keys:
      {'Status': 'Error'|'TimedOut', 'Error': '...', 'StandardErrorContent': '...'}
    """
    doc = "AWS-RunPowerShellScript" if is_windows else "AWS-RunShellScript"
    try:
        resp = ssm.send_command(
            InstanceIds=[instance_id],
            DocumentName=doc,
            Parameters={"commands": commands},
            CloudWatchOutputConfig={"CloudWatchOutputEnabled": False}
        )
    except Exception as e:
        return {"Status": "Error", "Error": f"SendCommand: {e}"}

    cmd_id = resp["Command"]["CommandId"]

    for _ in range(40):  # ~40s
        time.sleep(1)
        try:
            inv = ssm.get_command_invocation(CommandId=cmd_id, InstanceId=instance_id)
        except Exception as e:
            return {"Status": "Error", "Error": f"GetCommandInvocation: {e}"}
        if inv["Status"] in ("Success", "Failed", "Cancelled", "TimedOut"):
            return inv

    return {"Status": "TimedOut", "StandardOutputContent": "", "StandardErrorContent": "Command timed out"}

def service_status(instance_id, service_name):
    if not instance_id or not service_name:
        return _resp({"error": "instance_id and service required"}, 400)

    win = _is_windows(instance_id)
    if win:
        # Try by ServiceName, then by DisplayName for friendlier UX.
        ps = (
            f'try {{ (Get-Service -Name "{service_name}").Status }} '
            f'catch {{ try {{ (Get-Service -DisplayName "{service_name}").Status }} '
            f'catch {{ "NotFound" }} }}'
        )
        commands = [ps]
    else:
        # For Linux, rely on systemd.
        commands = [f'systemctl is-active {service_name} || echo NotFound']

    inv = _send_ssm(instance_id, commands, win)

    if inv.get("Status") != "Success":
        # Surface the reason so the UI shows a helpful message.
        return _resp({
            "InstanceId": instance_id,
            "Service": service_name,
            "OS": "Windows" if win else "Linux",
            "Status": inv.get("Status") or "Error",
            "Error": inv.get("StandardErrorContent") or inv.get("Error") or "SSM command did not complete"
        })

    out = (inv.get("StandardOutputContent") or "").strip()
    status = out.splitlines()[-1].strip() if out else "unknown"

    return _resp({
        "InstanceId": instance_id,
        "Service": service_name,
        "OS": "Windows" if win else "Linux",
        "Status": status
    })

def service_start(instance_id, service_name):
    if not instance_id or not service_name:
        return _resp({"error": "instance_id and service required"}, 400)

    win = _is_windows(instance_id)
    if win:
        commands = [(
            f'try {{ Start-Service -Name "{service_name}" -ErrorAction Stop; "OK" }} '
            f'catch {{ try {{ Start-Service -DisplayName "{service_name}" -ErrorAction Stop; "OK" }} '
            f'catch {{ "ERR" }} }}'
        )]
    else:
        commands = [f'sudo systemctl start {service_name} || echo ERR']

    _send_ssm(instance_id, commands, win)
    return service_status(instance_id, service_name)

def service_stop(instance_id, service_name):
    if not instance_id or not service_name:
        return _resp({"error": "instance_id and service required"}, 400)

    win = _is_windows(instance_id)
    if win:
        commands = [(
            f'try {{ Stop-Service -Name "{service_name}" -Force -ErrorAction Stop; "OK" }} '
            f'catch {{ try {{ Stop-Service -DisplayName "{service_name}" -Force -ErrorAction Stop; "OK" }} '
            f'catch {{ "ERR" }} }}'
        )]
    else:
        commands = [f'sudo systemctl stop {service_name} || echo ERR']

    _send_ssm(instance_id, commands, win)
    return service_status(instance_id, service_name)

# ---- Lambda entrypoint ----
def lambda_handler(event, context):
    # Handle CORS preflight if API GW forwards OPTIONS
    if event.get("requestContext", {}).get("http", {}).get("method") == "OPTIONS":
        return _resp({}, 204)

    q = _q(event)
    action = (q.get("action") or "").lower()

    if action == "list":
        return list_instances(q.get("env"))

    if action == "start":
        return start_instance(q.get("instance_id"))

    if action == "stop":
        return stop_instance(q.get("instance_id"))

    if action == "service_status":
        return service_status(q.get("instance_id"), q.get("service"))

    if action == "service_start":
        return service_start(q.get("instance_id"), q.get("service"))

    if action == "service_stop":
        return service_stop(q.get("instance_id"), q.get("service"))

    return _resp({"error": "unknown action"}, 400)
