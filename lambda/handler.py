import json, os, time
import boto3

ec2 = boto3.client("ec2")
ssm = boto3.client("ssm")

def _resp(body, code=200):
    return {
        "statusCode": code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*"
        },
        "body": json.dumps(body)
    }

def _q(event):
    # HTTP API v2 has queryStringParameters
    return (event.get("queryStringParameters") or {}) if isinstance(event, dict) else {}

def _name_from_tags(tags):
    for t in (tags or []):
        if t.get("Key") == "Name":
            return t.get("Value", "")
    return ""

def list_instances(env):
    if not env:
        return _resp({"error":"env required"}, 400)
    filters = [
        {"Name": "tag:Environment", "Values": [env]}
    ]
    res = ec2.describe_instances(Filters=filters)
    out = []
    for r in res.get("Reservations", []):
        for i in r.get("Instances", []):
            out.append({
                "InstanceId": i["InstanceId"],
                "Name": _name_from_tags(i.get("Tags")),
                "State": i.get("State", {}).get("Name", "")
            })
    return _resp(out)

def start_instance(instance_id):
    if not instance_id:
        return _resp({"error":"instance_id required"}, 400)
    ec2.start_instances(InstanceIds=[instance_id])
    return _resp({"ok": True, "action": "start", "InstanceId": instance_id})

def stop_instance(instance_id):
    if not instance_id:
        return _resp({"error":"instance_id required"}, 400)
    ec2.stop_instances(InstanceIds=[instance_id])
    return _resp({"ok": True, "action": "stop", "InstanceId": instance_id})

def _is_windows(instance_id):
    di = ec2.describe_instances(InstanceIds=[instance_id])
    inst = di["Reservations"][0]["Instances"][0]
    plat = inst.get("Platform", "")
    pdet = inst.get("PlatformDetails", "")
    return (plat == "windows") or ("Windows" in pdet)

def _send_ssm(instance_id, commands, is_windows):
    doc = "AWS-RunPowerShellScript" if is_windows else "AWS-RunShellScript"
    resp = ssm.send_command(
        InstanceIds=[instance_id],
        DocumentName=doc,
        Parameters={"commands": commands},
        CloudWatchOutputConfig={"CloudWatchOutputEnabled": False}
    )
    cmd_id = resp["Command"]["CommandId"]
    # poll up to ~20s
    for _ in range(20):
        time.sleep(1)
        inv = ssm.get_command_invocation(CommandId=cmd_id, InstanceId=instance_id)
        if inv["Status"] in ("Success","Failed","Cancelled","TimedOut"):
            return inv
    return {"Status":"TimedOut","StandardOutputContent":"","StandardErrorContent":"Timed out"}

def service_status(instance_id, service_name):
    if not instance_id or not service_name:
        return _resp({"error":"instance_id and service required"}, 400)
    win = _is_windows(instance_id)
    if win:
        commands = [f'try {{ (Get-Service -Name "{service_name}").Status }} catch {{ "NotFound" }}']
    else:
        commands = [f'systemctl is-active {service_name} || echo NotFound']
    inv = _send_ssm(instance_id, commands, win)
    out = (inv.get("StandardOutputContent") or "").strip()
    err = (inv.get("StandardErrorContent") or "").strip()
    status = out.splitlines()[-1].strip() if out else ("error" if err else "")
    return _resp({
        "InstanceId": instance_id,
        "Service": service_name,
        "OS": "Windows" if win else "Linux",
        "Status": status,
        "SSM": inv.get("Status")
    })

def service_start(instance_id, service_name):
    if not instance_id or not service_name:
        return _resp({"error":"instance_id and service required"}, 400)
    win = _is_windows(instance_id)
    if win:
        commands = [f'try {{ Start-Service -Name "{service_name}" -ErrorAction Stop; "OK" }} catch {{ "ERR" }}']
    else:
        commands = [f'sudo systemctl start {service_name} || echo ERR']
    inv = _send_ssm(instance_id, commands, win)
    return service_status(instance_id, service_name)

def service_stop(instance_id, service_name):
    if not instance_id or not service_name:
        return _resp({"error":"instance_id and service required"}, 400)
    win = _is_windows(instance_id)
    if win:
        commands = [f'try {{ Stop-Service -Name "{service_name}" -Force -ErrorAction Stop; "OK" }} catch {{ "ERR" }}']
    else:
        commands = [f'sudo systemctl stop {service_name} || echo ERR']
    inv = _send_ssm(instance_id, commands, win)
    return service_status(instance_id, service_name)

def lambda_handler(event, context):
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
    return _resp({"error":"unknown action"}, 400)
