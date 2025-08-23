import json, os, time
import boto3
from botocore.exceptions import ClientError

_ec2 = boto3.client('ec2')
_ssm = boto3.client('ssm')

def _resp(status, body):
    return {
        'statusCode': status,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Headers': 'authorization,content-type',
            'Access-Control-Allow-Methods': 'GET,POST,OPTIONS'
        },
        'body': json.dumps(body)
    }

def _is_windows(instance_id: str) -> bool:
    di = _ec2.describe_instances(InstanceIds=[instance_id])
    inst = di['Reservations'][0]['Instances'][0]
    plat = (inst.get('Platform') or '').lower()
    pdet = (inst.get('PlatformDetails') or '').lower()
    return plat == 'windows' or 'windows' in pdet

def _send_ssm(instance_id: str, commands, is_windows: bool):
    doc = 'AWS-RunPowerShellScript' if is_windows else 'AWS-RunShellScript'
    try:
        resp = _ssm.send_command(
            InstanceIds=[instance_id],
            DocumentName=doc,
            Parameters={'commands': commands},
            CloudWatchOutputConfig={'CloudWatchOutputEnabled': False}
        )
    except Exception as e:
        return {'Status': 'Error', 'Error': f'SendCommand: {e}'}

    cmd_id = resp['Command']['CommandId']
    for _ in range(45):         # ~45s
        time.sleep(1)
        try:
            inv = _ssm.get_command_invocation(CommandId=cmd_id, InstanceId=instance_id)
        except Exception as e:
            return {'Status': 'Error', 'Error': f'GetCommandInvocation: {e}'}
        if inv['Status'] in ('Success', 'Failed', 'Cancelled', 'TimedOut'):
            return inv
    return {'Status': 'TimedOut', 'StandardOutputContent': '', 'StandardErrorContent': 'Command timed out'}

def _tags_to_map(tags):
    return {t.get('Key'): t.get('Value') for t in (tags or [])}

def _first_group(s, regex):
    import re
    m = re.search(regex, s or '', re.I)
    return m.group(1) if m else ''

def _infer_env(name, tags):
    t = _tags_to_map(tags)
    return (
        t.get('Environment') or t.get('Env') or t.get('ENV') or t.get('environment')
        or _first_group(name, r'(PRQ[A0-9]+|PNQA[0-9]+|AVQA[0-9]+|DM-[A-Za-z0-9-]+)')
    )

def _infer_service(name, tags):
    t = _tags_to_map(tags)
    svc = t.get('Service') or t.get('Svc') or t.get('service') or ''
    if svc:
        return svc
    lname = (name or '').lower()
    for key in ['sql','web','app','api','etl','batch']:
        if key in lname:
            return key
    return ''

def list_instances():
    try:
        ec2 = _ec2.describe_instances()
        out = []
        # SSM ping map (optional)
        ping = {}
        try:
            next_token = None
            while True:
                kw = {'MaxResults': 50}
                if next_token: kw['NextToken'] = next_token
                resp = _ssm.describe_instance_information(**kw)
                for it in resp.get('InstanceInformationList', []):
                    ping[it['InstanceId']] = it.get('PingStatus')
                next_token = resp.get('NextToken')
                if not next_token: break
        except Exception:
            ping = {}

        for r in ec2.get('Reservations', []):
            for i in r.get('Instances', []):
                st = i.get('State',{}).get('Name')
                name = next((t['Value'] for t in i.get('Tags',[]) if t['Key']=='Name'), '')
                out.append({
                    'id': i['InstanceId'],
                    'name': name,
                    'state': st,
                    'env': _infer_env(name, i.get('Tags')),
                    'service': _infer_service(name, i.get('Tags')),
                    'az': i.get('Placement',{}).get('AvailabilityZone'),
                    'ip': i.get('PrivateIpAddress'),
                    'desc': i.get('InstanceType'),
                    'ping': ping.get(i['InstanceId'], '-')
                })
        return _resp(200, {'instances': out})
    except ClientError as e:
        return _resp(500, {'error': str(e)})

def mutate_instance(action, instance_id):
    try:
        if action == 'start':
            _ec2.start_instances(InstanceIds=[instance_id])
        elif action == 'stop':
            _ec2.stop_instances(InstanceIds=[instance_id])
        elif action == 'reboot':
            _ec2.reboot_instances(InstanceIds=[instance_id])
        elif action == 'status':
            pass
        else:
            return _resp(400, {'error': f'Unsupported action: {action}'})
        return _resp(200, {'ok': True})
    except ClientError as e:
        return _resp(400, {'error': str(e)})

def _split_patterns(patt: str):
    if not patt: return []
    raw = [p.strip() for p in patt.replace(';', ',').split(',')]
    return [p for p in raw if p]

def services_query(instance_id: str, pattern_text: str):
    if not instance_id:
        return _resp(400, {'error': 'instance_id required'})

    pats = _split_patterns(pattern_text) or ['SQL','SQLServer','ServiceManagement']
    win = _is_windows(instance_id)

    if win:
        or_filters = ' -or '.join([f"$_.Name -like '*{p}*' -or $_.DisplayName -like '*{p}*'" for p in pats])
        ps = (
            f"$svcs = Get-Service | Where-Object {{ {or_filters} }} | "
            f"Select-Object Name,DisplayName,Status; $svcs | ConvertTo-Json -Compress"
        )
        cmd = [ps]
    else:
        patt = '|'.join([p.replace('"','').replace("'",'') for p in pats])
        sh = (
            "systemctl list-units --type=service --all --no-legend | "
            f"egrep -i '\\b({patt})' || true"
        )
        cmd = [sh]

    inv = _send_ssm(instance_id, cmd, win)
    if inv.get('Status') != 'Success':
        return _resp(200, {
            'InstanceId': instance_id,
            'OS': 'Windows' if win else 'Linux',
            'Services': [],
            'Note': inv.get('StandardErrorContent') or inv.get('Error') or 'Command did not complete'
        })

    out = (inv.get('StandardOutputContent') or '').strip()
    services = []
    if win:
        text = out if out else '[]'
        try:
            data = json.loads(text)
            if isinstance(data, dict): data = [data]
            for s in data:
                services.append({
                    'name': s.get('Name'),
                    'displayName': s.get('DisplayName') or s.get('Name'),
                    'status': (s.get('Status') or '').lower()
                })
        except Exception:
            services = []
    else:
        for line in out.splitlines():
            parts = line.split()
            if not parts: continue
            unit = parts[0]
            status = parts[3] if len(parts) > 3 else (parts[2] if len(parts) > 2 else 'unknown')
            services.append({'name': unit, 'displayName': unit, 'status': status})

    return _resp(200, {
        'InstanceId': instance_id,
        'OS': 'Windows' if win else 'Linux',
        'Patterns': pats,
        'Services': services
    })

def service_toggle(instance_id: str, service_name: str, target: str):
    if not instance_id or not service_name:
        return _resp(400, {'error': 'instance_id and service required'})

    win = _is_windows(instance_id)
    if win:
        if target == 'start':
            commands = [(
                f'try {{ Start-Service -Name "{service_name}" -ErrorAction Stop; "OK" }} '
                f'catch {{ try {{ Start-Service -DisplayName "{service_name}" -ErrorAction Stop; "OK" }} '
                f'catch {{ "ERR" }} }}'
            )]
        else:
            commands = [(
                f'try {{ Stop-Service -Name "{service_name}" -Force -ErrorAction Stop; "OK" }} '
                f'catch {{ try {{ Stop-Service -DisplayName "{service_name}" -Force -ErrorAction Stop; "OK" }} '
                f'catch {{ "ERR" }} }}'
            )]
    else:
        cmd = 'start' if target == 'start' else 'stop'
        commands = [f'sudo systemctl {cmd} {service_name} || echo ERR']

    _send_ssm(instance_id, commands, win)

    # re-check the status after toggle
    if win:
        qps = (
            f'try {{ (Get-Service -Name "{service_name}").Status }} '
            f'catch {{ try {{ (Get-Service -DisplayName "{service_name}").Status }} catch {{ "NotFound" }} }}'
        )
        inv = _send_ssm(instance_id, [qps], win)
        status = (inv.get('StandardOutputContent') or '').strip() if inv.get('Status')=='Success' else 'unknown'
    else:
        inv = _send_ssm(instance_id, [f'systemctl is-active {service_name} || echo NotFound'], win)
        status = (inv.get('StandardOutputContent') or '').strip() if inv.get('Status')=='Success' else 'unknown'

    return _resp(200, {'InstanceId': instance_id, 'Service': service_name, 'Status': status})

def handler(event, context):
    method = event.get('requestContext',{}).get('http',{}).get('method','GET')
    route  = event.get('requestContext',{}).get('http',{}).get('path','/')

    if method == 'OPTIONS':
        return _resp(200, {'ok': True})

    if route.endswith('/instances'):
        if method == 'GET':
            return list_instances()

        if method == 'POST':
            try:
                body = json.loads(event.get('body') or '{}')
            except Exception:
                body = {}
            act = body.get('action')
            iid = body.get('instance_id')

            if act in ('start','stop','reboot','status'):
                return mutate_instance(act, iid)
            if act == 'services_query':
                return services_query(iid, body.get('pattern') or '')
            if act == 'service_start':
                return service_toggle(iid, body.get('service'), 'start')
            if act == 'service_stop':
                return service_toggle(iid, body.get('service'), 'stop')

            return _resp(400, {'error':'Unsupported action'})

    return _resp(404, {'error':'Not found'})
