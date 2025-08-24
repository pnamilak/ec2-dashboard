import json, time, re
import boto3
from botocore.exceptions import ClientError

_ec2 = boto3.client('ec2')
_ssm = boto3.client('ssm')

# ---------------- basics ----------------

def _http(status, body):
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

def _tags_to_map(tags):
    return {t.get('Key'): t.get('Value') for t in (tags or [])}

def _first_group(s, pattern):
    m = re.search(pattern, s or '', re.I)
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
    if svc: return svc
    lname = (name or '').lower()
    for key in ['sql','web','svc','iis','redis','app','api','etl','batch']:
        if key in lname: return key
    return ''

def _send_ssm(instance_id: str, commands, is_windows: bool):
    doc = 'AWS-RunPowerShellScript' if is_windows else 'AWS-RunShellScript'
    try:
        resp = _ssm.send_command(
            InstanceIds=[instance_id],
            DocumentName=doc,
            Parameters={'commands': commands},
            CloudWatchOutputConfig={'CloudWatchOutputEnabled': False},
        )
    except Exception as e:
        return {'Status': 'Error', 'Error': f'SendCommand: {e}'}

    cmd_id = resp['Command']['CommandId']
    # wait up to ~45s
    for _ in range(45):
        time.sleep(1)
        try:
            inv = _ssm.get_command_invocation(CommandId=cmd_id, InstanceId=instance_id)
        except Exception as e:
            return {'Status': 'Error', 'Error': f'GetCommandInvocation: {e}'}
        if inv['Status'] in ('Success', 'Failed', 'Cancelled', 'TimedOut'):
            return inv
    return {'Status': 'TimedOut', 'StandardOutputContent': '', 'StandardErrorContent': 'Command timed out'}

def _is_windows(instance_id: str) -> bool:
    di = _ec2.describe_instances(InstanceIds=[instance_id])
    inst = di['Reservations'][0]['Instances'][0]
    plat = (inst.get('Platform') or '').lower()
    pdet = (inst.get('PlatformDetails') or '').lower()
    return plat == 'windows' or 'windows' in pdet

def _ssm_info_map():
    """Map InstanceId -> {PingStatus, PlatformName, PlatformVersion} for SSM-managed instances."""
    out = {}
    token = None
    while True:
        kw = {'MaxResults': 50}
        if token: kw['NextToken'] = token
        resp = _ssm.describe_instance_information(**kw)
        for it in resp.get('InstanceInformationList', []):
            out[it['InstanceId']] = {
                'ping': it.get('PingStatus', '-'),
                'os_name': it.get('PlatformName') or it.get('PlatformType') or '',
                'os_ver': it.get('PlatformVersion') or ''
            }
        token = resp.get('NextToken')
        if not token: break
    return out

# ---------------- list & power ----------------

def list_instances():
    try:
        ssm_map = _ssm_info_map()
        ec2 = _ec2.describe_instances()
        items = []
        for r in ec2.get('Reservations', []):
            for i in r.get('Instances', []):
                iid  = i['InstanceId']
                name = next((t['Value'] for t in i.get('Tags',[]) if t['Key']=='Name'), '')
                env  = _infer_env(name, i.get('Tags'))
                svc  = _infer_service(name, i.get('Tags'))
                st   = i.get('State',{}).get('Name')
                ssm  = ssm_map.get(iid, {})
                os_s = (ssm.get('os_name') or '').strip()
                os_v = (ssm.get('os_ver') or '').strip()
                os_full = (os_s + (' ' + os_v if os_v else '')).strip() or '-'
                items.append({
                    'id': iid,
                    'name': name,
                    'state': st,
                    'env': env,
                    'service': svc,  # used by UI to pick default service patterns
                    'az': i.get('Placement',{}).get('AvailabilityZone'),
                    'ip': i.get('PrivateIpAddress'),
                    'type': i.get('InstanceType'),
                    'ping': ssm.get('ping', '-'),
                    'os': os_full,
                })

        total = len(items)
        running = sum(1 for x in items if x['state'] == 'running')
        stopped = sum(1 for x in items if x['state'] == 'stopped')

        return _http(200, {'instances': items, 'summary': {'total': total, 'running': running, 'stopped': stopped}})
    except ClientError as e:
        return _http(500, {'error': str(e)})

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
            return _http(400, {'error': f'Unsupported action: {action}'})
        return _http(200, {'ok': True})
    except ClientError as e:
        return _http(400, {'error': str(e)})

# ---------------- details: OS/SQL + services ----------------

def _split_patterns(patt: str):
    if not patt: return []
    raw = [p.strip() for p in patt.replace(';', ',').split(',')]
    return [p for p in raw if p]

def _sql_version_windows(instance_id: str):
    ps = r"""
$results = @()
$roots = @("HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server", "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Microsoft SQL Server")
foreach ($root in $roots) {
  try {
    $instKey = Join-Path $root "Instance Names\SQL"
    $map = Get-ItemProperty -Path $instKey -ErrorAction Stop
    foreach ($p in $map.PSObject.Properties) {
      $instName = $p.Name
      $instId = $p.Value
      $setup = Join-Path $root "$instId\Setup"
      $v = (Get-ItemProperty -Path $setup -ErrorAction SilentlyContinue)
      if ($v) {
        $results += [pscustomobject]@{ Name=$instName; Version=$($v.Version); Edition=$($v.Edition) }
      }
    }
  } catch {}
}
if ($results.Count -eq 0) { "[]" } else { $results | ConvertTo-Json -Compress }
""".strip()
    inv = _send_ssm(instance_id, [ps], True)
    if inv.get('Status') != 'Success': return ''
    txt = (inv.get('StandardOutputContent') or '').strip()
    try:
        data = json.loads(txt) if txt else []
        if isinstance(data, dict): data = [data]
        if not data: return ''
        return '; '.join([f"{d.get('Name','MSSQL')} {d.get('Version','')}".strip() for d in data])
    except Exception:
        return ''

def _sql_version_linux(instance_id: str):
    sh = r"""
rpm -q mssql-server --qf "%{VERSION}-%{RELEASE}\n" 2>/dev/null \
 || dpkg-query -W -f='${Version}\n' mssql-server 2>/dev/null \
 || echo ""
""".strip()
    inv = _send_ssm(instance_id, [sh], False)
    if inv.get('Status') != 'Success': return ''
    ver = (inv.get('StandardOutputContent') or '').strip().splitlines()
    ver = [x for x in ver if x.strip()]
    return ver[0] if ver else ''

def _get_os_string(instance_id: str):
    mp = _ssm_info_map()
    s = mp.get(instance_id, {})
    os_s = (s.get('os_name') or '').strip()
    os_v = (s.get('os_ver') or '').strip()
    return (os_s + (' ' + os_v if os_v else '')).strip()

def details_services(instance_id: str, pattern_text: str):
    pats = _split_patterns(pattern_text) or ['SQL','SQLServer','ServiceManagement','MSSQL','IIS','W3SVC','AppHostSvc','redis']
    win = _is_windows(instance_id)

    # list matching services
    if win:
        or_filters = ' -or '.join([f"$_.Name -like '*{p}*' -or $_.DisplayName -like '*{p}*'" for p in pats])
        ps = (
            f"$svcs = Get-Service | Where-Object {{ {or_filters} }} "
            f"| Select-Object Name,DisplayName,Status; $svcs | ConvertTo-Json -Compress"
        )
        cmd = [ps]
    else:
        patt = '|'.join([p.replace('\"','').replace(\"'\",'') for p in pats])
        sh = (
            "systemctl list-units --type=service --all --no-legend | "
            f"egrep -i '\\b({patt})' || true"
        )
        cmd = [sh]

    inv = _send_ssm(instance_id, cmd, win)
    services = []
    if inv.get('Status') == 'Success':
        out = (inv.get('StandardOutputContent') or '').strip()
        if win:
            try:
                data = json.loads(out) if out else []
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

    os_full = _get_os_string(instance_id) or ('Windows' if win else 'Linux')
    sql_ver = _sql_version_windows(instance_id) if win else _sql_version_linux(instance_id)

    return {'OS': os_full, 'isWindows': win, 'SQL': (sql_ver or '-'), 'Services': services}

def service_toggle(instance_id: str, service_name: str, target: str):
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

    # re-check status
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

    return status

def iis_reset(instance_id: str):
    if not _is_windows(instance_id):
        return {'ok': False, 'note': 'IIS reset supported only on Windows'}
    ps = 'iisreset /restart'
    inv = _send_ssm(instance_id, [ps], True)
    ok = inv.get('Status') == 'Success'
    return {'ok': ok, 'note': inv.get('StandardErrorContent') or ''}

# ---------------- router ----------------

def lambda_handler(event, context):
    method = event.get('requestContext',{}).get('http',{}).get('method','GET')
    path   = event.get('requestContext',{}).get('http',{}).get('path','/')

    if method == 'OPTIONS':
        return _http(200, {'ok': True})

    if path.endswith('/instances'):
        if method == 'GET':
            return list_instances()

        if method == 'POST':
            try:
                body = json.loads(event.get('body') or '{}')
            except Exception:
                body = {}
            act = body.get('action', '')
            iid = body.get('instance_id')

            if act in ('start','stop','reboot','status'):
                return mutate_instance(act, iid)

            if act == 'details':
                patt = body.get('pattern') or ''
                data = details_services(iid, patt)
                return _http(200, data)

            if act == 'service_start':
                st = service_toggle(iid, body.get('service',''), 'start')
                return _http(200, {'Service': body.get('service',''), 'Status': st})

            if act == 'service_stop':
                st = service_toggle(iid, body.get('service',''), 'stop')
                return _http(200, {'Service': body.get('service',''), 'Status': st})

            if act == 'iis_reset':
                res = iis_reset(iid)
                return _http(200, res)

            return _http(400, {'error': 'Unsupported action'})

    return _http(404, {'error': 'Not found'})
