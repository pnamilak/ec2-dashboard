import boto3, json, os, time, base64, re, random, string, hmac, hashlib
from botocore.exceptions import ClientError

ec2 = boto3.client("ec2")
ssm = boto3.client("ssm")
ses = boto3.client("ses")
ddb = boto3.client("dynamodb")

# ENV
OTP_TABLE        = os.environ.get("OTP_TABLE_NAME", "ec2dash-otp")
ALLOWLIST_TABLE  = os.environ.get("ALLOWLIST_TABLE", "ec2dash-allowlist")
SES_SENDER       = os.environ.get("SES_SENDER_EMAIL", "no-reply@domain.com")
ALLOWED_DOMAIN   = (os.environ.get("ALLOWED_EMAIL_DOMAIN","domain.com") or "").lower()
OTP_TTL          = int(os.environ.get("OTP_TTL_SECONDS","300"))
JWT_TTL          = int(os.environ.get("JWT_TTL_SECONDS","3600"))
JWT_SECRET_PARAM = os.environ.get("JWT_SECRET_PARAM","/ec2-dashboard/auth/jwt_secret")
CF_BASIC_AUTH_B64= os.environ.get("CF_BASIC_AUTH_B64","")
AUTH_FALLBACK    = os.environ.get("AUTH_FALLBACK","")

ENV_TOKEN = re.compile(r"([a-z]{2,3}qa\d+)", re.I)
GEN_ENV   = re.compile(r"(prod|prd|ppe|stage|stg|uat|sit|qa|dev|test|dr)", re.I)

def _tag(tags, key):
  for t in tags or []:
    if t.get("Key","").lower()==key.lower(): return t.get("Value","")
  return ""

def _env_from_name(name):
  n=(name or "").strip()
  if not n: return "other"
  first = n.split("-",1)[0]
  if m:=ENV_TOKEN.search(first): return m.group(1).lower()
  if m:=ENV_TOKEN.search(n):     return m.group(1).lower()
  if m:=GEN_ENV.search(n):       return m.group(1).lower()
  return "other"

def _list_instances():
  out=[]
  for page in ec2.get_paginator("describe_instances").paginate():
    for r in page.get("Reservations",[]):
      for i in r.get("Instances",[]):
        iid=i["InstanceId"]; state=i["State"]["Name"]; name=_tag(i.get("Tags"),"Name")
        plat=(i.get("PlatformDetails") or i.get("Platform") or "").lower()
        out.append({
          "id":iid, "name":name or iid, "state":state, "env":_env_from_name(name),
          "platform":"windows" if "windows" in plat else ("linux" if plat else "unknown"),
          "privateIp":i.get("PrivateIpAddress"), "publicIp":i.get("PublicIpAddress")
        })
  return out

def _wait_cmd(cmd_id, iid, timeout=120):
  t0=time.time()
  while True:
    try:
      r=ssm.get_command_invocation(CommandId=cmd_id, InstanceId=iid)
      if r.get("Status") in ("Success","Failed","Cancelled","TimedOut"): return r
    except ClientError as e:
      if e.response.get("Error",{}).get("Code")!="InvocationDoesNotExist": raise
    if time.time()-t0>timeout: return {"Status":"TimedOut","StandardOutputContent":"","StandardErrorContent":"Timeout"}
    time.sleep(2)

def _send_ps(iid, lines, comment="dashboard"):
  r=ssm.send_command(InstanceIds=[iid], DocumentName="AWS-RunPowerShellScript",
                     Parameters={"commands": lines if isinstance(lines,list) else [lines]}, Comment=comment)
  return _wait_cmd(r["Command"]["CommandId"], iid)

def _services_query_windows(iid, patterns):
  pats=[p for p in [x.strip() for x in (patterns or [])] if p] or ["SQL","SQLServer","SQLSERVERAGENT","ServiceManagement"]
  esc="|".join([f"({re.escape(p)})" for p in pats])
  script=f'''
$ErrorActionPreference = "SilentlyContinue"
$re = [regex]"{esc}"
$svcs = Get-Service | Where-Object {{ $_.Name -match $re -or $_.DisplayName -match $re }} |
 Select-Object Name, DisplayName, Status
$osKey = Get-ItemProperty "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
$os = $osKey.ProductName
if ($osKey.DisplayVersion) {{ $os = "$os $($osKey.DisplayVersion)" }} elseif ($osKey.ReleaseId) {{ $os = "$os $($osKey.ReleaseId)" }}
$sqlVers=@()
try {{
 $instRoot=Get-ItemProperty "HKLM:\\SOFTWARE\\Microsoft\\Microsoft SQL Server\\Instance Names\\SQL"
 foreach ($p in $instRoot.PSObject.Properties) {{
  $id=$p.Value; $cv=Get-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Microsoft SQL Server\\$id\\MSSQLServer\\CurrentVersion" -ErrorAction SilentlyContinue
  if ($cv) {{ $sqlVers += "$($p.Name) $($cv.CurrentVersion)" }}
 }}
}} catch {{}}
if (-not $sqlVers -and (Get-Command sqlcmd -ErrorAction SilentlyContinue)) {{
 try {{ $txt = sqlcmd -S . -Q "SET NOCOUNT ON; SELECT @@VERSION" -W -h-1 2>$null; if ($txt) {{ $sqlVers=@($txt) }} }} catch {{}}
}}
[PSCustomObject]@{{ os=$os; sql=($sqlVers -join '; '); services=$svcs }} | ConvertTo-Json -Depth 4 -Compress
'''
  res=_send_ps(iid, script, "services-query")
  if res.get("Status")!="Success": raise Exception(res.get("StandardErrorContent") or "SSM command failed")
  payload=(res.get("StandardOutputContent") or "").strip()
  try: return json.loads(payload) if payload else {}
  except Exception: return {"raw": payload}

def _service_control_windows(iid, name, op):
  ps = (f'($s=Start-Service -Name "{name}" -PassThru -ErrorAction Stop; Get-Service -Name "{name}") | Select Name,DisplayName,Status | ConvertTo-Json -Compress'
        if op=="start" else
        f'($s=Stop-Service -Name "{name}" -Force -PassThru -ErrorAction Stop; Get-Service -Name "{name}") | Select Name,DisplayName,Status | ConvertTo-Json -Compress')
  res=_send_ps(iid, ps, f"service-{op}")
  if res.get("Status")!="Success": raise Exception(res.get("StandardErrorContent") or "SSM command failed")
  return json.loads(res.get("StandardOutputContent","{}") or "{}")

def _iis_reset(iid):
  res=_send_ps(iid, "iisreset", "iis-reset")
  return {"ok": res.get("Status")=="Success", "stdout":res.get("StandardOutputContent",""), "stderr":res.get("StandardErrorContent","")}

# ---------- OTP & JWT ----------
def _rand_otp(n=6): return "".join(random.choice(string.digits) for _ in range(n))
def _put_otp(email, code):
  now=int(time.time()); exp=now+OTP_TTL
  ddb.put_item(TableName=OTP_TABLE, Item={
    "email":{"S":email}, "otp_code":{"S":code}, "issued_at":{"N":str(now)}, "expires_at":{"N":str(exp)}
  })
def _get_otp(email): return ddb.get_item(TableName=OTP_TABLE, Key={"email":{"S":email}}).get("Item")
def _del_otp(email): 
  try: ddb.delete_item(TableName=OTP_TABLE, Key={"email":{"S":email}})
  except Exception: pass

def _send_email(email, code):
  ses.send_email(Source=SES_SENDER, Destination={"ToAddresses":[email]},
    Message={"Subject":{"Data":"Your EC2 Dashboard OTP"},
             "Body":{"Text":{"Data":f"Your OTP is {code}. Expires in {OTP_TTL//60} minutes."}}})

_SECRET=None
def _jwt_secret():
  global _SECRET
  if _SECRET: return _SECRET
  r=ssm.get_parameter(Name=JWT_SECRET_PARAM, WithDecryption=True)
  _SECRET=r["Parameter"]["Value"].encode()
  return _SECRET

def _b64url(b: bytes)->str: return base64.urlsafe_b64encode(b).decode().rstrip("=")
def _make_jwt(email):
  h={"alg":"HS256","typ":"JWT"}; now=int(time.time()); p={"sub":email,"email":email,"iat":now,"exp":now+JWT_TTL,"iss":"ec2dash"}
  h_b=_b64url(json.dumps(h,separators=(",",":")).encode()); p_b=_b64url(json.dumps(p,separators=(",",":")).encode())
  sig=hmac.new(_jwt_secret(), f"{h_b}.{p_b}".encode(), hashlib.sha256).digest(); s_b=_b64url(sig)
  return f"{h_b}.{p_b}.{s_b}"

def _ok(body): return {"statusCode":200,"headers":{"Content-Type":"application/json"},"body":json.dumps(body)}
def _bad(code,msg): return {"statusCode":code,"headers":{"Content-Type":"application/json"},"body":json.dumps({"error":msg})}

def lambda_handler(event,_ctx):
  method=(event.get("requestContext",{}).get("http",{}).get("method") or event.get("httpMethod") or "GET").upper()
  path  =(event.get("requestContext",{}).get("http",{}).get("path")   or event.get("rawPath") or "/")

  # ----- ENTRY: request OTP -----
  if method=="POST" and path.endswith("/auth/request-otp"):
    body=json.loads(event.get("body") or "{}"); email=(body.get("email") or "").strip().lower()
    if not email or not email.endswith("@"+ALLOWED_DOMAIN): return _bad(400, f"Only @{ALLOWED_DOMAIN} emails are allowed.")
    code=_rand_otp(); _put_otp(email, code); _send_email(email, code)
    return _ok({"ok":True})

  # ----- ENTRY: verify OTP -> returns JWT -----
  if method=="POST" and path.endswith("/auth/verify"):
    body=json.loads(event.get("body") or "{}"); email=(body.get("email") or "").strip().lower(); otp=(body.get("otp") or "").strip()
    if not email.endswith("@"+ALLOWED_DOMAIN): return _bad(400, f"Only @{ALLOWED_DOMAIN} emails are allowed.")
    item=_get_otp(email)
    if not item: return _bad(400,"OTP not found or expired.")
    if int(time.time())>int(item["expires_at"]["N"]): _del_otp(email); return _bad(400,"OTP expired.")
    if otp!=item["otp_code"]["S"]: return _bad(400,"Invalid OTP.")
    _del_otp(email)
    return _ok({"ok":True, "token":_make_jwt(email)})

  # ----- ENTRY: access details (requires JWT via authorizer) -----
  if method=="POST" and path.endswith("/auth/access-details"):
    # email propagated by authorizer
    rc = event.get("requestContext",{}); lam=rc.get("authorizer",{}).get("lambda",{})
    email=(lam.get("principalId") or "").lower()
    if not email or not email.endswith("@"+ALLOWED_DOMAIN): return _bad(403,"Unauthorized")
    # allow-list check
    item=ddb.get_item(TableName=ALLOWLIST_TABLE, Key={"email":{"S":email}}).get("Item")
    if not item: return _bad(403,"You are not allowed to access the dashboard. Contact the admin.")
    # decode Basic user:pass
    try:
      userpass=base64.b64decode(CF_BASIC_AUTH_B64).decode()
      user, pw = userpass.split(":",1)
    except Exception:
      user, pw = "admin", "Password123!"
    dash_url = "https://" + os.environ.get("REAL_CF_DOMAIN","")  # not set here; we return from outputs instead
    return _ok({"ok":True, "dashboard_url":"(see Terraform output cloudfront_domain)", "user":user, "password":pw})

  # ----- REAL dashboard API (authorizer: Basic fallback) -----
  try:
    if method=="GET" and path.endswith("/instances"):
      items=_list_instances()
      total=len(items); running=sum(1 for x in items if x["state"]=="running"); stopped=sum(1 for x in items if x["state"]=="stopped")
      return _ok({"items":items,"summary":{"total":total,"running":running,"stopped":stopped}})
    if method=="POST" and path.endswith("/instances"):
      body=json.loads(event.get("body") or "{}"); action=(body.get("action") or "").lower()
      if action in ("start","stop","reboot"):
        iid=body.get("instanceId"); 
        if not iid: return _bad(400,"instanceId required")
        {"start": ec2.start_instances, "stop": ec2.stop_instances, "reboot": ec2.reboot_instances}[action](InstanceIds=[iid])
        return _ok({"ok":True})
      if action=="services_query":
        iid=body.get("instanceId"); data=_services_query_windows(iid, body.get("patterns") or [])
        return _ok({"ok":True,"data":data})
      if action in ("service_start","service_stop"):
        iid=body.get("instanceId"); name=body.get("name"); 
        if not (iid and name): return _bad(400,"instanceId and name required")
        op="start" if action=="service_start" else "stop"
        return _ok({"ok":True,"service":_service_control_windows(iid, name, op)})
      if action=="iis_reset":
        return _ok(_iis_reset(body.get("instanceId")))
      return _bad(400,"unknown action")
    return _bad(404,"not found")
  except Exception as e:
    return _bad(500,str(e))
