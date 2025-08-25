<!doctype html>
<html><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>EC2 Dashboard Access</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600&display=swap" rel="stylesheet"/>
<style>
:root{--bg:#0b1220;--card:#111a2b;--ink:#e5e7eb;--muted:#9ca3af}
*{box-sizing:border-box} body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.4 Inter,system-ui}
.main{max-width:520px;margin:10vh auto;background:#0e172a;border:1px solid #1f2937;border-radius:16px;padding:18px}
label{display:block;margin:8px 0 4px 0}
input{width:100%;padding:10px;border-radius:10px;border:1px solid #243145;background:#0b1325;color:#e5e7eb}
.btn{margin-top:10px;border:1px solid #334155;background:#1e293b;color:#e5e7eb;border-radius:10px;padding:10px 12px;cursor:pointer}
.hint{color:#9ca3af}
.kv{background:#101a2d;border:1px dashed #2b3a57;border-radius:10px;padding:10px;margin-top:10px}
.err{color:#fca5a5;margin-top:8px}
</style>
<script>
window.API_URL = "${api_url}";
window.ALLOWED_DOMAIN = "${allowed_domain}";
</script>
</head>
<body>
  <div class="main">
    <h2 style="margin:0 0 8px 0">Request Access</h2>
    <div class="hint">Only <b>@${allowed_domain}</b> emails are accepted.</div>
    <label>Email</label><input id="email" type="email" placeholder="you@${allowed_domain}" />
    <button id="send" class="btn">Send OTP</button>
    <div id="msg" class="hint"></div>

    <div id="otpBox" style="display:none">
      <label>OTP</label><input id="otp" type="text" inputmode="numeric" pattern="[0-9]*" placeholder="6-digit code" />
      <button id="verify" class="btn">Verify</button>
    </div>

    <div id="err" class="err" style="display:none"></div>

    <div id="access" style="display:none">
      <h3 style="margin-top:16px">Access Granted</h3>
      <div class="kv">
        <div><b>Dashboard URL:</b> <span id="dashUrl"></span></div>
        <div><b>Username:</b> <span id="dashUser"></span></div>
        <div><b>Password:</b> <span id="dashPass"></span></div>
        <div class="hint" style="margin-top:8px">Use these when the browser or app asks for credentials.</div>
      </div>
    </div>
  </div>
  <script src="entry.js?v=${js_ver_short}" defer></script>
</body></html>
