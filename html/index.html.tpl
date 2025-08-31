<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta http-equiv="x-ua-compatible" content="ie=edge" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>EC2 Dashboard • Verify your email</title>
  <style>
    :root {
      --bg: #0b1220;
      --panel: #121b2e;
      --muted: #a9b4c6;
      --text: #e7eefc;
      --danger: #ff6b6b;
      --ok: #63e6be;
      --btnStart: linear-gradient(90deg,#5aa8ff,#79f8d6);
    }
    html,body{margin:0;height:100%;background:var(--bg);color:var(--text);font:16px/1.4 system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Cantarell,'Helvetica Neue',Arial}
    .wrap{min-height:100%;display:grid;place-items:center;padding:24px}
    .card{
      width:min(760px,92vw);
      background:rgba(18,27,46,.92);
      border-radius:16px;
      box-shadow:0 20px 60px rgba(0,0,0,.45);
      padding:28px 28px 24px;
      backdrop-filter:saturate(140%) blur(6px);
    }
    h1{margin:0 0 14px;font-size:22px;letter-spacing:.2px}
    p.sub{margin:0 0 20px;color:var(--muted)}
    .row{display:flex;gap:12px;flex-wrap:wrap}
    .row>*{flex:1 1 260px}
    label{display:block;margin:16px 0 8px;color:var(--muted);font-size:13px}
    input{
      width:100%;height:44px;border-radius:10px;border:1px solid #1e2942;
      background:#0e1627;color:var(--text);padding:0 12px;outline:none
    }
    input:focus{border-color:#2f8fff;box-shadow:0 0 0 3px rgba(47,143,255,.15)}
    button{
      height:44px;border:0;border-radius:10px;padding:0 16px;cursor:pointer;
      color:#081018;font-weight:600
    }
    .btnPrimary{background:var(--btnStart);min-width:140px}
    .btnGhost{background:#1a2440;color:#d9e7ff}
    .msg{min-height:22px;margin-top:10px;font-size:13px}
    .msg.ok{color:var(--ok)}
    .msg.err{color:var(--danger)}
    .foot{margin-top:18px;color:var(--muted);font-size:13px}
    a{color:#8fd8ff;text-decoration:none}
    a:hover{text-decoration:underline}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <h1>Verify your email</h1>
      <p class="sub">Enter your email to receive a one-time code. Allowed domain: <strong>${allowed_email_domain}</strong>.</p>

      <div class="row">
        <div>
          <label for="otpEmail">Email</label>
          <input id="otpEmail" type="email" placeholder="name@${allowed_email_domain}" autocomplete="email" />
        </div>
        <div style="align-self:end">
          <button id="btnReq" class="btnGhost" type="button">Request OTP</button>
        </div>
      </div>

      <div class="row">
        <div>
          <label for="otpCode">6-digit code</label>
          <input id="otpCode" inputmode="numeric" maxlength="6" placeholder="123456" />
        </div>
        <div style="align-self:end">
          <button id="btnVer" class="btnPrimary" type="button">Verify OTP</button>
        </div>
      </div>

      <div id="otpMsg" class="msg"></div>

      <div class="foot">
        After successful verification you’ll be redirected to the credentials page.
      </div>
    </div>
  </div>

  <script>
  (function () {
    // Persist API base url so login.js can reuse it too
    const API = "${api_base_url}";
    const ALLOWED = "${allowed_email_domain}";
    const OTP_TTL_SECONDS = 600; // 10 minutes

    try {
      // Keep a copy in localStorage for other pages
      const current = localStorage.getItem("api_base_url");
      if (current !== API) localStorage.setItem("api_base_url", API);
    } catch (_) {}

    const emailEl = document.getElementById('otpEmail');
    const codeEl  = document.getElementById('otpCode');
    const reqBtn  = document.getElementById('btnReq');
    const verBtn  = document.getElementById('btnVer');
    const msgEl   = document.getElementById('otpMsg');

    const setMsg = (t, cls) => { msgEl.className = 'msg ' + (cls||''); msgEl.textContent = t||''; };

    async function post(path, body) {
      const r = await fetch(API + path, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body || {})
      });
      const data = await r.json().catch(()=> ({}));
      if (!r.ok) throw new Error(data.error || data.message || ('http_'+r.status));
      return data;
    }

    reqBtn.onclick = async () => {
      setMsg('');
      const email = (emailEl.value||'').trim().toLowerCase();
      if (!email.endsWith('@'+ALLOWED)) { setMsg('bad_email_domain', 'err'); return; }
      try {
        reqBtn.disabled = true;
        await post('/request-otp', { email });
        setMsg('otp_sent', 'ok');
      } catch (e) {
        setMsg(e.message || 'send_failed', 'err');
      } finally {
        reqBtn.disabled = false;
      }
    };

    verBtn.onclick = async () => {
      setMsg('');
      const email = (emailEl.value||'').trim().toLowerCase();
      const code  = (codeEl.value||'').trim();
      if (!email.endsWith('@'+ALLOWED)) { setMsg('bad_email_domain', 'err'); return; }
      if (!/^[0-9]{6}$/.test(code))      { setMsg('bad_code', 'err'); return; }
      try {
        verBtn.disabled = true;
        await post('/verify-otp', { email, code });
        // Store short-lived proof for the next page
        sessionStorage.setItem('otp_token', code);
        sessionStorage.setItem('otp_email', email);
        sessionStorage.setItem('otp_ts', String(Math.floor(Date.now()/1000)));

        // Only now go to credentials page
        location.href = '/login.html?v=' + Date.now();
      } catch (e) {
        setMsg(e.message || 'invalid_otp', 'err');
      } finally {
        verBtn.disabled = false;
      }
    };

    // If user already has a fresh OTP, you may auto-forward (optional)
    try {
      const ts = Number(sessionStorage.getItem('otp_ts') || 0);
      if (ts && (Math.floor(Date.now()/1000) - ts) < OTP_TTL_SECONDS) {
        // we have a very recent OTP -> let them continue if they refresh
        // location.href = '/login.html?v=' + Date.now();
      }
    } catch (_) {}
  })();
  </script>
</body>
</html>
