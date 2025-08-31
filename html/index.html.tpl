<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>EC2 Dashboard</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    :root{--bg:#0e1624;--panel:#121b2b;--ink:#e6e9ef;--mut:#9aa4b2;--brand:#7b8cff}
    body{margin:0;background:var(--bg);color:var(--ink);font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,"Helvetica Neue",sans-serif}
    /* Gate = full-screen OTP overlay */
    #otpGate{position:fixed;inset:0;display:none;align-items:center;justify-content:center;background:rgba(2,10,24,.7);backdrop-filter:blur(4px);z-index:9999}
    .card{background:var(--panel);border-radius:16px;padding:18px;min-width:580px;box-shadow:0 10px 30px rgba(0,0,0,.35)}
    .row{display:flex;gap:10px}
    input{background:#0f1a2e;border:1px solid #243355;color:#e6e9ef;border-radius:10px;padding:10px}
    .btn{padding:10px 14px;border-radius:10px;border:0;background:#203252;color:#dfe7f5;cursor:pointer}
    .mut{color:var(--mut);font-size:12px;margin-top:8px}
    .error{color:#ffb3bc;margin-top:8px;font-size:13px}
  </style>
</head>
<body>
  <!-- Your existing dashboard markup can stay as-is above/below -->

  <!-- OTP full-screen gate -->
  <div id="otpGate">
    <div class="card">
      <h3 style="margin:0 0 12px 0">Verify your email</h3>
      <div class="row" style="margin-bottom:10px">
        <input id="otpEmail" placeholder="name@${allowed_email_domain}" style="flex:1">
        <button class="btn" onclick="requestOtp()">Request OTP</button>
      </div>
      <div class="row">
        <input id="otpCode" placeholder="6-digit code" style="width:160px">
        <button class="btn" onclick="verifyOtp()">Verify OTP</button>
      </div>
      <div id="otpMsg" class="error" style="display:none"></div>
      <div class="mut">Allowed domain: ${allowed_email_domain}. After verifying OTP you’ll be redirected to the credential page.</div>
    </div>
  </div>

<script>
  const API = "${api_base_url}";

  function $(id){ return document.getElementById(id); }
  function showGate(){ $("otpGate").style.display = "flex"; }
  function hideGate(){ $("otpGate").style.display = "none"; }
  function say(id, msg){ const el=$(id); el.textContent=msg||""; el.style.display=msg?"block":"none"; }

  function http(path, method, obj){
    return fetch(API + path, {method, headers:{"content-type":"application/json"}, body: obj? JSON.stringify(obj): undefined})
    .then(async r=>{
      const data = await r.json().catch(()=> ({}));
      if(!r.ok){ throw new Error((data && (data.error||data.message)) || ("http "+r.status)); }
      return data;
    });
  }

  // OTP
  function requestOtp(){
    const em = $("otpEmail").value.trim();
    say("otpMsg","");
    if(!em){ say("otpMsg","enter email"); return; }
    http("/request-otp","POST",{email:em})
      .then(()=> say("otpMsg","OTP sent to your inbox."))
      .catch(e=> say("otpMsg", e.message||"failed"));
  }
  function verifyOtp(){
    const em = $("otpEmail").value.trim();
    const cd = $("otpCode").value.trim();
    say("otpMsg","");
    if(!em || !cd){ say("otpMsg","enter email & code"); return; }
    http("/verify-otp","POST",{email:em, code:cd})
      .then(res=>{
        try { sessionStorage.setItem("otp_token", res.otp); } catch(_){}
        window.location.href = "/login.html";
      })
      .catch(e=> say("otpMsg", e.message||"verify_failed"));
  }

  // Gate logic on first load:
  (function init(){
    // If no JWT yet, show OTP gate immediately
    const jwt = localStorage.getItem("jwt");
    if(!jwt){ showGate(); }
  })();
</script>
</body>
</html>
