<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>EC2 Dashboard</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  :root{--bg:#0e1624;--panel:#111a2b;--ink:#e7ecf3;--mut:#9aa7b8;--ok:#2ea36d;--bad:#c44e4e;--chip:#18243d;--brand:#7b8cff}
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--ink);font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,"Helvetica Neue",sans-serif}
  .wrap{max-width:1100px;margin:24px auto;padding:0 16px}
  .row{display:flex;gap:10px;flex-wrap:wrap}
  .tile{background:var(--chip);padding:12px 16px;border-radius:14px;font-weight:700;box-shadow:0 0 0 1px #1c2840 inset}
  .tile.big{font-size:22px}
  .tabs .tab{background:var(--chip);padding:8px 14px;border-radius:12px;cursor:pointer}
  .tabs .tab.active{outline:2px solid var(--brand)}
  .box{background:var(--panel);border-radius:14px;padding:12px 14px;margin:12px 0}
  .stack{display:flex;flex-direction:column;gap:10px}
  .rowline{display:flex;align-items:center;gap:10px;justify-content:space-between;background:#0f1a2e;border:1px solid #1c2840;border-radius:12px;padding:10px 12px}
  .btn{padding:6px 12px;border-radius:10px;border:0;background:#203252;color:#e7ecf3;cursor:pointer}
  .btn.ok{background:var(--ok)}
  .btn.bad{background:var(--bad)}
  .btn.small{padding:4px 10px;font-size:12px}
  .chip{padding:6px 10px;background:#1a2742;border-radius:12px;font-size:12px}
  .mut{color:var(--mut);font-size:12px}
  input{background:#0f1a2e;border:1px solid #243355;color:var(--ink);border-radius:10px;padding:8px 10px}
  /* gate (OTP) */
  #gate{position:fixed;inset:0;display:none;align-items:center;justify-content:center;background:rgba(0,0,0,.55);z-index:1000}
  #gate.show{display:flex}
  #gate .card{background:var(--panel);padding:18px;border-radius:16px;max-width:760px;width:100%}
  #gate h3{margin:0 0 12px 0}
  #app.blur{filter:blur(4px);pointer-events:none;user-select:none}
</style>
</head>
<body>
<div class="wrap" id="app">
  <div class="row">
    <div class="tile big" id="tTotal">Total: 0</div>
    <div class="tile big" id="tRun">Running: 0</div>
    <div class="tile big" id="tStop">Stopped: 0</div>
    <div class="chip" id="userBadge" style="margin-left:auto;display:none"></div>
    <button class="btn small" id="btnRefresh" onclick="refresh()" style="display:none">Refresh</button>
  </div>

  <div class="tabs row" id="envTabs"></div>
  <div id="envMount"></div>
</div>

<!-- OTP Gate (email only) -->
<div id="gate" aria-modal="true" role="dialog">
  <div class="card">
    <h3>Verify your email</h3>
    <div class="row" style="gap:8px">
      <input id="otpEmail" placeholder="name@${allowed_email_domain}" style="width:320px">
      <button class="btn" onclick="requestOtp()">Request OTP</button>
    </div>
    <div class="row" style="gap:8px;margin-top:8px">
      <input id="otpCode" placeholder="6-digit code" style="width:140px">
      <button class="btn ok" onclick="verifyOtp()">Verify OTP</button>
    </div>
    <div class="mut" style="margin-top:8px">Allowed domain: ${allowed_email_domain}. After verifying OTP you'll be redirected to the credential page.</div>
    <div id="otpMsg" class="mut" style="margin-top:6px"></div>
  </div>
</div>

<script>
  const API = "${api_base_url}";
  const ENV_NAMES = "${env_names}".split(",");

  function http(path, method, obj, bearer){
    const h = {"content-type":"application/json"};
    if(bearer){ h["authorization"] = "Bearer " + bearer; }
    return fetch(API + path, {method, headers:h, body: obj? JSON.stringify(obj): undefined})
      .then(async r => {
        const data = await r.json().catch(()=> ({}));
        if(!r.ok) throw new Error((data && (data.error||data.message)) || ("http "+r.status));
        return data;
      });
  }
  function $(id){ return document.getElementById(id); }
  function toast(m){ alert(m); }

  function openGate(){ $("gate").classList.add("show"); $("app").classList.add("blur"); }
  function closeGate(){ $("gate").classList.remove("show"); $("app").classList.remove("blur"); }

  function requestOtp(){
    const em = $("otpEmail").value.trim().toLowerCase();
    if(!em) return $("otpMsg").textContent="Enter email";
    http("/request-otp","POST",{email:em})
      .then(()=> { $("otpMsg").textContent="OTP sent. Check your inbox."; })
      .catch(e=> $("otpMsg").textContent = e.message);
  }
  function verifyOtp(){
    const em = $("otpEmail").value.trim().toLowerCase();
    const cd = $("otpCode").value.trim();
    if(!em || !cd) return $("otpMsg").textContent="Enter email and code";
    http("/verify-otp","POST",{email:em, code:cd})
      .then(()=>{
        // store normalized email and push to login page
        localStorage.setItem("otp_email", em);
        window.location.href = "/login.html";
      })
      .catch(e=> $("otpMsg").textContent = e.message);
  }

  function renderUser(){
    const u = localStorage.getItem("user");
    if(u){ const o=JSON.parse(u); $("userBadge").textContent=(o.name||o.username||"")+" • "+(o.role||""); $("userBadge").style.display="inline-block"; $("btnRefresh").style.display="inline-block"; }
    else { $("userBadge").style.display="none"; $("btnRefresh").style.display="none"; }
  }

  function refresh(){
    const jwt = localStorage.getItem("jwt");
    if(!jwt){ openGate(); return; }
    http("/instances","GET",null,jwt).then(data=>{
      $("tTotal").textContent="Total: "+data.summary.total;
      $("tRun").textContent  ="Running: "+data.summary.running;
      $("tStop").textContent ="Stopped: "+data.summary.stopped;
      renderTabs(data.envs);
      closeGate();
    }).catch(()=> openGate());
  }

  function renderTabs(envs){
    const tabs=$("envTabs"); tabs.innerHTML="";
    ENV_NAMES.forEach((e,i)=>{
      const b=document.createElement("div"); b.className="tab"; b.textContent=e;
      b.onclick=()=>{ drawEnv(envs[e]||{DM:[],EA:[]}); setActive(i); };
      tabs.appendChild(b);
    });
    setActive(0); drawEnv(envs[ENV_NAMES[0]]||{DM:[],EA:[]});
    function setActive(idx){ tabs.querySelectorAll(".tab").forEach((n,k)=>n.classList.toggle("active",k===idx)); }
  }

  function drawEnv(env){
    const m=$("envMount"); m.innerHTML="";
    [["Dream Mapper","DM"],["Encore Anywhere","EA"]].forEach(([title,key])=>{
      const box=document.createElement("div"); box.className="box";
      const head=document.createElement("div"); head.textContent=title; head.style.fontWeight="700"; head.style.marginBottom="8px"; box.appendChild(head);
      const wrap=document.createElement("div"); wrap.className="stack";
      (env[key]||[]).forEach(it=>{
        const line=document.createElement("div"); line.className="rowline";
        const left=document.createElement("div"); left.innerHTML="<b>"+it.name+"</b> <span class='mut'>("+it.id+")</span>";
        line.appendChild(left);
        const st=(it.state||"").toLowerCase();
        const bStart=btn("Start","ok",()=> act(it.id,"start")); const bStop=btn("Stop","bad",()=> act(it.id,"stop"));
        if(st==="running"){ bStart.disabled=true; } else { bStop.disabled=true; }
        line.appendChild(bStart); line.appendChild(bStop);
        wrap.appendChild(line);
      });
      box.appendChild(wrap); m.appendChild(box);
    });
  }
  function btn(t,c,fn){ const b=document.createElement("button"); b.textContent=t; b.className="btn small "+c; b.onclick=fn; return b; }
  function act(id,what){ http("/instance-action","POST",{id,action:what}, localStorage.getItem("jwt")).then(()=>setTimeout(refresh,1200)).catch(e=>toast(e.message)); }

  (function init(){
    // remember API for login page to read
    localStorage.setItem("api_base_url", API);
    renderUser();
    if(!localStorage.getItem("jwt")) openGate();
    refresh();
  })();
</script>
</body>
</html>
