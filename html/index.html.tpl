<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>EC2 Dashboard</title>
<style>
  :root{
    --bg:#0b1220; --card:#111827; --ink:#e5e7eb; --muted:#9aa3b2; --line:#1f2937; --pill:#0f172a;
    --green:#4ade80; --green-d:#22c55e; --red:#f87171; --red-d:#ef4444; --blue:#93c5fd; --blue-d:#3b82f6;
  }
  body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;margin:0;background:var(--bg);color:var(--ink)}
  .wrap{max-width:1100px;margin:0 auto;padding:28px}
  .card{background:var(--card);border:1px solid var(--line);border-radius:18px;padding:18px;margin:14px 0;box-shadow:0 20px 50px rgba(0,0,0,.25)}
  input,button,select{border-radius:12px;border:1px solid var(--line);background:#0f172a;color:var(--ink);padding:10px 12px}
  input{min-width:220px}
  .row{display:flex;gap:12px;flex-wrap:wrap}
  .col{flex:1}
  .tab{padding:10px 14px;border:1px solid var(--line);border-bottom:none;border-radius:12px 12px 0 0;background:#0f172a;margin-right:6px;cursor:pointer;color:#cbd5e1;font-weight:600}
  .tab.active{background:#172033;border-color:#263244}
  .inst{display:flex;align-items:center;justify-content:space-between;border:1px solid var(--line);border-radius:12px;padding:10px;margin:8px 0;background:#0f172a}
  .status.running{color:#86efac;font-weight:700} .status.stopped{color:#fda4af;font-weight:700} .status.terminated{color:#fbbf24;font-weight:700}
  .muted{color:var(--muted)}
  .pill{padding:3px 10px;border-radius:999px;background:var(--pill);border:1px solid var(--line);margin-right:6px;font-weight:600}
  dialog{border:none;border-radius:16px;background:#0f172a;color:var(--ink);box-shadow:0 30px 90px rgba(0,0,0,.45);width:min(760px,92vw)}
  .right{display:flex;gap:10px}
  .btn{cursor:pointer;font-weight:700;box-shadow:0 2px 0 rgba(0,0,0,.25)} .btn:active{transform:translateY(1px)}
  .btn-green{background:var(--green);border-color:var(--green-d);color:#0b1220} .btn-green:hover{background:var(--green-d);color:#fff}
  .btn-red{background:var(--red);border-color:var(--red-d);color:#0b1220} .btn-red:hover{background:var(--red-d);color:#fff}
  .btn-gray{background:var(--blue);border-color:var(--blue-d);color:#0b1220} .btn-gray:hover{background:var(--blue-d);color:#fff}
  #toasts{position:fixed;top:14px;right:14px;display:flex;flex-direction:column;gap:8px;z-index:50}
  .toast{background:#0f172a;border:1px solid var(--line);padding:10px 14px;border-radius:12px;box-shadow:0 8px 24px rgba(0,0,0,.45)}
  #userBar{position:fixed;top:12px;right:12px;display:flex;gap:8px;align-items:center}
</style>
</head>
<body>
<div class="wrap">
  <h2>EC2 Dashboard</h2>

  <!-- STEP 1: Email + OTP -->
  <div id="step1" class="card">
    <h3>Step 1: Email OTP (allowed domain: <span class="pill">@${allowed_email_domain}</span>)</h3>
    <div class="row">
      <div class="col"><input id="email" placeholder="you@${allowed_email_domain}" style="width:100%"/></div>
      <div><button class="btn btn-gray" id="btnReqOtp">Request OTP</button></div>
    </div>
    <div class="row">
      <div class="col"><input id="otp" placeholder="Enter 6-digit OTP" style="width:100%"/></div>
      <div><button class="btn btn-gray" id="btnVerifyOtp">Verify OTP</button></div>
    </div>
    <div id="msg1" class="muted"></div>
  </div>

  <!-- STEP 2: Username/Password -->
  <div id="step2" class="card" style="display:none">
    <h3>Step 2: Login</h3>
    <div class="row">
      <input id="username" placeholder="Username"/>
      <input id="password" type="password" placeholder="Password"/>
      <button class="btn btn-gray" id="btnLogin">Login</button>
    </div>
    <div id="msg2" class="muted"></div>
  </div>

  <!-- STEP 3: Dashboard -->
  <div id="dash" style="display:none">
    <div class="card">
      <div id="summary"></div>
    </div>
    <div class="row" id="env-tabs"></div>
    <div id="env-panels"></div>
  </div>
</div>

<!-- Services dialog -->
<dialog id="svcDlg">
  <div style="padding:16px">
    <h3>Services on <span id="svcInstName"></span></h3>
    <div class="row">
      <input id="svcFilter" placeholder="Type to filter (for SVC/WEB)"/>
      <button class="btn btn-gray" id="btnSvcRefresh">Refresh</button>
      <button class="btn btn-gray" id="btnIIS" data-iis>IIS Reset</button>
      <button class="btn btn-gray" id="btnPing">SSM Ping</button>
      <button class="btn btn-gray" id="btnSvcClose">Close</button>
    </div>
    <div id="svcList" style="margin-top:12px"></div>
    <div id="sqlInfo" class="muted" style="margin-top:8px"></div>
  </div>
</dialog>

<div id="userBar" style="display:none"></div>
<div id="toasts"></div>

<script>
(function(){
  var API = "${api_base_url}";
  var ENV_NAMES = "${env_names}".split(",").filter(Boolean);

  var TOKEN = localStorage.getItem("token") || null;
  var USER  = JSON.parse(localStorage.getItem("user") || "null");
  var READONLY = USER ? (USER.role !== "admin") : true;
  var CURRENT_ENV = localStorage.getItem("current_env") || null;
  var SVC_CTX = { id:null, name:null };

  function el(id){ return document.getElementById(id); }
  function toast(t){ var d=document.createElement('div'); d.className='toast'; d.textContent=t; el('toasts').appendChild(d); setTimeout(function(){ d.remove(); }, 5000); }
  function auth(){ return TOKEN ? {"Authorization":"Bearer "+TOKEN} : {}; }
  function merge(a,b){ var o={}; for(var k in a)o[k]=a[k]; for(var k2 in b)o[k2]=b[k2]; return o; }

  function setUserBar(){
    var bar = document.getElementById("userBar");
    if(!USER){ bar.style.display="none"; return; }
    bar.style.display="flex";
    bar.innerHTML = '';
    var chip = document.createElement("div"); chip.className="pill"; chip.textContent = (USER.name || USER.username) + " · " + USER.role;
    var btn  = document.createElement("button"); btn.className="btn btn-gray"; btn.textContent="Sign out";
    btn.onclick = function(){ localStorage.removeItem("token"); localStorage.removeItem("user"); TOKEN=null; USER=null; READONLY=true; location.reload(); };
    bar.appendChild(chip); bar.appendChild(btn);
  }

  // --- auth/otp/login ---
  function requestOtp(){
    fetch(API + "/request-otp", {method:"POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify({email:el("email").value.trim()})})
      .then(r => r.json().then(j => ({ok:r.ok, j}))).then(res => { el("msg1").textContent = res.ok ? "OTP sent." : (res.j.error || "Failed"); });
  }
  function verifyOtp(){
    fetch(API + "/verify-otp", {method:"POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify({email:el("email").value.trim(), code:el("otp").value.trim()})})
      .then(r => r.json().then(j => ({ok:r.ok, j}))).then(res => { if(res.ok){ el("step2").style.display="block"; toast("OTP verified. Login to continue."); } else { toast(res.j.error||"Failed"); }});
  }
  function login(){
    fetch(API + "/login", {method:"POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify({username:el("username").value.trim(),password:el("password").value.trim()})})
      .then(r => r.json().then(j => ({ok:r.ok, j}))).then(res => {
        if(res.ok){
          TOKEN = res.j.token; USER = res.j.user; READONLY = USER ? (USER.role !== "admin") : true;
          localStorage.setItem("token", TOKEN); localStorage.setItem("user", JSON.stringify(USER||{}));
          showDash(); setUserBar(); loadDashboard();
        } else { el("msg2").textContent = res.j.error || "Login failed"; }
      });
  }
  function showDash(){ el("step1").style.display="none"; el("step2").style.display="none"; el("dash").style.display="block"; }

  // --- dashboard ---
  function loadDashboard(){
    fetch(API + "/instances", {headers: auth()})
    .then(r => r.json().then(j => ({ok:r.ok, j})))
    .then(res => {
      if(!res.ok){ toast(res.j.error || "Auth failed"); return; }
      el("summary").innerHTML =
        '<span class="pill">Total: ' + res.j.summary.total + '</span>' +
        '<span class="pill">Running: ' + res.j.summary.running + '</span>' +
        '<span class="pill">Stopped: ' + res.j.summary.stopped + '</span>' +
        '<button class="btn btn-gray" style="float:right" id="btnRefresh">Refresh</button>';
      el("btnRefresh").onclick = loadDashboard;
      renderEnvTabs(res.j.envs);
    });
  }

  function renderEnvTabs(envs){
    var tabs = el("env-tabs"); tabs.innerHTML = "";
    ENV_NAMES.forEach(function(e){
      var t = document.createElement("div");
      var active = (!CURRENT_ENV && ENV_NAMES[0]===e) || (CURRENT_ENV===e);
      t.className = "tab" + (active ? " active" : "");
      t.textContent = e;
      t.addEventListener("click", function(){
        Array.prototype.forEach.call(tabs.children, c => c.classList.remove("active"));
        t.classList.add("active"); CURRENT_ENV = e; localStorage.setItem("current_env", e);
        renderEnvPanel(envs, e);
      });
      tabs.appendChild(t);
    });
    if(!CURRENT_ENV) CURRENT_ENV = ENV_NAMES[0];
    renderEnvPanel(envs, CURRENT_ENV);
  }

  function renderEnvPanel(envs, env){
    var p = el("env-panels"); p.innerHTML = ""; var data = envs[env] || {DM:[], EA:[]};
    ["DM","EA"].forEach(function(blk){
      var blockName = blk==="DM" ? "Dream Mapper" : "Encore Anywhere";
      var card = document.createElement("div"); card.className="card";
      var head = document.createElement("div"); head.style.display="flex"; head.style.justifyContent="space-between"; head.style.alignItems="center";
      var h3 = document.createElement("h3"); h3.textContent = blockName; head.appendChild(h3);
      var actions = document.createElement("div"); actions.className="right";
      var bStartAll = document.createElement("button"); bStartAll.className="btn btn-green"; bStartAll.textContent="Start All";
      var bStopAll  = document.createElement("button");  bStopAll.className="btn btn-red";   bStopAll.textContent="Stop All";
      bStartAll.onclick = function(){ if(READONLY) return toast("View-only user"); groupAction(env, blk, "start"); };
      bStopAll.onclick  = function(){ if(READONLY) return toast("View-only user"); groupAction(env, blk, "stop"); };
      if(READONLY){ bStartAll.disabled=true; bStopAll.disabled=true; bStartAll.title=bStopAll.title="View-only user"; }
      actions.appendChild(bStartAll); actions.appendChild(bStopAll); head.appendChild(actions);
      var list = document.createElement("div");
      card.appendChild(head); card.appendChild(list); p.appendChild(card);

      (data[blk] || []).forEach(function(inst){
        var row = document.createElement("div"); row.className="inst";
        var left = document.createElement("div");
        var strong = document.createElement("strong"); strong.textContent = inst.name;
        var spanId = document.createElement("span"); spanId.className="muted"; spanId.textContent = " (" + inst.id + ")";
        left.appendChild(strong); left.appendChild(document.createTextNode(" ")); left.appendChild(spanId);

        var right = document.createElement("div"); right.className="right";
        var status = document.createElement("span"); status.className="status " + inst.state; status.textContent = inst.state;

        var bToggle = document.createElement("button");
        if(inst.state === "running"){ bToggle.className="btn btn-red"; bToggle.textContent="Stop"; bToggle.onclick = function(){ if(READONLY) return toast("View-only user"); act(inst.id,"stop",inst.name); }; }
        else { bToggle.className="btn btn-green"; bToggle.textContent="Start"; bToggle.onclick = function(){ if(READONLY) return toast("View-only user"); act(inst.id,"start",inst.name); }; }
        if(READONLY){ bToggle.disabled=true; bToggle.title="View-only user"; }

        var bSvc = document.createElement("button"); bSvc.className="btn btn-gray"; bSvc.textContent="Services";
        bSvc.onclick = function(){ openServices(inst.id, inst.name); };

        right.appendChild(status); right.appendChild(bToggle); right.appendChild(bSvc);
        row.appendChild(left); row.appendChild(right); list.appendChild(row);
      });
    });
  }

  function act(id, action, name){
    toast((action==="start"?"Starting":"Stopping") + ": " + name);
    fetch(API + "/instance-action", {method:"POST", headers:merge({"Content-Type":"application/json"}, auth()), body: JSON.stringify({id:id, action:action})})
      .then(r => r.json().then(j => ({ok:r.ok, j})))
      .then(res => { if(!res.ok) toast(res.j.error||"Failed"); pollUntilStable(); });
  }
  function groupAction(env, block, action){
    toast((action==="start"?"Starting":"Stopping") + " ALL in " + env + " / " + block);
    // Optional: back-end can implement; for now just refresh loop
    pollUntilStable(60);
  }
  var pollTimer=null;
  function pollUntilStable(maxSecs){ if(typeof maxSecs!=="number") maxSecs = 45; if(pollTimer) clearInterval(pollTimer);
    var start=Date.now(); pollTimer=setInterval(function(){ loadDashboard(); if((Date.now()-start)/1000 > maxSecs){ clearInterval(pollTimer); } }, 3000); }

  // --- services modal ---
  function isWebOrSvc(n){ n=n.toLowerCase(); return n.includes("svc") || n.includes("web"); }

  function openServices(id, name){
    SVC_CTX.id = id; SVC_CTX.name=name;
    el("svcInstName").textContent = name;
    el("svcFilter").value="";
    var n = name.toLowerCase();

    // Toggle controls
    var iisBtn = el("btnIIS");
    var pingBtn = el("btnPing");
    if(iisBtn){ iisBtn.style.display = isWebOrSvc(n) ? "inline-block" : "none"; iisBtn.disabled = READONLY; iisBtn.title = READONLY ? "View-only user" : ""; }
    if(pingBtn){ pingBtn.onclick = ssmPing; }
    el("svcFilter").style.display = isWebOrSvc(n) ? "inline-block" : "none";
    el("sqlInfo").innerHTML = ""; el("svcList").innerHTML="";

    el("svcDlg").showModal();

    if(n.includes("sql")){
      loadSqlInfo();
    } else if(n.includes("redis")){
      el("svcFilter").style.display="none";
      loadServices("redis");
    } else {
      loadServices(); // default list with filter box
    }
  }
  function closeSvc(){ el("svcDlg").close(); }

  function rowForService(name, status){
    var d = document.createElement("div"); d.className="inst";
    var left = document.createElement("div"); left.innerHTML = name + ' <span class="pill">' + (status||"") + '</span>';
    var right = document.createElement("div"); right.className="right";
    var bStart = document.createElement("button"); bStart.className="btn btn-green"; bStart.textContent="Start";
    bStart.onclick = function(){ if(READONLY) return toast("View-only user"); svc(name, "start"); };
    var bStop  = document.createElement("button");  bStop.className="btn btn-red";   bStop.textContent="Stop";
    bStop.onclick = function(){ if(READONLY) return toast("View-only user"); svc(name, "stop"); };
    if(READONLY){ bStart.disabled=true; bStop.disabled=true; bStart.title=bStop.title="View-only user"; }
    right.appendChild(bStart); right.appendChild(bStop);
    d.appendChild(left); d.appendChild(right);
    return d;
  }

  function loadServices(pat){
    var list = el("svcList"); list.innerHTML = "";
    var pattern = (typeof pat === "string") ? pat : el("svcFilter").value.trim();
    fetch(API + "/services", {method:"POST", headers:merge({"Content-Type":"application/json"}, auth()), body: JSON.stringify({id:SVC_CTX.id, mode:"list", pattern:pattern})})
      .then(r => r.json().then(j => ({ok:r.ok, j}))).then(res => {
        if(!res.ok){ toast(res.j.error || "Internal"); return; }
        var arr = res.j.services || [];
        if(!Array.isArray(arr)) arr = [arr];
        if(arr.length===0) list.innerHTML='<div class="muted">No matching services.</div>';
        arr.forEach(function(s){
          var name = s.Name || s.name || "";
          var status = s.Status || s.status || "";
          list.appendChild(rowForService(name, status));
        });
      });
  }

  function loadSqlInfo(){
    var list = el("svcList"); list.innerHTML = "";
    fetch(API + "/services", {method:"POST", headers:merge({"Content-Type":"application/json"}, auth()), body: JSON.stringify({id:SVC_CTX.id, mode:"sqlinfo"})})
      .then(r => r.json().then(j => ({ok:r.ok, j}))).then(res => {
        if(!res.ok){ toast(res.j.error || "Internal"); return; }
        var svcs = res.j.services || []; if(!Array.isArray(svcs)) svcs = [svcs];
        svcs.forEach(function(s){ list.appendChild(rowForService(s.Name || s.name || "", s.Status || s.status || "")); });
        var os = res.j.os || {};
        var sql = res.j.sql || [];
        var html = "";
        if(os.Caption){ html += '<div class="pill">OS: '+os.Caption+' '+(os.Version||'')+' (Build '+(os.BuildNumber||'')+')</div>'; }
        if(sql && sql.length){
          html += '<div style="margin-top:6px">';
          sql.forEach(function(i){ html += '<div class="pill">SQL '+(i.Instance||'')+': '+(i.Version||'')+' ('+(i.PatchLevel||'')+')</div>'; });
          html += '</div>';
        }
        el("sqlInfo").innerHTML = html;
      });
  }

  function svc(name, action){
    fetch(API + "/services", {method:"POST", headers:merge({"Content-Type":"application/json"}, auth()), body: JSON.stringify({id:SVC_CTX.id, service:name, mode:action})})
      .then(r => r.json().then(j => ({ok:r.ok, j}))).then(res => { if(!res.ok){ toast(res.j.error || "Failed"); } setTimeout(function(){ if(SVC_CTX.name.toLowerCase().includes("sql")) loadSqlInfo(); else loadServices(); }, 1200); });
  }
  function iisReset(){
    if(READONLY){ return toast("View-only user"); }
    toast("Performing IIS Reset...");
    fetch(API + "/services", {method:"POST", headers:merge({"Content-Type":"application/json"}, auth()), body: JSON.stringify({id:SVC_CTX.id, mode:"iisreset"})})
      .then(r => r.json().then(j => ({ok:r.ok, j}))).then(res => { if(res.ok){ toast("IIS Reset completed"); } else { toast(res.j.error || "IIS Reset failed"); }});
  }
  function ssmPing(){
    fetch(API + "/ssm-ping", {method:"POST", headers:merge({"Content-Type":"application/json"}, auth()), body: JSON.stringify({id:SVC_CTX.id})})
      .then(r => r.json().then(j => ({ok:r.ok, j}))).then(res => {
        if(res.ok){ toast("Ping: "+res.j.status+" — check console for output"); console.log("SSM PING OUT:", res.j); }
        else { toast(res.j.error || "Ping failed"); }
      });
  }

  // wire buttons
  el("btnReqOtp").onclick = requestOtp; el("btnVerifyOtp").onclick = verifyOtp; el("btnLogin").onclick = login;
  el("btnSvcRefresh").onclick = function(){ if(SVC_CTX.name && SVC_CTX.name.toLowerCase().includes("sql")) loadSqlInfo(); else loadServices(); };
  el("btnSvcClose").onclick = closeSvc; el("btnIIS").onclick = iisReset;

  window.addEventListener("load", function(){
    if(TOKEN){ showDash(); setUserBar(); loadDashboard(); }
  });
})();
</script>
</body>
</html>
