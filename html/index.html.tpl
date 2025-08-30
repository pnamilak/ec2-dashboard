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
  .status.running{color:#86efac;font-weight:700}
  .status.stopped{color:#fda4af;font-weight:700}
  .status.terminated{color:#fbbf24;font-weight:700}
  .muted{color:var(--muted)}
  .pill{padding:3px 10px;border-radius:999px;background:var(--pill);border:1px solid var(--line);margin-right:6px;font-weight:600}
  dialog{border:none;border-radius:16px;background:#0f172a;color:var(--ink);box-shadow:0 30px 90px rgba(0,0,0,.45);width:min(780px,92vw)}
  .right{display:flex;gap:10px}
  .btn{cursor:pointer;font-weight:700;box-shadow:0 2px 0 rgba(0,0,0,.25)} .btn:active{transform:translateY(1px)}
  .btn-green{background:var(--green);border-color:var(--green-d);color:#0b1220} .btn-green:hover{background:var(--green-d);border-color:var(--green-d);color:#fff}
  .btn-red{background:var(--red);border-color:var(--red-d);color:#0b1220} .btn-red:hover{background:var(--red-d);border-color:var(--red-d);color:#fff}
  .btn-gray{background:var(--blue);border-color:var(--blue-d);color:#0b1220} .btn-gray:hover{background:var(--blue-d);border-color:var(--blue-d);color:#fff}
  #toasts{position:fixed;top:14px;right:14px;display:flex;flex-direction:column;gap:8px;z-index:50}
  .toast{background:#0f172a;border:1px solid var(--line);padding:10px 14px;border-radius:12px;box-shadow:0 8px 24px rgba(0,0,0,.45)}
  /* top right user chip */
  .topbar{display:flex;align-items:center;justify-content:space-between;margin-bottom:8px}
  .userchip{display:flex;align-items:center;gap:10px}
  .chip{padding:6px 10px;border:1px solid var(--line);border-radius:999px;background:#0f172a;font-weight:600}
  .kv{display:flex;gap:12px;flex-wrap:wrap;margin-top:10px}
  .kv .item{background:#0f172a;border:1px solid var(--line);border-radius:10px;padding:8px 10px}
  .hr{height:1px;background:var(--line);margin:10px 0}
</style>
</head>
<body>
<div class="wrap">
  <div class="topbar">
    <h2>EC2 Dashboard</h2>
    <div class="userchip">
      <span id="userInfo" class="chip" title="Signed in user">not signed in</span>
      <button id="btnSignout" class="btn btn-gray">Sign out</button>
    </div>
  </div>

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

<dialog id="svcDlg">
  <div style="padding:16px">
    <h3>Services on <span id="svcInstName"></span></h3>

    <!-- SQL/OS meta appears here when on SQL boxes -->
    <div id="svcMeta" class="kv" style="display:none"></div>

    <!-- filter row for SVC/WEB only -->
    <div class="row" id="svcFilterRow" style="margin-top:6px;display:none">
      <input id="svcFilter" placeholder="Type to filter (for SVC/WEB)"/>
      <button class="btn btn-gray" id="btnSvcRefresh">Refresh</button>
      <button class="btn btn-gray" id="btnIIS" data-iis style="display:none">IIS Reset</button>
      <button class="btn btn-gray" id="btnSvcClose">Close</button>
    </div>

    <div class="row" id="sqlButtons" style="gap:8px;margin-top:6px;display:none">
      <button class="btn btn-gray" id="btnSqlRefresh">Refresh</button>
      <button class="btn btn-gray" id="btnSvcClose2">Close</button>
    </div>

    <div id="svcList" style="margin-top:12px"></div>
  </div>
</dialog>

<div id="toasts"></div>

<script>
(function(){
  var API = "${api_base_url}";
  var ENV_NAMES = "${env_names}".split(",").filter(Boolean);

  var TOKEN = localStorage.getItem("token") || null;
  var CURRENT_ENV = localStorage.getItem("activeEnv") || null;
  var SVC_CTX = { id:null, name:null, mode:"" };

  function el(id){ return document.getElementById(id); }
  function msg(id, t){ el(id).textContent = t; }
  function toast(t){ var d=document.createElement('div'); d.className='toast'; d.textContent=t; el('toasts').appendChild(d); setTimeout(function(){ d.remove(); }, 4800); }
  function auth(){ return TOKEN ? {"Authorization":"Bearer "+TOKEN} : {}; }
  function merge(a,b){ var o={}; for(var k in a)o[k]=a[k]; for(var k2 in b)o[k2]=b[k2]; return o; }
  Object.prototype.with = function(obj){ return merge(this, obj); };

  // ---- user chip ----
  function parseJwt(t){
    try{ var base=t.split('.')[1]; var json=atob(base.replace(/-/g,'+').replace(/_/g,'/')); return JSON.parse(decodeURIComponent(escape(json))); }
    catch(e){ return {}; }
  }
  function updateUserChip(){
    var info = "not signed in";
    if(TOKEN){
      var j=parseJwt(TOKEN);
      var name = j.name || j.sub || "user";
      var role = j.role || "user";
      info = name + " · " + role;
    }
    el("userInfo").textContent = info;
  }
  function signout(){
    localStorage.removeItem("token");
    TOKEN=null; updateUserChip();
    location.reload();
  }

  // ---- Auth + steps ----
  function requestOtp(){
    var email = el("email").value.trim();
    fetch(API + "/request-otp", {method:"POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify({email:email})})
      .then(r=>r.json().then(j=>({ok:r.ok,j}))).then(res=>{
        msg("msg1", res.ok ? "OTP sent. Check your email." : (res.j.error || "Failed"));
      });
  }
  function verifyOtp(){
    var email = el("email").value.trim();
    var code  = el("otp").value.trim();
    fetch(API + "/verify-otp", {method:"POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify({email:email, code:code})})
      .then(r=>r.json().then(j=>({ok:r.ok,j}))).then(res=>{
        if(res.ok){ el("step2").style.display="block"; msg("msg1","OTP verified. Proceed to login."); }
        else { msg("msg1", res.j.error || "Failed"); }
      });
  }
  function login(){
    var username = el("username").value.trim();
    var password = el("password").value.trim();
    fetch(API + "/login", {method:"POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify({username:username,password:password})})
      .then(r=>r.json().then(j=>({ok:r.ok,j}))).then(res=>{
        if(res.ok){
          TOKEN = res.j.token; localStorage.setItem("token", TOKEN);
          updateUserChip();
          showDash(); loadDashboard();
        }else{ msg("msg2", res.j.error || "Login failed"); }
      });
  }
  function showDash(){ el("step1").style.display="none"; el("step2").style.display="none"; el("dash").style.display="block"; }

  // ---- Dashboard ----
  function loadDashboard(){
    fetch(API + "/instances", {headers: auth()})
      .then(r=>r.json().then(j=>({ok:r.ok,j}))).then(res=>{
        if(!res.ok){ alert(res.j.error || "Auth failed"); return; }
        el("summary").innerHTML =
          '<span class="pill">Total: ' + res.j.summary.total + '</span>' +
          '<span class="pill">Running: ' + res.j.summary.running + '</span>' +
          '<span class="pill">Stopped: ' + res.j.summary.stopped + '</span>' +
          '<button class="btn btn-gray" style="float:right" id="btnRefresh">Refresh</button>';
        el("btnRefresh").addEventListener("click", loadDashboard);
        renderEnvTabs(res.j.envs);
      });
  }

  function renderEnvTabs(envs){
    var tabs = el("env-tabs"); tabs.innerHTML = "";
    ENV_NAMES.forEach(function(e, i){
      var t = document.createElement("div");
      var active = (CURRENT_ENV ? CURRENT_ENV===e : i===0);
      t.className = "tab" + (active ? " active" : "");
      t.textContent = e;
      t.addEventListener("click", function(){
        Array.prototype.forEach.call(tabs.children, function(c){ c.classList.remove("active"); });
        t.classList.add("active");
        CURRENT_ENV = e; localStorage.setItem("activeEnv", e);
        renderEnvPanel(envs, e);
      });
      tabs.appendChild(t);
    });
    if(!CURRENT_ENV){ CURRENT_ENV = ENV_NAMES[0]; }
    renderEnvPanel(envs, CURRENT_ENV);
  }

  function isWebOrSvc(name){ var n=name.toLowerCase(); return n.indexOf("svc")>-1 || n.indexOf("web")>-1; }

  function renderEnvPanel(envs, env){
    var p = el("env-panels"); var data = envs[env]; p.innerHTML = "";
    ["DM","EA"].forEach(function(blk){
      var blockName = blk==="DM" ? "Dream Mapper" : "Encore Anywhere";
      var card = document.createElement("div"); card.className="card";
      var head = document.createElement("div"); head.style.display="flex"; head.style.justifyContent="space-between"; head.style.alignItems="center";
      var h3 = document.createElement("h3"); h3.textContent = blockName; head.appendChild(h3);
      var actions = document.createElement("div"); actions.className="right";
      var bStartAll = document.createElement("button"); bStartAll.className="btn btn-green"; bStartAll.textContent="Start All"; bStartAll.addEventListener("click", function(){ groupAction(env, blk, "start"); });
      var bStopAll = document.createElement("button"); bStopAll.className="btn btn-red"; bStopAll.textContent="Stop All"; bStopAll.addEventListener("click", function(){ groupAction(env, blk, "stop"); });
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
        if(inst.state === "running"){ bToggle.className="btn btn-red"; bToggle.textContent="Stop"; bToggle.addEventListener("click", function(){ act(inst.id, "stop", inst.name); }); }
        else { bToggle.className="btn btn-green"; bToggle.textContent="Start"; bToggle.addEventListener("click", function(){ act(inst.id, "start", inst.name); }); }

        var bSvc = document.createElement("button"); bSvc.className="btn btn-gray"; bSvc.textContent="Services";
        bSvc.addEventListener("click", function(){ openServices(inst.id, inst.name); });

        right.appendChild(status); right.appendChild(bToggle); right.appendChild(bSvc);
        row.appendChild(left); row.appendChild(right); list.appendChild(row);
      });
    });
  }

  function act(id, action, name){
    toast((action==="start"?"Starting":"Stopping") + ": " + name);
    fetch(API + "/instance-action", {method:"POST", headers:{"Content-Type":"application/json"}.with(auth()), body: JSON.stringify({id:id, action:action})})
      .then(function(){ pollUntilStable(); });
  }
  function groupAction(env, block, action){
    toast((action==="start"?"Starting":"Stopping") + " ALL in " + env + " / " + block);
    fetch(API + "/instance-action", {method:"POST", headers:{"Content-Type":"application/json"}.with(auth()), body: JSON.stringify({env:env, block:block, action:action})})
      .then(function(){ pollUntilStable(60); });
  }
  var pollTimer=null;
  function pollUntilStable(maxSecs){ if(typeof maxSecs!=="number") maxSecs = 45; if(pollTimer) clearInterval(pollTimer);
    var start=Date.now();
    pollTimer=setInterval(function(){ loadDashboard(); if((Date.now()-start)/1000 > maxSecs){ clearInterval(pollTimer); } }, 3000);
  }

  // ===========================
  // Services modal (SQL vs SVC/WEB)
  // ===========================
  function openServices(id, name){
    SVC_CTX.id = id; SVC_CTX.name = name;
    el("svcInstName").textContent = name;
    el("svcMeta").style.display = "none"; el("svcMeta").innerHTML = "";
    el("svcList").innerHTML = "";

    var n = name.toLowerCase();
    var isSvcWeb = (n.indexOf("svc")>-1 || n.indexOf("web")>-1);
    var isSql = (n.indexOf("sql")>-1);

    // Show proper controls
    el("svcFilterRow").style.display = isSvcWeb ? "flex" : "none";
    el("btnIIS").style.display = isSvcWeb ? "inline-block" : "none";
    el("sqlButtons").style.display = isSql ? "flex" : "none";

    el("svcDlg").showModal();

    if(isSql){
      SVC_CTX.mode = "sqlinfo";
      fetchSqlInfo();
    }else{
      SVC_CTX.mode = "list";
      loadServices();
    }
  }

  function renderServiceLine(name, status){
    var d = document.createElement("div"); d.className="inst";
    var left = document.createElement("div");
    left.innerHTML = '<strong>'+name+'</strong> <span class="pill">'+status+'</span>';
    var right = document.createElement("div"); right.className="right";
    var bStart = document.createElement("button"); bStart.className="btn btn-green"; bStart.textContent="Start";
    bStart.addEventListener("click", function(){ svc(name, "start"); });
    var bStop  = document.createElement("button"); bStop.className="btn btn-red"; bStop.textContent="Stop";
    bStop.addEventListener("click", function(){ svc(name, "stop"); });
    right.appendChild(bStart); right.appendChild(bStop);
    d.appendChild(left); d.appendChild(right);
    return d;
  }

  function renderSqlInfo(j){
    el("svcList").innerHTML = "";
    // meta: OS + SQL Version(s)
    var meta = el("svcMeta"); meta.innerHTML = "";
    if(j.os){
      var osItem = document.createElement("div"); osItem.className="item";
      osItem.textContent = "OS: " + (j.os.name||"") + " " + (j.os.version||"");
      meta.appendChild(osItem);
    }
    if(Array.isArray(j.sql) && j.sql.length){
      j.sql.forEach(function(s){
        var it=document.createElement("div"); it.className="item";
        it.textContent = "SQL " + (s.Instance||"") + " v" + (s.Version||"");
        meta.appendChild(it);
      });
    }
    meta.style.display = "flex";

    // services (MSSQLSERVER, SQLSERVERAGENT)
    (j.services||[]).forEach(function(svc){
      var nm = svc.Name || svc.name || "";
      var st = svc.Status || svc.status || "";
      el("svcList").appendChild( renderServiceLine(nm, st) );
    });
  }

  function fetchSqlInfo(){
    fetch(API + "/services", {
      method:"POST",
      headers: merge({"Content-Type":"application/json"}, auth()),
      body: JSON.stringify({ id:SVC_CTX.id, mode:"sqlinfo" })
    })
    .then(r=>r.json().then(j=>({ok:r.ok,j}))).then(res=>{
      if(!res.ok){ toast("Error: " + (res.j.error||"Internal")); return; }
      renderSqlInfo(res.j);
    })
    .catch(e=>toast("Request failed: "+e));
  }

  function loadServices(){
    var pattern = (el("svcFilter").value || "").trim();
    fetch(API + "/services", {
      method:"POST",
      headers: merge({"Content-Type":"application/json"}, auth()),
      body: JSON.stringify({ id:SVC_CTX.id, mode:"list", pattern: pattern })
    })
    .then(r=>r.json().then(j=>({ok:r.ok,j}))).then(res=>{
      if(!res.ok){ toast("Error: " + (res.j.error||"Internal")); return; }
      var list = el("svcList"); list.innerHTML = "";
      (res.j.services || []).forEach(function(s){
        list.appendChild( renderServiceLine(s.Name||s.name, s.Status||s.status) );
      });
    })
    .catch(e=>toast("Request failed: "+e));
  }

  function svc(name, action){
    toast((action==="start"?"Starting":"Stopping") + " service: " + name);
    fetch(API + "/services", {
      method:"POST",
      headers: merge({"Content-Type":"application/json"}, auth()),
      body: JSON.stringify({id:SVC_CTX.id, mode:action, service:name})
    }).then(function(){ setTimeout(function(){
      if(SVC_CTX.mode==="sqlinfo") fetchSqlInfo(); else loadServices();
    }, 1200); });
  }

  function iisReset(){
    toast("Performing IIS Reset...");
    fetch(API + "/services", {
      method:"POST",
      headers: merge({"Content-Type":"application/json"}, auth()),
      body: JSON.stringify({id:SVC_CTX.id, mode:"iisreset"})
    })
    .then(r=>r.json().then(j=>({ok:r.ok,j})))
    .then(function(res){
      if(res.ok){ toast("IIS Reset completed on " + SVC_CTX.name); }
      else { toast("IIS Reset failed: " + (res.j.error || "Unknown error")); }
    })
    .catch(err => toast("IIS Reset request failed: " + err));
  }
  function closeSvc(){ el("svcDlg").close(); }

  // wire buttons
  document.getElementById("btnReqOtp").addEventListener("click", requestOtp);
  document.getElementById("btnVerifyOtp").addEventListener("click", verifyOtp);
  document.getElementById("btnLogin").addEventListener("click", login);
  document.getElementById("btnSvcRefresh").addEventListener("click", loadServices);
  document.getElementById("btnSqlRefresh").addEventListener("click", fetchSqlInfo);
  document.getElementById("btnSvcClose").addEventListener("click", closeSvc);
  document.getElementById("btnSvcClose2").addEventListener("click", closeSvc);
  document.getElementById("btnIIS").addEventListener("click", iisReset);
  document.getElementById("btnSignout").addEventListener("click", signout);

  // enter shortcuts
  ["email","otp","username","password"].forEach(function(id){
    var e=el(id); if(!e) return;
    e.addEventListener("keydown", function(ev){ if(ev.key==="Enter"){
      if(id==="email")requestOtp(); else if(id==="otp")verifyOtp(); else login();
    }});
  });

  window.addEventListener("load", function(){
    if(TOKEN){ updateUserChip(); showDash(); loadDashboard(); } else { updateUserChip(); }
  });
})();
</script>
</body>
</html>
