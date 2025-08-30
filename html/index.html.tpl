<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>EC2 Dashboard</title>
<style>
  :root{
    --bg:#0b1220; --card:#111827; --ink:#e5e7eb; --muted:#9aa3b2; --line:#1f2937; --pill:#0f172a;
    --green:#4ade80;  --green-d:#22c55e; --red:#f87171; --red-d:#ef4444; --blue:#93c5fd; --blue-d:#3b82f6;
  }
  body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;margin:0;background:var(--bg);color:var(--ink)}
  .wrap{max-width:1100px;margin:0 auto;padding:28px;position:relative}
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
  dialog{border:none;border-radius:16px;background:#0f172a;color:var(--ink);box-shadow:0 30px 90px rgba(0,0,0,.45);width:min(820px,92vw)}
  .right{display:flex;gap:10px}
  .btn{cursor:pointer;font-weight:700;box-shadow:0 2px 0 rgba(0,0,0,.25)}
  .btn:active{transform:translateY(1px)}
  .btn-green{background:var(--green);border-color:var(--green-d);color:#0b1220}
  .btn-green:hover{background:var(--green-d);border-color:var(--green-d);color:#fff}
  .btn-red{background:var(--red);border-color:var(--red-d);color:#0b1220}
  .btn-red:hover{background:var(--red-d);border-color:var(--red-d);color:#fff}
  .btn-gray{background:var(--blue);border-color:var(--blue-d);color:#0b1220}
  .btn-gray:hover{background:var(--blue-d);border-color:var(--blue-d);color:#fff}
  .btn[disabled]{opacity:.5;cursor:not-allowed;box-shadow:none}
  #toasts{position:fixed;top:14px;right:14px;display:flex;flex-direction:column;gap:8px;z-index:50}
  .toast{background:#0f172a;border:1px solid var(--line);padding:10px 14px;border-radius:12px;box-shadow:0 8px 24px rgba(0,0,0,.45)}
  /* user chip */
  #userbar{position:absolute;top:20px;right:24px;display:flex;gap:8px;align-items:center}
  #userchip{border:1px solid var(--line);background:#0f172a;border-radius:999px;padding:6px 10px}
  #signinout{margin-left:6px}
  .subtle{font-size:12px;color:#9aa3b2}
  .grid2{display:grid;grid-template-columns:1fr 1fr;gap:10px}
  .kvs{font-size:14px;color:#cbd5e1}
</style>
</head>
<body>
<div class="wrap">
  <h2>EC2 Dashboard</h2>
  <div id="userbar" style="display:none">
    <span id="userchip"></span>
    <button class="btn btn-gray" id="signinout">Sign out</button>
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
    <div class="row">
      <input id="svcFilter" placeholder="Type to filter (for SVC/WEB)"/>
      <button class="btn btn-gray" id="btnSvcRefresh">Refresh</button>
      <button class="btn btn-gray" id="btnIIS" data-iis>IIS Reset</button>
      <button class="btn btn-gray" id="btnSvcClose">Close</button>
    </div>
    <div id="svcDiag" class="subtle" style="margin-top:8px"></div>
    <div id="svcSqlInfo" class="card" style="display:none;margin-top:12px"></div>
    <div id="svcList" style="margin-top:12px"></div>
  </div>
</dialog>

<div id="toasts"></div>

<script>
(function(){
  var API = "${api_base_url}";
  var ENV_NAMES = "${env_names}".split(",").filter(Boolean);

  var TOKEN = localStorage.getItem("token") || null;
  var USER  = JSON.parse(localStorage.getItem("user") || "null");
  var CURRENT_ENV = localStorage.getItem("current_env") || null;
  var SVC_CTX = { id:null, name:null };
  var READ_ONLY = (USER && USER.role === "read");

  function el(id){ return document.getElementById(id); }
  function msg(id, t){ el(id).textContent = t; }
  function toast(t){ var d=document.createElement('div'); d.className='toast'; d.textContent=t; el('toasts').appendChild(d); setTimeout(function(){ d.remove(); }, 4500); }
  function auth(){ return TOKEN ? {"Authorization":"Bearer "+TOKEN} : {}; }
  function merge(a,b){ var o={}; for(var k in a)o[k]=a[k]; for(var k2 in b)o[k2]=b[k2]; return o; }
  Object.prototype.with = function(obj){ return merge(this, obj); };

  function showUserBar(){
    if(!USER){ el("userbar").style.display="none"; return; }
    el("userbar").style.display="flex";
    el("userchip").innerHTML = USER.name + ' <span class="subtle">('+(USER.email||USER.username)+')</span> <span class="pill">'+USER.role+'</span>';
  }
  function signout(){
    localStorage.removeItem("token");
    localStorage.removeItem("user");
    TOKEN=null; USER=null; READ_ONLY=true;
    location.reload();
  }

  function requestOtp(){
    var email = el("email").value.trim();
    fetch(API + "/request-otp", {method:"POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify({email:email})})
      .then(r=>r.json().then(j=>({ok:r.ok, j})))
      .then(res=>{ msg("msg1", res.ok ? "OTP sent. Check your email." : (res.j.error || "Failed")); });
  }
  function verifyOtp(){
    var email = el("email").value.trim();
    var code  = el("otp").value.trim();
    fetch(API + "/verify-otp", {method:"POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify({email:email, code:code})})
      .then(r=>r.json().then(j=>({ok:r.ok, j})))
      .then(res=>{
        if(res.ok){ el("step2").style.display="block"; msg("msg1","OTP verified. Proceed to login."); }
        else { msg("msg1", res.j.error || "Failed"); }
      });
  }
  function login(){
    var username = el("username").value.trim();
    var password = el("password").value.trim();
    fetch(API + "/login", {method:"POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify({username:username,password:password})})
      .then(r=>r.json().then(j=>({ok:r.ok, j})))
      .then(res=>{
        if(res.ok){
          TOKEN = res.j.token; localStorage.setItem("token", TOKEN);
          USER = res.j.user || null; if(USER) localStorage.setItem("user", JSON.stringify(USER));
          READ_ONLY = (USER && USER.role === "read");
          showDash(); loadMe().then(loadDashboard);
        } else { msg("msg2", res.j.error || "Login failed"); }
      });
  }
  function loadMe(){
    if(!TOKEN) return Promise.resolve();
    return fetch(API + "/me", {headers: auth()})
      .then(r=>r.json())
      .then(j=>{
        if(j.user){
          USER = j.user; localStorage.setItem("user", JSON.stringify(USER));
          READ_ONLY = (USER.role === "read");
          showUserBar();
        }
      }).catch(()=>{});
  }
  function showDash(){
    var s1=el("step1"), s2=el("step2");
    if(s1) s1.style.display="none";
    if(s2) s2.style.display="none";
    el("dash").style.display="block";
    showUserBar();
  }

  function loadDashboard(){
    fetch(API + "/instances", {headers: auth()})
      .then(r=>r.json().then(j=>({ok:r.ok, j})))
      .then(res=>{
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
    var defaultEnv = CURRENT_ENV && ENV_NAMES.includes(CURRENT_ENV) ? CURRENT_ENV : (ENV_NAMES[0] || null);
    ENV_NAMES.forEach(function(e){
      var t = document.createElement("div");
      t.className = "tab" + (e===defaultEnv ? " active" : "");
      t.textContent = e;
      t.addEventListener("click", function(){
        Array.prototype.forEach.call(tabs.children, function(c){ c.classList.remove("active"); });
        t.classList.add("active");
        CURRENT_ENV = e; localStorage.setItem("current_env", e);
        renderEnvPanel(envs, e);
      });
      tabs.appendChild(t);
    });
    CURRENT_ENV = defaultEnv; if(CURRENT_ENV) localStorage.setItem("current_env", CURRENT_ENV);
    if (CURRENT_ENV) renderEnvPanel(envs, CURRENT_ENV);
  }

  function isWebOrSvc(name){ var n=name.toLowerCase(); return n.indexOf("svc")>-1 || n.indexOf("web")>-1; }

  function renderEnvPanel(envs, env){
    var p = el("env-panels");
    var data = envs[env];
    p.innerHTML = "";

    ["DM","EA"].forEach(function(blk){
      var blockName = blk==="DM" ? "Dream Mapper" : "Encore Anywhere";
      var card = document.createElement("div"); card.className="card";

      var head = document.createElement("div"); head.style.display="flex"; head.style.justifyContent="space-between"; head.style.alignItems="center";
      var h3 = document.createElement("h3"); h3.textContent = blockName; head.appendChild(h3);
      var actions = document.createElement("div"); actions.className="right";
      var bStartAll = document.createElement("button"); bStartAll.className="btn btn-green"; bStartAll.textContent="Start All"; bStartAll.disabled = READ_ONLY;
      bStartAll.addEventListener("click", function(){ groupAction(env, blk, "start"); });
      var bStopAll = document.createElement("button"); bStopAll.className="btn btn-red"; bStopAll.textContent="Stop All"; bStopAll.disabled = READ_ONLY;
      bStopAll.addEventListener("click", function(){ groupAction(env, blk, "stop"); });
      actions.appendChild(bStartAll); actions.appendChild(bStopAll);
      head.appendChild(actions);

      var list = document.createElement("div");

      card.appendChild(head);
      card.appendChild(list);
      p.appendChild(card);

      (data[blk] || []).forEach(function(inst){
        var row = document.createElement("div"); row.className="inst";

        var left = document.createElement("div");
        var strong = document.createElement("strong"); strong.textContent = inst.name;
        var spanId = document.createElement("span"); spanId.className="muted"; spanId.textContent = " (" + inst.id + ")";
        left.appendChild(strong); left.appendChild(document.createTextNode(" ")); left.appendChild(spanId);

        var right = document.createElement("div"); right.className="right";
        var status = document.createElement("span"); status.className="status " + inst.state; status.textContent = inst.state;

        var bToggle = document.createElement("button");
        if(inst.state === "running"){
          bToggle.className="btn btn-red"; bToggle.textContent="Stop"; bToggle.disabled = READ_ONLY;
          bToggle.addEventListener("click", function(){ act(inst.id, "stop", inst.name); });
        } else {
          bToggle.className="btn btn-green"; bToggle.textContent="Start"; bToggle.disabled = READ_ONLY;
          bToggle.addEventListener("click", function(){ act(inst.id, "start", inst.name); });
        }

        var bSvc = document.createElement("button"); bSvc.className="btn btn-gray"; bSvc.textContent="Services";
        bSvc.addEventListener("click", function(){ openServices(inst.id, inst.name); });

        right.appendChild(status); right.appendChild(bToggle); right.appendChild(bSvc);
        row.appendChild(left); row.appendChild(right);
        list.appendChild(row);
      });
    });
  }

  function act(id, action, name){
    if(READ_ONLY){ toast("Read-only: action not permitted"); return; }
    toast((action==="start"?"Starting":"Stopping") + ": " + name);
    fetch(API + "/instance-action", {method:"POST", headers:{"Content-Type":"application/json"}.with(auth()), body: JSON.stringify({id:id, action:action})})
      .then(()=> pollUntilStable());
  }

  function groupAction(env, block, action){
    if(READ_ONLY){ toast("Read-only: action not permitted"); return; }
    toast((action==="start"?"Starting":"Stopping") + " ALL in " + env + " / " + block);
    fetch(API + "/instance-action", {method:"POST", headers:{"Content-Type":"application/json"}.with(auth()), body: JSON.stringify({env:env, block:block, action:action})})
      .then(()=> pollUntilStable(60));
  }

  var pollTimer=null;
  function pollUntilStable(maxSecs){
    if(typeof maxSecs!=="number") maxSecs = 45;
    if(pollTimer) clearInterval(pollTimer);
    var start=Date.now();
    pollTimer=setInterval(function(){
      loadDashboard();
      if((Date.now()-start)/1000 > maxSecs){ clearInterval(pollTimer); }
    }, 3000);
  }

  function openServices(id, name){
    SVC_CTX.id = id; SVC_CTX.name = name;
    el("svcInstName").textContent = name;
    el("svcDiag").textContent = "";
    var n = (name||"").toLowerCase();

    // IIS Reset only for svc/web
    var iisBtn = el("btnIIS");
    if(iisBtn){
      iisBtn.style.display = (n.includes("svc") || n.includes("web")) ? "inline-block" : "none";
      iisBtn.disabled = READ_ONLY;
    }

    // textbox only for svc/web
    el("svcFilter").style.display = (n.includes("svc") || n.includes("web")) ? "inline-block" : "none";

    el("svcSqlInfo").style.display = "none";
    el("svcSqlInfo").innerHTML = "";
    el("svcList").innerHTML = "";

    el("svcDlg").showModal();

    // first, do a quick SSM ping to surface errors
    fetch(API + "/ssm-ping", {method:"POST", headers:{"Content-Type":"application/json"}.with(auth()), body: JSON.stringify({id:id})})
      .then(r=>r.json()).then(j=>{
        if(j.error){ el("svcDiag").textContent = "SSM error: " + j.error; }
        else if(j.cmdStatus !== "Success"){ el("svcDiag").textContent = "SSM command status: " + j.cmdStatus + (j.stderr?(" | "+j.stderr):""); }
        else { el("svcDiag").textContent = "SSM OK"; }
      }).catch(()=>{ el("svcDiag").textContent = "SSM diag failed"; });

    // Auto-list SQL/Redis without textbox; default otherwise
    if(n.includes("sql")){
      fetch(API + "/services", {method:"POST", headers:{"Content-Type":"application/json"}.with(auth()), body: JSON.stringify({id:id, mode:"sqlinfo"})})
        .then(r=>r.json())
        .then(j=>{
          if(j.error){ toast("Error: "+j.error); return; }
          // SQL box (OS + SQL versions)
          var box = '<div class="grid2 kvs">';
          var os = j.os || {};
          box += '<div><strong>OS</strong><br/>'+(os.Caption||"?")+'<br/>Version '+(os.Version||"?")+' (Build '+(os.BuildNumber||"?")+')</div>';
          var sqls = j.sql||[];
          var sqlHtml = sqls.length ? sqls.map(function(s){return (s.Instance||"?")+": "+(s.Version||"?")+" ("+(s.PatchLevel||"?")+")";}).join("<br/>") : "No SQL version info";
          box += '<div><strong>SQL</strong><br/>'+sqlHtml+'</div>';
          box += '</div>';
          el("svcSqlInfo").innerHTML = box;
          el("svcSqlInfo").style.display = "block";

          // services list (SQL Server + Agent)
          var list = el("svcList"); list.innerHTML = "";
          (j.services||[]).forEach(function(s){
            addSvcRow(list, s.Name || s.name, s.Status || s.status);
          });
          if(!j.services || !j.services.length){
            ["MSSQLSERVER","SQLSERVERAGENT"].forEach(function(name){ addSvcRow(list, name, "unknown"); });
          }
        });
    } else if(n.includes("redis")){
      var list = el("svcList"); list.innerHTML = "";
      ["Redis"].forEach(function(name){ addSvcRow(list, name, "unknown"); });
    } else {
      loadServices(); // default (WEB/SVC)
    }
  }
  function closeSvc(){ el("svcDlg").close(); }

  function addSvcRow(list, name, status){
    var d = document.createElement("div"); d.className="inst";
    var left = document.createElement("div");
    left.innerHTML = name + ' <span class="pill">' + (status||"") + '</span>';
    var right = document.createElement("div"); right.className="right";
    var bStart = document.createElement("button"); bStart.className="btn btn-green"; bStart.textContent="Start"; bStart.disabled = READ_ONLY;
    bStart.addEventListener("click", function(){ svc(name, "start"); });
    var bStop  = document.createElement("button"); bStop.className="btn btn-red"; bStop.textContent="Stop"; bStop.disabled = READ_ONLY;
    bStop.addEventListener("click", function(){ svc(name, "stop"); });
    right.appendChild(bStart); right.appendChild(bStop);
    d.appendChild(left); d.appendChild(right);
    list.appendChild(d);
  }

  function loadServices(){
    var pattern = el("svcFilter").value.trim();
    fetch(API + "/services", {method:"POST", headers:merge({"Content-Type":"application/json"}, auth()), body: JSON.stringify({id:SVC_CTX.id, mode:"list", pattern:pattern})})
      .then(r=>r.json())
      .then(j=>{
        if(j.error){ toast(j.error); }
        var list = el("svcList"); list.innerHTML = "";
        (j.services||[]).forEach(function(s){
          var name = s.Name || s.name;
          var status = s.Status || s.status;
          addSvcRow(list, name, status);
        });
      });
  }

  function svc(name, action){
    if(READ_ONLY){ toast("Read-only: action not permitted"); return; }
    toast((action==="start"?"Starting":"Stopping") + " service: " + name);
    fetch(API + "/services", {method:"POST", headers:merge({"Content-Type":"application/json"}, auth()), body: JSON.stringify({id:SVC_CTX.id, service:name, mode:action})})
      .then(r=>r.json())
      .then(j=>{
        if(j.error){ toast(j.error); return; }
        setTimeout(loadServices, 1200);
      });
  }
  function iisReset(){
    if(READ_ONLY){ toast("Read-only: action not permitted"); return; }
    toast("Performing IIS Reset...");
    fetch(API + "/services", {method:"POST", headers:merge({"Content-Type":"application/json"}, auth()), body: JSON.stringify({id:SVC_CTX.id, mode:"iisreset"})})
      .then(r=>r.json().then(j=>({ok:r.ok, j})))
      .then(function(res){
        if(res.ok && !res.j.error) toast("IIS Reset completed on " + SVC_CTX.name);
        else toast("IIS Reset failed: " + ((res.j && res.j.error) || "Unknown error"));
      })
      .catch(err => toast("IIS Reset request failed: " + err));
  }

  function wireEnter(id, fn){
    var e=el(id); if(!e) return;
    e.addEventListener("keydown", function(ev){
      if(ev.key==="Enter") fn();
    });
  }

  // events
  el("btnReqOtp").addEventListener("click", requestOtp);
  el("btnVerifyOtp").addEventListener("click", verifyOtp);
  el("btnLogin").addEventListener("click", login);
  el("btnSvcRefresh").addEventListener("click", loadServices);
  el("btnSvcClose").addEventListener("click", closeSvc);
  el("btnIIS").addEventListener("click", iisReset);
  el("signinout").addEventListener("click", signout);

  wireEnter("email", requestOtp);
  wireEnter("otp", verifyOtp);
  wireEnter("username", login);
  wireEnter("password", login);

  // boot
  window.addEventListener("load", function(){
    if(TOKEN){
      showDash();
      loadMe().then(loadDashboard);
    }
  });
})();
</script>
</body>
</html>
