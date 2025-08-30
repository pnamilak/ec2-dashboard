<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>EC2 Dashboard</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <style>
    :root { --bg:#0f172a; --card:#111827; --ink:#e5e7eb; --muted:#9ca3af; --good:#10b981; --bad:#ef4444; --btn:#60a5fa; --chip:#1f2937; }
    html,body{margin:0;height:100%;background:var(--bg);color:var(--ink);font-family:ui-sans-serif,system-ui,Segoe UI,Roboto,Arial}
    .wrap{max-width:1100px;margin:32px auto;padding:0 16px}
    h1{font-size:24px;margin:0 0 10px 0}
    .row{display:flex;gap:10px;align-items:center;justify-content:space-between}
    .kpis{display:flex;gap:8px;flex-wrap:wrap}
    .chip{background:#0b1220;border:1px solid #1e293b;color:#cbd5e1;border-radius:9999px;padding:6px 10px;font-size:12px}
    .pill{background:var(--chip);padding:5px 10px;border-radius:8px;border:1px solid #1f2937}
    button{background:#1e293b;border:1px solid #374151;color:#dbeafe;padding:8px 12px;border-radius:8px;cursor:pointer}
    button:hover{background:#253142}
    button.small{padding:6px 10px;font-size:12px}
    button.ok{background:#064e3b;border-color:#065f46}
    button.danger{background:#3f1d1d;border-color:#7f1d1d}
    button.primary{background:#0c4a6e;border-color:#075985}
    button:disabled{opacity:.5;cursor:not-allowed}
    .section{background:var(--card);border:1px solid #1f2937;border-radius:14px;padding:14px 14px;margin:14px 0}
    .envtabs{display:flex;gap:10px;margin:8px 0 14px 0;flex-wrap:wrap}
    .srv{display:flex;align-items:center;justify-content:space-between;padding:10px 12px;margin:8px 0;background:#0b1220;border:1px solid #1e293b;border-radius:10px}
    .name{font-weight:600}
    .state{font-size:12px;color:#a7f3d0}
    .state.bad{color:#fecaca}
    .group-title{font-weight:700;margin:8px 0 4px 0}
    .modal{position:fixed;inset:0;display:none;align-items:center;justify-content:center;background:rgba(0,0,0,.5)}
    .panel{background:#0b1220;border:1px solid #1f2937;border-radius:16px;max-width:820px;width:92%;padding:16px}
    .grid{display:grid;grid-template-columns:1fr auto auto auto auto;gap:8px}
    .svcrow{display:grid;grid-template-columns:1fr auto auto;gap:8px;align-items:center;padding:8px;border-bottom:1px solid #172036}
    .svcname{font-family:ui-monospace,Menlo,Consolas; font-size:13px}
    .svcok{color:#34d399}
    .svcbad{color:#f87171}
    .muted{color:var(--muted)}
    input,select{background:#0b1220;border:1px solid #1f2937;color:#e5e7eb;border-radius:8px;padding:8px}
    .right{display:flex;gap:10px;align-items:center}
    .badge{background:#111827;border:1px solid #374151;padding:6px 10px;border-radius:999px;font-size:12px}
    .hidden{display:none}
    .note{font-size:12px;color:#cbd5e1}
  </style>
</head>
<body>
<div class="wrap">
  <div class="row">
    <h1>EC2 Dashboard</h1>
    <div class="right">
      <span id="userBadge" class="badge hidden"></span>
      <button id="loginBtn" class="small">Login</button>
      <button id="logoutBtn" class="small hidden">Sign out</button>
      <button id="refreshBtn" class="small">Refresh</button>
    </div>
  </div>

  <div class="kpis">
    <span id="kTotal" class="chip">Total: 0</span>
    <span id="kRun"   class="chip">Running: 0</span>
    <span id="kStop"  class="chip">Stopped: 0</span>
  </div>

  <div class="envtabs" id="envTabs"></div>

  <div id="envContainer"></div>
</div>

<!-- Services Modal -->
<div id="svcModal" class="modal">
  <div class="panel">
    <div class="row" style="margin-bottom:10px">
      <div id="svcTitle" class="group-title">Services</div>
      <div class="right">
        <input id="svcFilter" placeholder="Type to filter (svc/web/sql/agent/ssm/winrm)" style="width:260px" />
        <button id="svcRefresh" class="small">Refresh</button>
        <button id="btnIisReset" class="small">IIS Reset</button>
        <button id="btnSqlInfo" class="small">SQL Info</button>
        <button id="btnSsmPing" class="small">SSM Ping</button>
        <button id="svcClose" class="small">Close</button>
      </div>
    </div>
    <div id="svcBody"></div>
    <div id="svcFooter" class="note"></div>
  </div>
</div>

<!-- Login Modal (username/password + OTP) -->
<div id="loginModal" class="modal">
  <div class="panel" style="max-width:520px">
    <div class="group-title">Sign in</div>
    <div style="display:flex;gap:12px;margin:10px 0 6px 0">
      <button class="small" id="tabPwd">User / Password</button>
      <button class="small" id="tabOtp">Email OTP</button>
      <span class="note">Allowed domain: <b>${allowed_email_domain}</b></span>
    </div>

    <div id="formPwd">
      <div style="margin:6px 0"><input id="inUser" placeholder="username" style="width:100%"></div>
      <div style="margin:6px 0"><input id="inPass" type="password" placeholder="password" style="width:100%"></div>
      <div class="row">
        <span class="note">Tip: give a user the role <code>read</code> for demo-only (start/stop disabled).</span>
        <button id="btnLogin" class="small primary">Login</button>
      </div>
    </div>

    <div id="formOtp" class="hidden">
      <div style="margin:6px 0"><input id="inEmail" placeholder="name@${allowed_email_domain}" style="width:100%"></div>
      <div class="row">
        <button id="btnReqOtp" class="small">Request OTP</button>
        <span id="otpMsg" class="note"></span>
      </div>
      <div style="margin:6px 0"><input id="inCode" placeholder="Enter OTP code" style="width:100%"></div>
      <div class="row">
        <span></span>
        <button id="btnVerifyOtp" class="small primary">Verify</button>
      </div>
    </div>

    <div class="row" style="margin-top:10px">
      <span id="loginMsg" class="note"></span>
      <button id="loginClose" class="small">Close</button>
    </div>
  </div>
</div>

<script>
(function(){
  var API = "${api_base_url}";
  var ENV_NAMES = "${env_names}".split(",").filter(function(x){return x.length>0;});
  var token = localStorage.getItem("token") || "";
  var role  = localStorage.getItem("role")  || "";
  var user  = localStorage.getItem("user")  || "";

  function setBadge(){
    var b = document.getElementById("userBadge");
    var lo = document.getElementById("loginBtn");
    var so = document.getElementById("logoutBtn");
    if(token){
      b.textContent = (user?user:"user") + " • " + (role?role:"");
      b.classList.remove("hidden");
      so.classList.remove("hidden");
      lo.classList.add("hidden");
    }else{
      b.classList.add("hidden");
      so.classList.add("hidden");
      lo.classList.remove("hidden");
    }
  }

  function headers(jwt){
    var h = {"content-type":"application/json"};
    if(jwt){ h["Authorization"] = "Bearer " + jwt; }
    return h;
  }

  function getJSON(url, opt, cb){
    fetch(url, opt).then(function(r){ return r.json().catch(function(){ return {}; }) })
      .then(function(j){ cb(null,j); })
      .catch(function(e){ cb(e); });
  }

  function loadInstances(){
    if(!token){ return; }
    getJSON(API + "/instances", {method:"GET", headers:headers(token)}, function(err, res){
      if(err){ return; }
      if(!res || !res.envs){ return; }
      document.getElementById("kTotal").textContent  = "Total: "   + (res.summary && res.summary.total   || 0);
      document.getElementById("kRun").textContent    = "Running: " + (res.summary && res.summary.running || 0);
      document.getElementById("kStop").textContent   = "Stopped: " + (res.summary && res.summary.stopped || 0);

      var envTabs = document.getElementById("envTabs");
      envTabs.innerHTML = "";
      var envContainer = document.getElementById("envContainer");
      envContainer.innerHTML = "";

      var keys = Object.keys(res.envs);
      keys.forEach(function(k){
        var btn = document.createElement("button");
        btn.className = "small";
        btn.textContent = k;
        btn.onclick = function(){
          var blocks = document.querySelectorAll("[data-env]");
          blocks.forEach(function(el){ el.style.display = el.getAttribute("data-env")==k ? "block" : "none"; });
        };
        envTabs.appendChild(btn);

        var envBlock = document.createElement("div");
        envBlock.setAttribute("data-env", k);
        envBlock.className = "section";
        envBlock.innerHTML = "<div class='group-title'>"+k+"</div>";
        envContainer.appendChild(envBlock);

        ["DM","EA"].forEach(function(blk){
          var list = res.envs[k][blk] || [];
          if(list.length===0){ return; }
          var head = document.createElement("div");
          head.className = "group-title";
          head.textContent = (blk=="DM"?"Dream Mapper":"Encore Anywhere");
          envBlock.appendChild(head);
          list.forEach(function(it){
            var row = document.createElement("div");
            row.className = "srv";
            var left = document.createElement("div");
            left.innerHTML = "<span class='name'>"+it.name+"</span> <span class='muted'>("+it.id+")</span>";
            var st = document.createElement("span");
            st.className = "state" + (it.state=="running"?"":" bad");
            st.textContent = it.state;
            var right = document.createElement("div");
            right.style.display = "flex"; right.style.gap="8px";

            var btnStart = document.createElement("button");
            btnStart.className = "small ok"; btnStart.textContent = "Start";
            btnStart.onclick = function(){ instAction(it.id,"start"); };
            var btnStop  = document.createElement("button");
            btnStop.className = "small danger"; btnStop.textContent = "Stop";
            btnStop.onclick = function(){ instAction(it.id,"stop"); };
            if(role==="read" || role==="readonly"){ btnStart.disabled = true; btnStop.disabled = true; }

            var btnSvc   = document.createElement("button");
            btnSvc.className = "small"; btnSvc.textContent = "Services";
            btnSvc.onclick = function(){ openSvc(it); };

            right.appendChild(st);
            right.appendChild(btnStart);
            right.appendChild(btnStop);
            right.appendChild(btnSvc);
            row.appendChild(left);
            row.appendChild(right);
            envBlock.appendChild(row);
          });
        });
      });

      // show first env
      var first = document.querySelector("[data-env]");
      if(first){ first.style.display = "block"; }
    });
  }

  function instAction(id, action){
    if(!token){ return; }
    if(role==="read" || role==="readonly"){ return; }
    getJSON(API + "/instance-action", {
      method:"POST", headers:headers(token),
      body:JSON.stringify({id:id, action:action})
    }, function(){ setTimeout(loadInstances, 1500); });
  }

  // --- Services modal
  var currentInst = null;
  function openSvc(inst){
    currentInst = inst;
    document.getElementById("svcTitle").textContent = "Services on "+inst.name;
    document.getElementById("svcBody").innerHTML = "";
    document.getElementById("svcFooter").textContent = "";
    if(role==="read" || role==="readonly"){
      document.getElementById("btnIisReset").disabled = true;
    }else{
      document.getElementById("btnIisReset").disabled = false;
    }
    document.getElementById("svcModal").style.display = "flex";
    refreshSvc();
  }

  function closeSvc(){ document.getElementById("svcModal").style.display = "none"; currentInst=null; }
  function refreshSvc(){
    if(!currentInst){ return; }
    var patt = document.getElementById("svcFilter").value.trim();
    getJSON(API + "/services", {
      method:"POST", headers:headers(token),
      body:JSON.stringify({id: currentInst.id, mode: "list", pattern: patt})
    }, function(err, res){
      var box = document.getElementById("svcBody");
      box.innerHTML = "";
      if(res && res.error){ box.innerHTML = "<div class='note'>"+res.error+"</div>"; return; }
      var arr = res && res.services ? res.services : [];
      if(!arr || (arr.length===0)){
        box.innerHTML = "<div class='note'>No matching services</div>";
        return;
      }
      arr.forEach(function(s){
        var line = document.createElement("div");
        line.className = "svcrow";
        var nm = document.createElement("div");
        nm.className = "svcname"; nm.textContent = s.Name;
        var st = document.createElement("div");
        st.className = (s.Status=="Running" ? "svcok" : "svcbad");
        st.textContent = s.Status;
        var controls = document.createElement("div");
        if(role==="read" || role==="readonly"){
          controls.innerHTML = "<span class='note'>read-only</span>";
        }else{
          var b1 = document.createElement("button");
          b1.className = "small ok"; b1.textContent = "Start";
          b1.onclick = function(){ svcAction(s.Name, "start"); };
          var b2 = document.createElement("button");
          b2.className = "small danger"; b2.textContent = "Stop";
          b2.onclick = function(){ svcAction(s.Name, "stop"); };
          controls.appendChild(b1); controls.appendChild(b2);
        }
        line.appendChild(nm); line.appendChild(st); line.appendChild(controls);
        box.appendChild(line);
      });
    });
  }

  function svcAction(name, action){
    if(!currentInst){ return; }
    if(role==="read" || role==="readonly"){ return; }
    getJSON(API + "/services", {
      method:"POST", headers:headers(token),
      body:JSON.stringify({id: currentInst.id, mode: action, service: name})
    }, function(){ setTimeout(refreshSvc, 1200); });
  }

  function iisReset(){
    if(!currentInst){ return; }
    if(role==="read" || role==="readonly"){ return; }
    getJSON(API + "/services", {
      method:"POST", headers:headers(token),
      body:JSON.stringify({id: currentInst.id, mode: "iisreset"})
    }, function(err,res){
      document.getElementById("svcFooter").textContent = "IIS reset requested";
      setTimeout(refreshSvc, 1800);
    });
  }

  function sqlInfo(){
    if(!currentInst){ return; }
    getJSON(API + "/services", {
      method:"POST", headers:headers(token),
      body:JSON.stringify({id: currentInst.id, mode: "sqlinfo"})
    }, function(err,res){
      var box = document.getElementById("svcBody");
      box.innerHTML = "";
      if(res && res.error){ box.innerHTML = "<div class='note'>"+res.error+"</div>"; return; }
      var os = res && res.os ? res.os : {};
      var sql = res && res.sql ? res.sql : [];
      var sv = res && res.services ? res.services : [];
      var h = "<div class='note'>OS: "+(os.Caption||"")+" "+(os.Version||"")+" ("+(os.BuildNumber||"")+")</div>";
      if(sql && sql.length>0){
        h += "<div class='group-title' style='margin-top:10px'>SQL Instances</div>";
        sql.forEach(function(x){
          h += "<div class='note'>"+x.Instance+" — v"+x.Version+" ("+x.PatchLevel+")</div>";
        });
      }else{
        h += "<div class='note'>No SQL instance info found</div>";
      }
      h += "<div class='group-title' style='margin-top:10px'>SQL Services</div>";
      box.innerHTML = h;
      (sv||[]).forEach(function(s){
        var line = document.createElement("div");
        line.className = "svcrow";
        var nm = document.createElement("div"); nm.className="svcname"; nm.textContent = s.Name;
        var st = document.createElement("div"); st.className = (s.Status=="Running"?"svcok":"svcbad"); st.textContent = s.Status;
        var controls = document.createElement("div");
        if(role==="read" || role==="readonly"){ controls.innerHTML = "<span class='note'>read-only</span>"; }
        else{
          var b1 = document.createElement("button"); b1.className="small ok"; b1.textContent="Start"; b1.onclick=function(){ svcAction(s.Name,"start"); };
          var b2 = document.createElement("button"); b2.className="small danger"; b2.textContent="Stop"; b2.onclick=function(){ svcAction(s.Name,"stop"); };
          controls.appendChild(b1); controls.appendChild(b2);
        }
        line.appendChild(nm); line.appendChild(st); line.appendChild(controls);
        box.appendChild(line);
      });
    });
  }

  function ssmPing(){
    if(!currentInst){ return; }
    getJSON(API + "/ssm-ping", {
      method:"POST", headers:headers(token),
      body:JSON.stringify({id: currentInst.id})
    }, function(err,res){
      var t = document.getElementById("svcFooter");
      if(res && res.ping){ t.textContent = "Host: " + (res.ping.Host||"") + " • Time: " + (res.ping.Time||""); }
      else if(res && res.error){ t.textContent = res.error; }
      else { t.textContent = "No response"; }
    });
  }

  // --- Auth UI
  function openLogin(){ document.getElementById("loginModal").style.display = "flex"; }
  function closeLogin(){ document.getElementById("loginModal").style.display = "none"; document.getElementById("loginMsg").textContent=""; }

  function switchTab(which){
    var a = document.getElementById("formPwd");
    var b = document.getElementById("formOtp");
    if(which==="pwd"){ a.classList.remove("hidden"); b.classList.add("hidden"); }
    else { b.classList.remove("hidden"); a.classList.add("hidden"); }
  }

  function doLogin(){
    var u = document.getElementById("inUser").value.trim();
    var p = document.getElementById("inPass").value;
    document.getElementById("loginMsg").textContent = "";
    getJSON(API + "/login", {
      method:"POST", headers:headers(), body:JSON.stringify({username:u,password:p})
    }, function(err,res){
      if(res && res.token){
        token = res.token; role = res.role || ""; user = (res.user && res.user.name) || u;
        localStorage.setItem("token", token);
        localStorage.setItem("role", role);
        localStorage.setItem("user", user);
        setBadge(); closeLogin(); loadInstances();
      }else{
        document.getElementById("loginMsg").textContent = (res && res.error) ? res.error : "Login failed";
      }
    });
  }

  function reqOtp(){
    var em = document.getElementById("inEmail").value.trim();
    document.getElementById("otpMsg").textContent = "";
    getJSON(API + "/request-otp", {method:"POST", headers:headers(), body:JSON.stringify({email:em})}, function(err,res){
      document.getElementById("otpMsg").textContent = res && res.error ? res.error : "OTP sent (check email)";
    });
  }
  function verifyOtp(){
    var em = document.getElementById("inEmail").value.trim();
    var cd = document.getElementById("inCode").value.trim();
    getJSON(API + "/verify-otp", {method:"POST", headers:headers(), body:JSON.stringify({email:em, code:cd})}, function(err,res){
      document.getElementById("loginMsg").textContent = res && res.error ? res.error : "Verified. (Now sign in with your user/password if required.)";
    });
  }

  function logout(){
    token=""; role=""; user="";
    localStorage.removeItem("token"); localStorage.removeItem("role"); localStorage.removeItem("user");
    setBadge();
    document.getElementById("envTabs").innerHTML="";
    document.getElementById("envContainer").innerHTML="";
    document.getElementById("kTotal").textContent="Total: 0";
    document.getElementById("kRun").textContent="Running: 0";
    document.getElementById("kStop").textContent="Stopped: 0";
  }

  // wire up
  document.getElementById("refreshBtn").onclick = loadInstances;
  document.getElementById("loginBtn").onclick   = openLogin;
  document.getElementById("logoutBtn").onclick  = logout;

  document.getElementById("svcClose").onclick   = closeSvc;
  document.getElementById("svcRefresh").onclick = refreshSvc;
  document.getElementById("btnIisReset").onclick= iisReset;
  document.getElementById("btnSqlInfo").onclick = sqlInfo;
  document.getElementById("btnSsmPing").onclick = ssmPing;

  document.getElementById("tabPwd").onclick     = function(){ switchTab("pwd"); };
  document.getElementById("tabOtp").onclick     = function(){ switchTab("otp"); };
  document.getElementById("btnLogin").onclick   = doLogin;
  document.getElementById("btnReqOtp").onclick  = reqOtp;
  document.getElementById("btnVerifyOtp").onclick = verifyOtp;
  document.getElementById("loginClose").onclick = closeLogin;

  // init
  setBadge();
  if(token){ loadInstances(); }
})();
</script>
</body>
</html>
