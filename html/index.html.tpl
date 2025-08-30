<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>EC2 Dashboard</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    :root{
      --bg:#0b1422; --card:#111b2b; --chip:#0f223e; --text:#e9f0ff; --muted:#9fb2d7;
      --green:#1f8f5f; --red:#a34444; --blue:#4578e6; --chip2:#15233b;
    }
    *{box-sizing:border-box} body{margin:0;background:var(--bg);color:var(--text);font-family:system-ui,Segoe UI,Roboto,Arial}
    .wrap{max-width:1200px;margin:0 auto;padding:24px;}
    h1{margin:0 0 12px 0;font-weight:700}
    .stats{display:flex;gap:12px;flex-wrap:wrap;margin:8px 0 20px 0}
    .stat{background:var(--chip);border-radius:18px;padding:10px 16px;font-weight:700}
    .stat.big{font-size:22px;padding:14px 22px;border:1px solid #28446f;box-shadow:0 0 0 2px #0c2142 inset}
    .topbar{display:flex;gap:10px;align-items:center;justify-content:flex-end;margin-top:-44px}
    .btn{background:#20385f;color:#dbe8ff;border:none;border-radius:10px;padding:8px 12px;cursor:pointer}
    .btn.small{padding:6px 10px}
    .btn.green{background:var(--green)} .btn.red{background:var(--red)} .btn.blue{background:var(--blue)}
    .btn:disabled{opacity:.5;cursor:not-allowed}
    .tabs{display:flex;gap:10px;flex-wrap:wrap;margin:10px 0 16px 0}
    .pill{background:var(--chip2);padding:8px 14px;border-radius:999px;cursor:pointer}
    .pill.active{outline:2px solid #2b4f8a}
    .card{background:var(--card);border-radius:14px;padding:16px;margin:12px 0}
    .row{display:flex;align-items:center;justify-content:space-between;background:#0f192a;border-radius:10px;padding:10px 12px;margin:8px 0}
    .name{font-weight:700}
    .state{color:#9dd8b9;margin-right:8px}
    .modal{position:fixed;inset:0;background:rgba(0,0,0,.55);display:none;align-items:center;justify-content:center;padding:16px;z-index:30}
    .modal.in{display:flex}
    .panel{max-width:620px;width:100%;background:var(--card);border-radius:16px;padding:18px}
    .grid{display:grid;grid-template-columns:1fr auto auto;gap:8px;align-items:center}
    .svc-head{display:flex;justify-content:space-between;align-items:center;margin-bottom:8px}
    .muted{color:var(--muted);font-size:12px}
    input,select{background:#0f1b2c;border:1px solid #20324d;color:#e9f0ff;border-radius:8px;padding:9px 10px}
    .w100{width:100%}
    .mt8{margin-top:8px}.mt12{margin-top:12px}.mt16{margin-top:16px}
    .note{font-size:12px;color:#a8b9db}
    .svc-row{display:grid;grid-template-columns:1fr 80px 80px;gap:8px;align-items:center;background:#0f1829;border-radius:8px;padding:8px;margin:6px 0}
    .svcname{font-family:ui-monospace,Consolas,monospace}
    .err{background:#291316;border:1px solid #5f2b2b;border-radius:10px;padding:8px 10px;color:#ffb3b3;margin:8px 0}
    .header{display:flex;align-items:flex-end;justify-content:space-between}
    .who{background:#12243d;border-radius:999px;padding:8px 12px}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="header">
      <h1>EC2 Dashboard</h1>
      <div class="topbar">
        <span id="who" class="who" style="display:none"></span>
        <button class="btn small" id="btnSignOut" style="display:none">Sign out</button>
        <button class="btn small" id="btnRefresh">Refresh</button>
        <button class="btn small" id="btnLogin">Login</button>
      </div>
    </div>

    <div class="stats">
      <div class="stat big" id="statTotal">Total: 0</div>
      <div class="stat big" id="statRun">Running: 0</div>
      <div class="stat big" id="statStop">Stopped: 0</div>
    </div>

    <div class="tabs" id="envTabs"></div>

    <div id="envContainer"></div>
  </div>

  <!-- Sign-in modal -->
  <div class="modal" id="authModal">
    <div class="panel" style="max-width:700px">
      <h3>Sign in</h3>
      <div style="display:flex;gap:8px" class="mt8">
        <button class="btn small" id="tabOtp">Email OTP</button>
        <button class="btn small" id="tabUpw">User / Password</button>
      </div>

      <div id="otpPane" class="mt12">
        <div class="note">Allowed domain: <b id="allowDom"></b></div>
        <div class="mt8"><input class="w100" id="otpEmail" placeholder="name@example.com"></div>
        <div class="mt8" style="display:flex;gap:8px">
          <button class="btn blue" id="btnReqOtp">Request OTP</button>
          <input id="otpCode" placeholder="6-digit code" style="width:160px">
          <button class="btn blue" id="btnVerifyOtp">Verify OTP</button>
        </div>
        <div class="note mt8">After verification a new tab with the username/password page will open.</div>
      </div>

      <div id="upwPane" class="mt12" style="display:none;opacity:.5;pointer-events:none">
        <div class="note">Enter credentials (OTP required first).</div>
        <div class="mt8"><input class="w100" id="upwUser" placeholder="username"></div>
        <div class="mt8" style="display:flex;gap:8px">
          <input id="upwPass" placeholder="password" type="password" class="w100">
          <button class="btn blue" id="btnLogin2">Login</button>
        </div>
        <div class="note mt8">Tip: give a user the role <b>read</b> for demo-only (start/stop disabled).</div>
      </div>

      <div class="mt16" style="text-align:right">
        <button class="btn" id="btnCloseAuth">Close</button>
      </div>
    </div>
  </div>

  <!-- Services modal -->
  <div class="modal" id="svcModal">
    <div class="panel" style="max-width:900px">
      <div class="svc-head">
        <div>
          <b>Services on <span id="svcTitle"></span></b>
          <div class="note" id="svcHint"></div>
        </div>
        <div>
          <input id="svcFilter" placeholder="Type to filter (web/svc)" style="display:none">
          <button class="btn small" id="btnIIS" style="display:none">IIS Reset</button>
          <button class="btn small" id="btnCloseSvc">Back</button>
        </div>
      </div>
      <div id="svcError" class="err" style="display:none"></div>
      <div id="svcRows"></div>
      <div class="note" id="svcFoot"></div>
    </div>
  </div>

<script>
(function(){
  var API = "${api_base_url}";
  var ALLOWED = "${allowed_email_domain}";
  var ENVS = ("${env_names}"||"").split(",").filter(function(x){return x});

  var token = "";
  var role = "read";
  var userObj = null;

  var envData = {}; // cached listing response
  var svcCtx = null; // current services context

  // DOM refs
  var envTabs = document.getElementById("envTabs");
  var envContainer = document.getElementById("envContainer");
  var statTotal = document.getElementById("statTotal");
  var statRun = document.getElementById("statRun");
  var statStop = document.getElementById("statStop");
  var btnLogin = document.getElementById("btnLogin");
  var btnSignOut = document.getElementById("btnSignOut");
  var btnRefresh = document.getElementById("btnRefresh");
  var who = document.getElementById("who");

  // auth modal
  var authModal = document.getElementById("authModal");
  var tabOtp = document.getElementById("tabOtp");
  var tabUpw = document.getElementById("tabUpw");
  var otpPane = document.getElementById("otpPane");
  var upwPane = document.getElementById("upwPane");
  var allowDom = document.getElementById("allowDom");
  var otpEmail = document.getElementById("otpEmail");
  var otpCode = document.getElementById("otpCode");
  var btnReqOtp = document.getElementById("btnReqOtp");
  var btnVerifyOtp = document.getElementById("btnVerifyOtp");
  var upwUser = document.getElementById("upwUser");
  var upwPass = document.getElementById("upwPass");
  var btnLogin2 = document.getElementById("btnLogin2");
  var btnCloseAuth = document.getElementById("btnCloseAuth");

  // svc modal
  var svcModal = document.getElementById("svcModal");
  var svcTitle = document.getElementById("svcTitle");
  var svcRows = document.getElementById("svcRows");
  var svcFilter = document.getElementById("svcFilter");
  var btnIIS = document.getElementById("btnIIS");
  var btnCloseSvc = document.getElementById("btnCloseSvc");
  var svcHint = document.getElementById("svcHint");
  var svcError = document.getElementById("svcError");
  var svcFoot = document.getElementById("svcFoot");

  allowDom.textContent = ALLOWED;

  function show(el, yes){ el.style.display = yes ? "" : "none"; }
  function modal(m, yes){ if(yes){m.classList.add("in")} else {m.classList.remove("in")} }
  function hdr(){
    if(userObj){
      who.textContent = userObj.name+" • "+role;
      show(who,true); show(btnSignOut,true); show(btnLogin,false);
    }else{
      show(who,false); show(btnSignOut,false); show(btnLogin,true);
    }
  }

  function api(path, opt){
    opt = opt||{};
    var m = opt.method||"GET";
    var body = opt.body? JSON.stringify(opt.body): null;
    return fetch(API+path, {method:m, headers:{"content-type":"application/json","Authorization":"Bearer "+token}, body:body})
      .then(function(r){ return r.ok? r.json(): r.json().catch(function(){return {error:"request failed"}}) })
  }

  // ---------- OTP gating ----------
  tabOtp.onclick = function(){ otpPane.style.display=""; upwPane.style.display="none" }
  tabUpw.onclick = function(){ otpPane.style.display="none"; upwPane.style.display="" }
  btnLogin.onclick = function(){ openAuth() }
  btnCloseAuth.onclick = function(){ modal(authModal,false) }

  function openAuth(){
    modal(authModal,true);
    // if hash is #/login, enable UPW tab
    var hasOtp = sessionStorage.getItem("otp_token")? true:false;
    if(location.hash=="#/login"){ 
      tabUpw.click();
    }else{
      tabOtp.click();
    }
    setUpwEnabled(hasOtp);
  }

  function setUpwEnabled(enabled){
    upwPane.style.opacity = enabled? "1":"0.5";
    upwPane.style.pointerEvents = enabled? "auto":"none";
  }

  btnReqOtp.onclick = function(){
    var em = (otpEmail.value||"").trim();
    api("/request-otp",{method:"POST",body:{email:em}})
      .then(function(j){ alert(j.error||"OTP sent (check your email)"); })
  }

  btnVerifyOtp.onclick = function(){
    var em = (otpEmail.value||"").trim();
    var code = (otpCode.value||"").trim();
    api("/verify-otp",{method:"POST",body:{email:em,code:code}})
      .then(function(j){
        if(j.error){ alert(j.error); return; }
        sessionStorage.setItem("otp_token", j.otp_token||"");
        setUpwEnabled(true);
        // open UPW page in a new tab
        window.open(location.origin + location.pathname + "#/login", "_blank");
      })
  }

  btnLogin2.onclick = function(){
    var u = (upwUser.value||"").trim();
    var p = (upwPass.value||"").trim();
    var otpTok = sessionStorage.getItem("otp_token")||"";
    api("/login",{method:"POST",body:{username:u,password:p,otp_token:otpTok}})
      .then(function(j){
        if(j.error){ alert(j.error); return; }
        token = j.token||""; role = j.role||"read"; userObj = j.user||null; modal(authModal,false); hdr(); refresh();
      })
  }

  btnSignOut.onclick = function(){ token=""; role="read"; userObj=null; hdr(); }
  btnRefresh.onclick = function(){ refresh(); }

  // ---------- Instances ----------
  function refresh(){
    api("/instances").then(function(j){
      if(j.error){ alert(j.error); return; }
      envData = j; updateSummary(j.summary||{total:0,running:0,stopped:0}); renderTabs(j.envs||{});
    })
  }
  function updateSummary(s){
    statTotal.textContent = "Total: "+(s.total||0);
    statRun.textContent = "Running: "+(s.running||0);
    statStop.textContent = "Stopped: "+(s.stopped||0);
  }

  function renderTabs(envs){
    envTabs.innerHTML = "";
    var first = null;
    ENVS.forEach(function(e){
      if(!envs[e]) return;
      var b = document.createElement("div");
      b.className="pill"; b.textContent=e;
      b.onclick = function(){
        Array.prototype.forEach.call(envTabs.children,function(c){c.classList.remove("active")});
        b.classList.add("active");
        renderEnv(e, envs[e]);
      }
      envTabs.appendChild(b);
      if(!first) first = b;
    });
    envContainer.innerHTML = "";
    if(first){ first.click(); } // show nothing until a tab is clicked? (still highlights summary)
  }

  function renderEnv(name, blocks){
    envContainer.innerHTML = "";
    ["Dream Mapper","Encore Anywhere"].forEach(function(title, idx){
      var key = idx==0? "DM":"EA";
      var list = (blocks[key]||[]).slice();
      var card = document.createElement("div");
      card.className="card";
      var h = document.createElement("div"); h.textContent = title; h.style.fontWeight="700"; h.style.marginBottom="8px"; card.appendChild(h);

      list.forEach(function(it){
        var row = document.createElement("div"); row.className="row";
        var left = document.createElement("div");
        left.innerHTML = '<span class="name">'+escapeHtml(it.name)+'</span> <span class="muted">('+it.id+')</span>';
        var right = document.createElement("div");

        var st = document.createElement("span"); st.className="state"; st.textContent = it.state;
        var bStart = document.createElement("button"); bStart.className="btn small green"; bStart.textContent="Start";
        var bStop  = document.createElement("button"); bStop.className="btn small red"; bStop.textContent="Stop";
        var bSvc   = document.createElement("button"); bSvc.className="btn small"; bSvc.textContent="Services";

        bStart.disabled = role=="read" || it.state=="running";
        bStop.disabled  = role=="read" || it.state!="running";

        bStart.onclick = function(){ action(it.id,"start") }
        bStop.onclick  = function(){ action(it.id,"stop") }
        bSvc.onclick   = function(){ openServices(it) }

        right.appendChild(st); right.appendChild(bStart); right.appendChild(bStop); right.appendChild(bSvc);
        row.appendChild(left); row.appendChild(right);
        card.appendChild(row);
      });

      envContainer.appendChild(card);
    });
  }

  function action(id, act){
    api("/instance-action",{method:"POST",body:{id:id,action:act}}).then(function(j){
      if(j.error){ alert(j.error); return; }
      setTimeout(refresh, 1500);
    })
  }

  // ---------- Services ----------
  function detectSvcKind(name){
    var n = (name||"").toLowerCase();
    if(n.indexOf("sql")>=0) return "sql";
    if(n.indexOf("redis")>=0) return "redis";
    if(n.indexOf("svc")>=0 || n.indexOf("web")>=0) return "web";
    return "web";
  }

  function openServices(it){
    svcCtx = { id: it.id, name: it.name, kind: detectSvcKind(it.name) };
    svcTitle.textContent = it.name;
    svcRows.innerHTML = "";
    svcError.style.display="none";
    svcFilter.value = "";
    show(btnIIS, svcCtx.kind=="web");
    show(svcFilter, svcCtx.kind=="web");
    svcHint.textContent = (svcCtx.kind=="sql")? "Showing SQL Server & SQL Agent services (default + named instances)."
                        : (svcCtx.kind=="redis")? "Showing redis-related services."
                        : "Type to filter; empty shows IIS core services.";
    svcFoot.textContent = "";
    modal(svcModal,true);
    loadServices();
  }

  function loadServices(){
    var body = { id: svcCtx.id, mode:"list", svc_kind: svcCtx.kind, pattern: (svcCtx.kind=="web"? (svcFilter.value||""):"") };
    api("/services",{method:"POST",body:body}).then(function(j){
      if(j.error){ showSvcErr(j.error); return; }
      renderSvcRows(j.services||[]);
      if(svcCtx.kind=="sql"){
        // fetch version/OS
        api("/services",{method:"POST",body:{id:svcCtx.id, mode:"sqlinfo"}}).then(function(info){
          if(info && !info.error){
            var os = info.os||{};
            var extra = "OS: "+(os.Caption||"")+" "+(os.Version||"")+" build "+(os.BuildNumber||"");
            var sqlv = (info.sql||[]).map(function(x){ return (x.Instance||"")+" "+(x.Version||"")+" ("+(x.PatchLevel||"")+")" });
            if(sqlv.length) extra += " • SQL: "+ sqlv.join("; ");
            svcFoot.textContent = extra;
          }
        });
      }
    })
  }

  function renderSvcRows(list){
    svcRows.innerHTML = "";
    list.forEach(function(sv){
      var r = document.createElement("div"); r.className="svc-row";
      var n = document.createElement("div"); n.className="svcname"; n.textContent = sv.Name||"";
      var bStart = document.createElement("button"); bStart.className="btn small green"; bStart.textContent="Start";
      var bStop  = document.createElement("button"); bStop.className="btn small red"; bStop.textContent="Stop";
      var running = ((""+sv.Status).toLowerCase()=="running");
      bStart.disabled = role=="read" || running;
      bStop.disabled  = role=="read" || !running;
      bStart.onclick = function(){ changeSvc(sv.Name,"start") }
      bStop.onclick  = function(){ changeSvc(sv.Name,"stop") }
      r.appendChild(n); r.appendChild(bStart); r.appendChild(bStop);
      svcRows.appendChild(r);
    });
  }

  function changeSvc(name, action){
    api("/services",{method:"POST",body:{id:svcCtx.id, mode:action, service:name}})
      .then(function(j){
        if(j.error){ showSvcErr(j.error); return; }
        renderSvcRows(j.services||[]);
      })
  }

  function showSvcErr(code){
    var map = {
      "not_connected":"SSM target not connected. The instance is online in your EC2 list but the SSM Agent is not reachable.",
      "denied":"SSM access denied. The Lambda role or instance profile lacks SSM permissions.",
      "timeout":"SSM command timed out.",
      "failed":"SSM command failed."
    };
    svcError.textContent = (map[code]||("Error: "+code));
    svcError.style.display = "";
  }

  btnIIS.onclick = function(){
    api("/services",{method:"POST",body:{id:svcCtx.id, mode:"iisreset"}}).then(function(j){
      if(j.error){ showSvcErr(j.error); return; }
      renderSvcRows(j.services||[]);
    })
  }
  svcFilter.oninput = function(){ loadServices() }
  btnCloseSvc.onclick = function(){ modal(svcModal,false) }

  // ---------- misc ----------
  function escapeHtml(s){ return (s||"").replace(/[&<>"']/g,function(c){return({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c])}) }

  // Auto-open OTP if first visit; if hash=#/login, open UPW page
  btnLogin.style.display=""; 
  if(location.hash=="#/login"){ openAuth(); tabUpw.click(); }
  refresh();
  hdr();
})();
</script>
</body>
</html>
