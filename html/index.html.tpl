<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>EC2 Dashboard</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    :root{--bg:#0e1624;--panel:#121b2b;--ink:#e6e9ef;--mut:#9aa4b2;--ok:#2e9762;--bad:#b94a4a;--chip:#19243a;--brand:#7b8cff}
    body{margin:0;background:var(--bg);color:var(--ink);font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,"Helvetica Neue",sans-serif}
    .wrap{max-width:1100px;margin:28px auto;padding:0 16px}
    .row{display:flex;gap:10px;flex-wrap:wrap}
    .tile{background:var(--chip);padding:14px 18px;border-radius:14px;font-weight:700;box-shadow:0 0 0 1px #1c2840 inset}
    .tile.big{font-size:24px}
    .tabs .tab{background:var(--chip);padding:8px 14px;border-radius:12px;cursor:pointer}
    .tabs .tab.active{outline:2px solid var(--brand)}
    .box{background:var(--panel);border-radius:14px;padding:14px 16px;margin:12px 0}
    .stack{display:flex;flex-direction:column;gap:10px}
    .rowline{display:flex;align-items:center;gap:10px;justify-content:space-between;background:#0f1a2e;border:1px solid #1c2840;border-radius:12px;padding:10px 12px}
    .state{font-size:12px;color:#cfead9}
    .btn{padding:6px 12px;border-radius:10px;background:#203252;border:0;color:#dfe7f5;cursor:pointer}
    .btn.ok{background:var(--ok)}
    .btn.bad{background:var(--bad)}
    .btn.small{padding:4px 10px;font-size:12px}
    .chip{padding:6px 10px;background:#1a2742;border-radius:12px;font-size:12px}
    .mut{color:var(--mut);font-size:12px}
    .right{margin-left:auto}
    .modal{position:fixed;inset:0;background:rgba(0,0,0,.5);display:none;align-items:center;justify-content:center;padding:16px;z-index:10}
    .modal .card{background:var(--panel);border-radius:14px;padding:16px;max-width:900px;width:100%}
    .grid{display:grid;grid-template-columns:1fr 1fr 50px 50px;gap:10px}
    input,select{background:#0f1a2e;border:1px solid #243355;color:#e6e9ef;border-radius:10px;padding:8px 10px}
    .error{background:#2b1620;color:#ffd9de;border:1px solid #5a2533;border-radius:10px;padding:8px 10px}
  </style>
</head>
<body>
<div class="wrap" id="app">
  <div class="row">
    <div class="tile big" id="tTotal">Total: 0</div>
    <div class="tile big" id="tRun">Running: 0</div>
    <div class="tile big" id="tStop">Stopped: 0</div>
    <div class="right"></div>
    <div class="chip" id="userBadge" style="display:none"></div>
    <button class="btn small" onclick="openLogin()">Login</button>
    <button class="btn small" onclick="logout()">Sign out</button>
    <button class="btn small" onclick="refresh()">Refresh</button>
  </div>

  <div class="tabs row" id="envTabs"></div>
  <div id="envMount"></div>
</div>

<div class="modal" id="svcModal">
  <div class="card">
    <div class="row" style="margin-bottom:10px">
      <div id="svcTitle" style="font-weight:700">Services</div>
      <div class="right"></div>
      <input id="svcFilter" placeholder="Type to filter (Name or DisplayName)" style="width:260px;display:none">
      <button class="btn small" id="btnRefresh" onclick="svcRefresh()" style="display:none">Refresh</button>
      <button class="btn small" id="btnIIS" onclick="svcIISReset()" style="display:none">IIS Reset</button>
      <button class="btn small" onclick="closeSvc()">Back</button>
    </div>
    <div id="svcBody"></div>
    <div id="svcHint" class="mut" style="margin-top:10px"></div>
  </div>
</div>

<div class="modal" id="authModal">
  <div class="card" style="max-width:760px">
    <div class="row" style="gap:12px;margin-bottom:12px">
      <button id="tabOtp" class="btn small" onclick="showOtp()">Email OTP</button>
      <button id="tabPwd" class="btn small" onclick="showPwd()">User / Password</button>
      <div class="right"></div>
      <button class="btn small" onclick="closeAuth()">Close</button>
    </div>

    <div id="paneOtp">
      <div class="row" style="gap:10px">
        <input id="otpEmail" placeholder="name@${allowed_email_domain}" style="width:320px">
        <button class="btn" onclick="requestOtp()">Request OTP</button>
      </div>
      <div class="row" style="gap:10px;margin-top:10px">
        <input id="otpCode" placeholder="6-digit code" style="width:160px">
        <button class="btn" onclick="verifyOtp()">Verify OTP</button>
      </div>
      <div class="mut" style="margin-top:8px">Allowed domain: ${allowed_email_domain}</div>
    </div>

    <div id="panePwd" style="display:none">
      <div class="mut" style="margin-bottom:6px">Enter credentials (OTP required first).</div>
      <div class="row" style="gap:10px">
        <input id="uName" placeholder="username" style="width:220px">
        <input id="uPass" placeholder="password" type="password" style="width:220px">
        <button id="btnLogin" class="btn" onclick="doLogin()" disabled>Login</button>
      </div>
      <div class="mut" style="margin-top:8px">Tip: give a user the role <b>read</b> for demo-only (start/stop disabled).</div>
    </div>
  </div>
</div>

<script>
  var API = "${api_base_url}";
  var ENV_NAMES = "${env_names}".split(",");
  // Let login.js pick this up without templating
  try { localStorage.setItem("api_base_url", API); } catch(e) {}

  function http(path, method, obj, bearer){
    var h = {"content-type":"application/json"};
    if(bearer){ h["authorization"] = "Bearer " + bearer; }
    return fetch(API + path, {method:method, headers:h, body: obj? JSON.stringify(obj): undefined})
      .then(async function(r){
        const data = await r.json().catch(()=> ({}));
        if(!r.ok){ const msg = (data && (data.error||data.message)) || ("http " + r.status); throw new Error(msg); }
        return data;
      });
  }
  function $(id){ return document.getElementById(id); }
  function toast(msg){ alert(msg); }

  function openLogin(){ $("authModal").style.display="flex"; showOtp(); }
  function logout(){
    ["jwt","role","user","otp_verified","otp_verified_until","allowed_domain"].forEach(k=>localStorage.removeItem(k));
    refresh();
  }
  function closeAuth(){ $("authModal").style.display = "none"; }
  function showOtp(){ $("paneOtp").style.display="block"; $("panePwd").style.display="none"; }
  function showPwd(){ $("paneOtp").style.display="none"; $("panePwd").style.display="block"; }

  function requestOtp(){
    var em = $("otpEmail").value.trim();
    if(!em){ toast("enter email"); return; }
    http("/request-otp","POST",{email:em}).then(()=>toast("OTP sent")).catch(e=>toast(e.message));
  }

  // ✅ Redirect to a SEPARATE page after OTP success
  function verifyOtp(){
    var em = $("otpEmail").value.trim(), cd = $("otpCode").value.trim();
    if(!em || !cd){ toast("enter email and code"); return; }
    http("/verify-otp","POST",{email:em, code:cd})
      .then(function(){
        localStorage.setItem("otp_verified","1");
        localStorage.setItem("allowed_domain","${allowed_email_domain}");
        localStorage.setItem("otp_verified_until", String(Date.now() + (10 * 60 * 1000))); // 10 min
        window.location.assign("/login.html");
      })
      .catch(e=>toast(e.message));
  }

  // (kept for backwards-compat if someone opens modal)
  function doLogin(){
    var u = $("uName").value.trim(), p = $("uPass").value;
    if(!u || !p){ toast("missing credentials"); return; }
    if(localStorage.getItem("otp_verified")!=="1"){ toast("Please verify OTP first"); return; }
    http("/login","POST",{username:u,password:p})
      .then(function(res){
        localStorage.setItem("jwt", res.token);
        localStorage.setItem("role", res.role);
        localStorage.setItem("user", JSON.stringify(res.user));
        $("authModal").style.display="none";
        renderUser(); refresh();
      }).catch(e=>toast(e.message));
  }
  $("uPass").addEventListener("keydown", function(e){ if(e.key==="Enter"){ doLogin(); } });

  function renderUser(){
    var u = localStorage.getItem("user");
    if(u){ var o=JSON.parse(u); $("userBadge").textContent=(o.name||o.username||"")+" • "+(o.role||""); $("userBadge").style.display="inline-block"; }
    else{ $("userBadge").style.display="none"; }
  }

  function refresh(){
    var jwt = localStorage.getItem("jwt");
    if(!jwt){ $("authModal").style.display="flex"; showOtp(); return; }
    http("/instances","GET",null,jwt).then(function(data){
      $("tTotal").textContent="Total: "+data.summary.total;
      $("tRun").textContent="Running: "+data.summary.running;
      $("tStop").textContent="Stopped: "+data.summary.stopped;
      renderTabs(data.envs);
    }).catch(function(){ $("authModal").style.display="flex"; showOtp(); });
  }

  function renderTabs(envs){
    var tabs=$("envTabs"); tabs.innerHTML="";
    ENV_NAMES.forEach(function(e,i){
      var b=document.createElement("div"); b.className="tab"; b.textContent=e;
      b.onclick=function(){ drawEnv(envs[e]||{DM:[],EA:[]}); setActive(i); };
      tabs.appendChild(b);
    });
    setActive(0); drawEnv(envs[ENV_NAMES[0]]||{DM:[],EA:[]});
    function setActive(idx){ tabs.querySelectorAll(".tab").forEach((n,k)=>n.classList.toggle("active",k===idx)); }
  }

  function drawEnv(env){
    var mount=$("envMount"); mount.innerHTML="";
    ["Dream Mapper","Encore Anywhere"].forEach(function(section, si){
      var box=document.createElement("div"); box.className="box";
      var head=document.createElement("div"); head.textContent=section; head.style.fontWeight="700"; head.style.marginBottom="8px"; box.appendChild(head);
      var list= si===0 ? (env.DM||[]) : (env.EA||[]);
      var wrap=document.createElement("div"); wrap.className="stack";
      list.forEach(function(it){
        var line=document.createElement("div"); line.className="rowline";
        var left=document.createElement("div"); left.innerHTML="<b>"+it.name+"</b> <span class='mut'>("+it.id+")</span>";
        line.appendChild(left);
        var state=document.createElement("div"); state.className="state"; state.textContent=it.state||""; line.appendChild(state);
        var start=btn("Start","ok",function(){ act(it.id,"start"); });
        var stop=btn("Stop","bad",function(){ act(it.id,"stop"); });
        if((it.state||"").toLowerCase()==="running"){ start.disabled=true; } else { stop.disabled=true; }
        line.appendChild(start); line.appendChild(stop);
        line.appendChild(btn("Services","",function(){ openSvc(it); }));
        wrap.appendChild(line);
      });
      box.appendChild(wrap); mount.appendChild(box);
    });
  }
  function btn(tone, css, fn){ var b=document.createElement("button"); b.textContent=tone; b.className="btn small "+css; b.onclick=fn; return b; }
  function act(id,what){ http("/instance-action","POST",{id:id, action:what}, localStorage.getItem("jwt")).then(()=>setTimeout(refresh,1500)).catch(()=>toast("action failed")); }

  var svcCtx={id:"",name:"",type:"svcweb"};
  function openSvc(it){
    svcCtx.id=it.id; svcCtx.name=it.name||""; var nm=(svcCtx.name.toLowerCase());
    svcCtx.type = nm.indexOf("sql")>=0 ? "sql" : "svcweb";
    $("svcTitle").textContent="Services on "+svcCtx.name;
    if(svcCtx.type==="sql"){ $("svcFilter").style.display="none"; $("btnRefresh").style.display="none"; $("btnIIS").style.display="none"; $("svcHint").textContent="Showing SQL Server & SQL Agent services."; }
    else{ $("svcFilter").style.display="inline-block"; $("btnRefresh").style.display="inline-block"; $("btnIIS").style.display="inline-block"; $("svcHint").textContent="Type a fragment (e.g. 'w3svc', 'app', 'redis') and press Refresh."; }
    $("svcBody").innerHTML=""; $("svcModal").style.display="flex"; svcRefresh();
  }
  function closeSvc(){ $("svcModal").style.display="none"; }
  function svcRefresh(){
    var body={id:svcCtx.id, mode:"list", instanceName:svcCtx.name}; if(svcCtx.type!=="sql") body.pattern=$("svcFilter").value.trim();
    http("/services","POST", body, localStorage.getItem("jwt")).then(function(res){
      var mount=$("svcBody"); mount.innerHTML="";
      if(res.error){
        var tip=""; if(res.error==="not_connected") tip="SSM target not connected. Check SSM Agent is running, instance has internet/VPC endpoints, and the instance profile is attached.";
        else if(res.error==="denied") tip="SSM access denied. Ensure Lambda role and instance profile permissions are correct.";
        var d=document.createElement("div"); d.className="error"; d.textContent="SSM error: "+res.error+(res.reason? " ("+res.reason+")":"")+". "+tip; mount.appendChild(d); return;
      }
      var svcs=res.services||[]; if(svcCtx.type!=="sql" && !$("svcFilter").value.trim()){ var d2=document.createElement("div"); d2.className="mut"; d2.textContent="Enter text to filter services."; mount.appendChild(d2); return; }
      var g=document.createElement("div"); g.className="grid"; var role=(localStorage.getItem("role")||"read").toLowerCase();
      for(var i=0;i<svcs.length;i++){ var s=svcs[i];
        var n=document.createElement("div"); n.textContent=s.Name||""; var d=document.createElement("div"); d.textContent=s.DisplayName||""; var st=(s.Status||"").toString().toLowerCase();
        var b1=btn("Start","ok",(function(name){return function(){svcAction("start",name);};})(s.Name));
        var b2=btn("Stop","bad",(function(name){return function(){svcAction("stop",name);};})(s.Name));
        if(role!=="admin"){ b1.disabled=true; b2.disabled=true; } if(st==="running"){ b1.disabled=true; } else if(st==="stopped"){ b2.disabled=true; }
        g.appendChild(n); g.appendChild(d); g.appendChild(b1); g.appendChild(b2);
      } mount.appendChild(g);
    }).catch(()=>toast("internal"));
  }
  function svcAction(what,name){ http("/services","POST",{id:svcCtx.id,mode:what,service:name}, localStorage.getItem("jwt")).then(()=>svcRefresh()).catch(()=>toast("service action failed")); }
  function svcIISReset(){ http("/services","POST",{id:svcCtx.id,mode:"iisreset"}, localStorage.getItem("jwt")).then(()=>{toast("IIS reset sent"); svcRefresh();}).catch(()=>toast("failed")); }

  (function init(){ renderUser(); $("authModal").style.display="flex"; showOtp(); refresh(); })();
</script>
</body>
</html>
