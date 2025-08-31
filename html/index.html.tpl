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
    .grid{display:grid;grid-template-columns:1fr 1fr 120px 80px 80px;gap:12px}
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
    <button id="btnLoginTop"  class="btn small" onclick="openLogin()" style="display:none">Login</button>
    <button id="btnSignout"   class="btn small" onclick="logout()"   style="display:none">Sign out</button>
    <button id="btnRefresh"   class="btn small" onclick="refresh()"  style="display:none">Refresh</button>
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
      <button class="btn small" id="btnSvcRefresh" onclick="svcRefresh()" style="display:none">Refresh</button>
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

  function $(id){ return document.getElementById(id); }
  function toast(msg){ alert(msg); }
  function sleep(ms){ return new Promise(r=>setTimeout(r,ms)); }

  function http(path, method, obj, bearer){
    var h = {"content-type":"application/json"};
    if(bearer){ h["authorization"] = "Bearer " + bearer; }
    return fetch(API + path, {method:method, headers:h, body: obj? JSON.stringify(obj): undefined})
      .then(async function(r){
        const data = await r.json().catch(()=> ({}));
        if(!r.ok){ const msg = (data && (data.error||data.message)) || r.statusText || ("http " + r.status); throw new Error(msg); }
        return data;
      });
  }
  async function httpRetry(path, method, obj, bearer){
    try { return await http(path, method, obj, bearer); }
    catch(e){
      if((e.message||"").toLowerCase().includes("service") || (e.message||"").includes("http 5")){
        await sleep(800);  // cold start / transient
        return await http(path, method, obj, bearer);
      }
      throw e;
    }
  }

  function openLogin(){ $("authModal").style.display="flex"; showOtp(); }
  function logout(){
    localStorage.removeItem("jwt"); localStorage.removeItem("role");
    localStorage.removeItem("user"); localStorage.removeItem("otp_verified");
    renderUser(); refresh();
  }
  function closeAuth(){ $("authModal").style.display = "none"; }
  function showOtp(){ $("paneOtp").style.display="block"; $("panePwd").style.display="none"; }
  function showPwd(){ $("paneOtp").style.display="none"; $("panePwd").style.display="block"; }

  function requestOtp(){
    var em = $("otpEmail").value.trim();
    if(!em){ toast("enter email"); return; }
    http("/request-otp","POST",{email:em}).then(()=>toast("OTP sent")).catch(e=>toast(e.message));
  }
  function verifyOtp(){
    var em = $("otpEmail").value.trim(), cd = $("otpCode").value.trim();
    if(!em || !cd){ toast("enter email and code"); return; }
    http("/verify-otp","POST",{email:em, code:cd})
      .then(function(){
        localStorage.setItem("otp_verified","1");
        showPwd(); $("btnLogin").disabled=false; $("uName").focus();
      }).catch(e=>toast(e.message));
  }
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
    var uStr = localStorage.getItem("user");
    var authed = !!localStorage.getItem("jwt");
    if(uStr && authed){
      var o=JSON.parse(uStr);
      $("userBadge").textContent=(o.name||o.username||"")+" • "+(o.role||"");
      $("userBadge").style.display="inline-block";
      $("btnLoginTop").style.display="none";
      $("btnSignout").style.display="inline-block";
      $("btnRefresh").style.display="inline-block";
    }else{
      $("userBadge").style.display="none";
      $("btnLoginTop").style.display="inline-block";
      $("btnSignout").style.display="none";
      $("btnRefresh").style.display="none";
    }
  }

  function refresh(){
    var jwt = localStorage.getItem("jwt");
    if(!jwt){ $("authModal").style.display="flex"; showOtp(); renderUser(); return; }
    http("/instances","GET",null,jwt).then(function(data){
      $("tTotal").textContent   = "Total: "   + data.summary.total;
      $("tRun").textContent     = "Running: " + data.summary.running;
      $("tStop").textContent    = "Stopped: " + data.summary.stopped;
      renderUser();
      renderTabs(data.envs);
    }).catch(function(e){
      $("authModal").style.display="flex"; showOtp();
      toast(e.message || "auth required");
    });
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
    var role=(localStorage.getItem("role")||"read").toLowerCase();

    [["Dream Mapper","DM"],["Encore Anywhere","EA"]].forEach(function(def){
      var title=def[0], key=def[1];
      var list = env[key] || [];
      var box=document.createElement("div"); box.className="box";

      var head=document.createElement("div");
      head.style.display="flex"; head.style.alignItems="center"; head.style.gap="8px"; head.style.marginBottom="8px";
      var lbl=document.createElement("div"); lbl.textContent=title; lbl.style.fontWeight="700";
      head.appendChild(lbl);
      var spacer=document.createElement("div"); spacer.className="right"; head.appendChild(spacer);

      var bStartAll=btn("Start all","ok",function(){ bulk(list,"start"); });
      var bStopAll =btn("Stop all","bad",function(){ bulk(list,"stop"); });
      if(role!=="admin"){ bStartAll.disabled=true; bStopAll.disabled=true; }
      head.appendChild(bStartAll); head.appendChild(bStopAll);
      box.appendChild(head);

      var wrap=document.createElement("div"); wrap.className="stack";
      list.forEach(function(it){
        var line=document.createElement("div"); line.className="rowline";
        var left=document.createElement("div"); left.innerHTML="<b>"+it.name+"</b> <span class='mut'>("+it.id+")</span>";
        line.appendChild(left);

        var st=(it.state||"").toString().toLowerCase().trim();
        var state=document.createElement("div"); state.className="state"; state.textContent=st||"";
        line.appendChild(state);

        if(st==="running"){
          var stop=btn("Stop","bad",function(){ act(it.id,"stop"); });
          if(role!=="admin") stop.disabled=true;
          line.appendChild(stop);
        }else if(st==="stopped"){
          var start=btn("Start","ok",function(){ act(it.id,"start"); });
          if(role!=="admin") start.disabled=true;
          line.appendChild(start);
        }else{
          var wait=btn("…","",function(){}); wait.disabled=true;
          line.appendChild(wait);
        }

        line.appendChild(btn("Services","",function(){ openSvc(it); }));
        wrap.appendChild(line);
      });
      box.appendChild(wrap);
      mount.appendChild(box);
    });
  }

  function btn(tone, css, fn){ var b=document.createElement("button"); b.textContent=tone; b.className="btn small "+css; b.onclick=fn; return b; }
  function act(id,what){
    http("/instance-action","POST",{id:id, action:what}, localStorage.getItem("jwt"))
      .then(()=>setTimeout(refresh,1500))
      .catch(e=>toast(e.message || "action failed"));
  }
  function bulk(list, action){
    var jwt=localStorage.getItem("jwt");
    Promise.all(list.map(function(it){
      return http("/instance-action","POST",{id:it.id, action:action}, jwt).catch(function(){});
    })).then(function(){ setTimeout(refresh,1800); });
  }

  // ------------- Services modal -------------
  var svcCtx={id:"",name:"",type:"svcweb"};
  function openSvc(it){
    svcCtx.id=it.id; svcCtx.name=it.name||"";
    svcCtx.type = (svcCtx.name.toLowerCase().indexOf("sql")>=0) ? "sql" : "svcweb";
    $("svcTitle").textContent="Services on "+svcCtx.name;
    if(svcCtx.type==="sql"){ $("svcFilter").style.display="none"; $("btnSvcRefresh").style.display="none"; $("btnIIS").style.display="none"; $("svcHint").textContent="Showing SQL Server & SQL Agent services."; }
    else{ $("svcFilter").style.display="inline-block"; $("btnSvcRefresh").style.display="inline-block"; $("btnIIS").style.display="inline-block"; $("svcHint").textContent="Type a fragment (e.g. 'w3svc', 'app', 'redis') and press Refresh."; }
    $("svcBody").innerHTML=""; $("svcModal").style.display="flex"; svcRefresh();
  }
  function closeSvc(){ $("svcModal").style.display="none"; }

  function svcRefresh(){
    var body={id:svcCtx.id, mode:"list", instanceName:svcCtx.name}; if(svcCtx.type!=="sql") body.pattern=$("svcFilter").value.trim();
    httpRetry("/services","POST", body, localStorage.getItem("jwt")).then(function(res){
      var mount=$("svcBody"); mount.innerHTML="";
      if(res.error){
        var d=document.createElement("div"); d.className="error";
        d.textContent="SSM error: "+res.error + (res.reason? " ("+res.reason+")": "");
        mount.appendChild(d); return;
      }
      var svcs=res.services||[];
      if(svcCtx.type!=="sql" && !$("svcFilter").value.trim()){
        var d2=document.createElement("div"); d2.className="mut"; d2.textContent="Enter text to filter services."; mount.appendChild(d2); return;
      }
      var g=document.createElement("div"); g.className="grid"; var role=(localStorage.getItem("role")||"read").toLowerCase();
      for(var i=0;i<svcs.length;i++){
        var s=svcs[i]; var st=((""+s.Status)||"").toString(); var stLower=st.toLowerCase();

        var n=document.createElement("div"); n.textContent=s.Name||"";
        var d=document.createElement("div"); d.textContent=s.DisplayName||"";
        var t=document.createElement("div"); t.textContent=st || ""; t.className="mut";

        var start=btn("Start","ok",(function(name){return function(){svcAction("start",name);};})(s.Name));
        var stop =btn("Stop","bad",(function(name){return function(){svcAction("stop",name);};})(s.Name));

        if(role!=="admin"){ start.disabled=true; stop.disabled=true; }
        if(stLower==="running"){ start.style.display="none"; }
        else if(stLower==="stopped"){ stop.style.display="none"; }
        else { start.disabled=true; stop.disabled=true; }

        g.appendChild(n); g.appendChild(d); g.appendChild(t); g.appendChild(start); g.appendChild(stop);
      } mount.appendChild(g);
    }).catch(function(e){ toast(e.message || "internal"); });
  }
  function svcAction(what,name){
    httpRetry("/services","POST",{id:svcCtx.id,mode:what,service:name}, localStorage.getItem("jwt"))
      .then(function(res){
        if(res && res.error){ toast("SSM error: "+res.error+(res.reason? " ("+res.reason+")":"")); return; }
        if(res && res.service && res.service.Status){ toast(name+" → "+res.service.Status); }
        svcRefresh();
      })
      .catch(e=>toast(e.message || "service action failed"));
  }
  function svcIISReset(){
    httpRetry("/services","POST",{id:svcCtx.id,mode:"iisreset"}, localStorage.getItem("jwt"))
      .then(()=>{toast("IIS reset sent"); svcRefresh();})
      .catch(e=>toast(e.message || "failed"));
  }

  (function init(){ renderUser(); $("authModal").style.display="flex"; showOtp(); refresh(); })();
</script>
</body>
</html>
