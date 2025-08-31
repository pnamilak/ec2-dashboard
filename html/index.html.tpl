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
    .grid{display:grid;grid-template-columns:1fr 1fr 120px 120px;gap:10px}
    input,select{background:#0f1a2e;border:1px solid #243355;color:#e6e9ef;border-radius:10px;padding:8px 10px}
    .error{background:#2b1620;color:#ffd9de;border:1px solid #5a2533;border-radius:10px;padding:8px 10px}
    a { color:#a8e0ff; }
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
    <!-- No Login/Sign out buttons pre-auth; OTP drives the flow -->
    <button class="btn small" id="btnRefreshTop" onclick="refresh()" style="display:none">Refresh</button>
  </div>

  <div class="tabs row" id="envTabs"></div>

  <div id="envMount"></div>
</div>

<!-- Services modal -->
<div class="modal" id="svcModal">
  <div class="card">
    <div class="row" style="margin-bottom:10px">
      <div id="svcTitle" style="font-weight:700">Services</div>
      <div class="right"></div>
      <input id="svcFilter" placeholder="Type to filter (e.g. 'w3svc', 'app', 'redis') and press Refresh" style="width:320px;display:none">
      <button class="btn small" id="btnRefresh" onclick="svcRefresh()" style="display:none">Refresh</button>
      <button class="btn small" id="btnIIS" onclick="svcIISReset()" style="display:none">IIS Reset</button>
      <button class="btn small" onclick="closeSvc()">Back</button>
    </div>
    <div class="mut" id="svcHint" style="margin-bottom:8px"></div>
    <div id="svcBody"></div>
  </div>
</div>

<!-- OTP modal (email-only) -->
<div class="modal" id="otpModal">
  <div class="card" style="max-width:620px">
    <div style="font-weight:700;margin-bottom:8px">Verify your email</div>
    <div class="row" style="gap:10px">
      <input id="otpEmail" placeholder="name@${allowed_email_domain}" style="width:320px">
      <button class="btn" onclick="requestOtp()">Request OTP</button>
    </div>
    <div class="row" style="gap:10px;margin-top:10px">
      <input id="otpCode" placeholder="6-digit code" style="width:160px">
      <button class="btn" onclick="verifyOtp()">Verify OTP</button>
    </div>
    <div class="mut" style="margin-top:8px">Allowed domain: ${allowed_email_domain}. After verifying OTP you'll be redirected to the credential page.</div>
  </div>
</div>

<script>
  var API = "${api_base_url}";
  var ENV_NAMES = "${env_names}".split(",");

  function http(path, method, obj, bearer){
    var h = {"content-type":"application/json"};
    if(bearer){ h["authorization"] = "Bearer " + bearer; }
    return fetch(API + path, {method:method, headers:h, body: obj? JSON.stringify(obj): undefined})
      .then(async function(r){
        const txt = await r.text();
        let data={}; try{ data = txt? JSON.parse(txt): {}; }catch(e){ data={raw:txt}; }
        if(!r.ok){ const msg = (data && (data.error||data.message||txt)) || ("http " + r.status); throw new Error(msg); }
        return data;
      });
  }
  function $(id){ return document.getElementById(id); }
  function toast(msg){ alert(msg); }

  // ---------- OTP flow ----------
  function requestOtp(){
    var em = $("otpEmail").value.trim();
    if(!em){ toast("Enter email"); return; }
    http("/request-otp","POST",{email:em}).then(()=>toast("OTP sent")).catch(e=>toast(e.message));
  }
  function verifyOtp(){
    var em = $("otpEmail").value.trim(), cd = $("otpCode").value.trim();
    if(!em || !cd){ toast("Enter email and code"); return; }
    http("/verify-otp","POST",{email:em, code:cd})
      .then(function(res){
        // store short-lived OVT (one-time verifier token) for 5 minutes
        localStorage.setItem("ovt", res.ovt);
        localStorage.setItem("ovt_exp", (Date.now()+5*60*1000).toString());
        window.location.href = "login.html";
      }).catch(e=>toast(e.message));
  }

  // ---------- App ----------
  function renderUser(){
    var u = localStorage.getItem("user");
    if(u){ var o=JSON.parse(u); $("userBadge").textContent=(o.name||o.username||"")+" • "+(o.role||""); $("userBadge").style.display="inline-block"; $("btnRefreshTop").style.display="inline-block"; }
    else{ $("userBadge").style.display="none"; $("btnRefreshTop").style.display="none"; }
  }

  function refresh(){
    var jwt = localStorage.getItem("jwt");
    if(!jwt){ $("otpModal").style.display="flex"; return; }
    http("/instances","GET",null,jwt).then(function(data){
      $("tTotal").textContent="Total: "+data.summary.total;
      $("tRun").textContent="Running: "+data.summary.running;
      $("tStop").textContent="Stopped: "+data.summary.stopped;
      renderTabs(data.envs);
    }).catch(function(){ $("otpModal").style.display="flex"; });
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
    [["Dream Mapper","DM"],["Encore Anywhere","EA"]].forEach(function(pair){
      var title=pair[0], key=pair[1]; var list=env[key]||[];
      var box=document.createElement("div"); box.className="box";
      box.innerHTML="<div style='font-weight:700;margin-bottom:8px'>"+title+" <span class='right'></span></div>";
      var headerRow=document.createElement("div"); headerRow.className="row"; headerRow.style.marginBottom="8px";
      var startAll=btn("Start all","ok",function(){ bulkAction(list,"start"); });
      var stopAll =btn("Stop all","bad",function(){ bulkAction(list,"stop"); });
      headerRow.appendChild(startAll); headerRow.appendChild(stopAll);
      box.appendChild(headerRow);

      var wrap=document.createElement("div"); wrap.className="stack";
      list.forEach(function(it){
        var line=document.createElement("div"); line.className="rowline";
        var left=document.createElement("div"); left.innerHTML="<b>"+it.name+"</b> <span class='mut'>("+it.id+")</span>";
        line.appendChild(left);
        var state=document.createElement("div"); state.className="state"; state.textContent=(it.state||"");
        line.appendChild(state);
        var stBtn=btn("Start","ok",function(){ act(it.id,"start"); }); var spBtn=btn("Stop","bad",function(){ act(it.id,"stop"); });
        if((it.state||"").toLowerCase()==="running"){ stBtn.style.display="none"; } else { spBtn.style.display="none"; }
        line.appendChild(stBtn); line.appendChild(spBtn);
        line.appendChild(btn("Services","",function(){ openSvc(it); }));
        wrap.appendChild(line);
      });
      box.appendChild(wrap); mount.appendChild(box);
    });
  }
  function btn(tone, css, fn){ var b=document.createElement("button"); b.textContent=tone; b.className="btn small "+css; b.onclick=fn; return b; }
  function act(id,what){ http("/instance-action","POST",{id:id, action:what}, localStorage.getItem("jwt")).then(()=>setTimeout(refresh,1200)).catch(e=>toast(e.message)); }
  function bulkAction(list,what){ list.forEach(function(it){ act(it.id,what); }); }

  // ---------- Service modal ----------
  var svcCtx={id:"",name:"",type:"svcweb"};
  function normStatus(s){
    if(s===4||s==="4") return "running";
    if(s===1||s==="1") return "stopped";
    return (""+s).toLowerCase();
  }
  function openSvc(it){
    svcCtx.id=it.id; svcCtx.name=it.name||""; var nm=(svcCtx.name.toLowerCase());
    svcCtx.type = nm.indexOf("sql")>=0 ? "sql" : "svcweb";
    $("svcTitle").textContent="Services on "+svcCtx.name;
    if(svcCtx.type==="sql"){ $("svcFilter").style.display="none"; $("btnRefresh").style.display="none"; $("btnIIS").style.display="none"; $("svcHint").textContent="Showing SQL Server & SQL Agent services."; }
    else{ $("svcFilter").style.display="inline-block"; $("btnRefresh").style.display="inline-block"; $("btnIIS").style.display="inline-block"; $("svcHint").textContent="Type at least 2 letters (e.g. 'w3', 'app', 'redis') and press Refresh."; }
    $("svcBody").innerHTML=""; $("svcModal").style.display="flex"; svcRefresh();
  }
  function closeSvc(){ $("svcModal").style.display="none"; }
  document.addEventListener("keydown", function(e){ if(e.key==="Escape"){ closeSvc(); $("otpModal").style.display="none"; }});

  function svcRefresh(){
    var body={id:svcCtx.id, mode:"list", instanceName:svcCtx.name};
    if(svcCtx.type!=="sql"){
      var pat=$("svcFilter").value.trim();
      if(pat.length<2){ $("svcBody").innerHTML="<div class='mut'>Enter ≥2 letters and press Refresh.</div>"; return; }
      body.pattern=pat;
    }
    http("/services","POST", body, localStorage.getItem("jwt")).then(function(res){
      var mount=$("svcBody"); mount.innerHTML="";
      if(res.error){
        var tip=""; if((res.error||"").startsWith("invocation_")) tip="SSM run command error on instance."; 
        if(res.error==="not_connected") tip="SSM target not connected. Check SSM Agent, network/VPC endpoints and instance profile.";
        else if(res.error==="denied") tip="SSM access denied. Confirm Lambda role and instance profile permissions.";
        var d=document.createElement("div"); d.className="error"; d.textContent="SSM error: "+res.error+(res.reason? " ("+res.reason+")":"")+". "+tip; mount.appendChild(d); return;
      }
      var svcs=res.services||[];
      var g=document.createElement("div"); g.className="grid";
      // header
      ["Service","Display Name","Status","Action"].forEach(function(h){ var x=document.createElement("div"); x.style.fontWeight="700"; x.textContent=h; g.appendChild(x); });
      var role=(localStorage.getItem("role")||"read").toLowerCase();
      for(var i=0;i<svcs.length;i++){
        var s=svcs[i]; var st=normStatus(s.Status||s.status||"");
        var n=document.createElement("div"); n.textContent=s.Name||""; 
        var d=document.createElement("div"); d.textContent=s.DisplayName||"";
        var stc=document.createElement("div"); stc.textContent=st||"";
        var action=document.createElement("div");
        var canAdmin=(role==="admin");
        var start=btn("Start","ok", (function(name){return function(){svcAction("start",name);};})(s.Name));
        var stop =btn("Stop" ,"bad",(function(name){return function(){svcAction("stop",name); };})(s.Name));
        if(!canAdmin){ start.disabled=true; stop.disabled=true; }
        if(st==="running"){ start.style.display="none"; }
        else if(st==="stopped"){ stop.style.display="none"; }
        action.appendChild(start); action.appendChild(stop);
        [n,d,stc,action].forEach(function(x){ g.appendChild(x); });
      }
      mount.appendChild(g);
    }).catch(e=>toast(e.message));
  }
  function svcAction(what,name){ http("/services","POST",{id:svcCtx.id,mode:what,service:name}, localStorage.getItem("jwt")).then(()=>svcRefresh()).catch(e=>toast(e.message)); }
  function svcIISReset(){ http("/services","POST",{id:svcCtx.id,mode:"iisreset"}, localStorage.getItem("jwt")).then(()=>{toast("IIS reset sent");}).catch(e=>toast(e.message)); }

  (function init(){ renderUser(); $("otpModal").style.display="flex"; refresh(); })();
</script>
</body>
</html>
