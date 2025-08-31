<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>EC2 Dashboard</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <style>
    :root{
      --bg:#0e1624; --panel:#121b2b; --ink:#e6e9ef; --mut:#9aa4b2;
      --ok:#2e9762; --bad:#b94a4a; --chip:#19243a; --brand:#7b8cff
    }
    html,body{height:100%}
    body{margin:0;background:var(--bg);color:var(--ink);font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,"Helvetica Neue",sans-serif}

    .wrap{max-width:1100px;margin:28px auto;padding:0 16px}
    .row{display:flex;gap:10px;flex-wrap:wrap}
    .tile{background:var(--chip);padding:14px 18px;border-radius:14px;font-weight:700;box-shadow:0 0 0 1px #1c2840 inset}
    .tile.big{font-size:24px}

    .tabs{display:flex;gap:10px;margin:14px 0}
    .tab{background:var(--chip);padding:8px 14px;border-radius:12px;cursor:pointer}
    .tab.active{outline:2px solid var(--brand)}

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

    /* OTP gate */
    body.gated{ background:var(--bg); }
    #gate{
      position:fixed; inset:0; display:none;
      align-items:center; justify-content:center;
      background:var(--bg); z-index:50;
    }
    body.gated #gate{ display:flex; }
    body.gated #app{ display:none; }
    .gate-card{background:var(--panel);border-radius:16px;padding:18px;box-shadow:0 0 0 1px #1c2840 inset; width:min(720px,92vw)}
    .gate-row{display:flex;gap:10px;align-items:center;margin-top:10px}

    .modal{position:fixed;inset:0;background:rgba(0,0,0,.55);display:none;align-items:center;justify-content:center;padding:16px;z-index:20}
    .modal .card{background:var(--panel);border-radius:14px;padding:16px;max-width:980px;width:100%}
    .grid{display:grid;grid-template-columns:1fr 1fr 90px 90px;gap:10px}
    input,select{background:#0f1a2e;border:1px solid #243355;color:#e6e9ef;border-radius:10px;padding:8px 10px}
    .error{background:#2b1620;color:#ffd9de;border:1px solid #5a2533;border-radius:10px;padding:8px 10px}
  </style>
</head>

<body class="gated">
<!-- OTP modal -->
<div id="gate">
  <div class="gate-card">
    <div style="font-size:20px;font-weight:700;margin-bottom:8px">Verify your email</div>
    <div class="mut" style="margin-bottom:10px">Allowed domain: ${allowed_email_domain}. After verifying OTP you’ll be redirected to the credential page.</div>
    <div class="gate-row">
      <input id="otpEmail" placeholder="name@${allowed_email_domain}" style="flex:1">
      <button class="btn" onclick="requestOtp()">Request OTP</button>
    </div>
    <div class="gate-row">
      <input id="otpCode" placeholder="6-digit code" style="width:180px">
      <button class="btn ok" onclick="verifyOtp()">Verify OTP</button>
      <div id="otpMsg" class="mut"></div>
    </div>
  </div>
</div>

<!-- App -->
<div class="wrap" id="app">
  <div class="row">
    <div class="tile big" id="tTotal">Total: 0</div>
    <div class="tile big" id="tRun">Running: 0</div>
    <div class="tile big" id="tStop">Stopped: 0</div>
    <div class="right"></div>
    <div class="chip" id="userBadge" style="display:none"></div>
    <button class="btn small" onclick="logout()" id="btnSignout" style="display:none">Sign out</button>
    <button class="btn small" onclick="refresh()" id="btnRefresh" style="display:none">Refresh</button>
  </div>
  <div class="tabs" id="envTabs"></div>
  <div id="envMount"></div>
</div>

<!-- Services Modal -->
<div class="modal" id="svcModal">
  <div class="card">
    <div class="row" style="margin-bottom:10px">
      <div id="svcTitle" style="font-weight:700">Services</div>
      <div class="right"></div>
      <input id="svcFilter" placeholder="Type to filter (Name or DisplayName)" style="width:260px;display:none">
      <button class="btn small" id="btnRefreshSvc" onclick="svcRefresh()" style="display:none">Refresh</button>
      <button class="btn small" id="btnIIS" onclick="svcIISReset()" style="display:none">IIS Reset</button>
      <button class="btn small" onclick="closeSvc()">Back</button>
    </div>
    <div id="svcBody"></div>
    <div id="svcHint" class="mut" style="margin-top:10px"></div>
  </div>
</div>

<script>
  // ===== Template values =====
  const API = "${api_base_url}";
  const ENV_NAMES = "${env_names},Dev".split(",").map(s=>s.trim()).filter(Boolean);
  try { localStorage.setItem("api_base_url", API); } catch(_) {}

  // ===== Helpers =====
  const $ = (id)=>document.getElementById(id);
  const toast = (m)=>alert(m);
  const gateOn  = ()=>document.body.classList.add("gated");
  const gateOff = ()=>document.body.classList.remove("gated");

  function http(path, method, obj, bearer){
    const h={"content-type":"application/json"};
    if(bearer){ h["authorization"]="Bearer "+bearer; }
    return fetch(API+path,{method,headers:h,body:obj?JSON.stringify(obj):undefined})
      .then(async r=>{
        const data = await r.json().catch(()=> ({}));
        if(!r.ok){ const msg=(data && (data.error||data.message)) || ("http "+r.status); throw new Error(msg); }
        return data;
      });
  }

  function logout(){
    ["jwt","role","user","otp_email"].forEach(k=>{
      try { localStorage.removeItem(k); sessionStorage.removeItem(k); } catch(_){}
    });
    gateOn();
    renderUser();
  }

  function renderUser(){
    let u=null; try{ u=JSON.parse(localStorage.getItem("user")||"null"); }catch(_){}
    const has = !!localStorage.getItem("jwt");
    $("userBadge").style.display   = has && u ? "inline-block" : "none";
    $("btnSignout").style.display  = has ? "inline-block" : "none";
    $("btnRefresh").style.display  = has ? "inline-block" : "none";
    if(has && u){ $("userBadge").textContent=(u.name||u.username||"")+" • "+(u.role||""); }
  }

  // ===== OTP actions =====
  function requestOtp(){
    const em = $("otpEmail").value.trim().toLowerCase();
    if(!em){ $("otpMsg").textContent="Enter your email."; return; }
    $("otpMsg").textContent="Sending…";
    http("/request-otp","POST",{email:em})
      .then(()=>{$("otpMsg").textContent="OTP sent to "+em;})
      .catch(e=>{$("otpMsg").textContent=e.message;});
  }

  function verifyOtp(){
    const em = $("otpEmail").value.trim().toLowerCase();
    const cd = $("otpCode").value.trim();
    if(!em || !cd){ $("otpMsg").textContent="Enter email and code."; return; }
    $("otpMsg").textContent="Verifying…";
    http("/verify-otp","POST",{email:em, code:cd})
      .then(()=>{
        // put in BOTH storages and also put in the URL for login.html (belt & suspenders)
        try { sessionStorage.setItem("otp_email", em); localStorage.setItem("otp_email", em); } catch(_){}
        const ts = Date.now();
        window.location.href = "/login.html?e="+encodeURIComponent(em)+"&ts="+ts;
      })
      .catch(e=>{$("otpMsg").textContent=e.message;});
  }

  // ===== Dashboard =====
  function refresh(){
    const jwt = localStorage.getItem("jwt");
    if(!jwt){ gateOn(); renderUser(); return; }
    http("/instances","GET",null,jwt)
      .then(data=>{
        gateOff();
        $("tTotal").textContent  = "Total: "   + data.summary.total;
        $("tRun").textContent    = "Running: " + data.summary.running;
        $("tStop").textContent   = "Stopped: " + data.summary.stopped;
        renderUser();
        renderTabs(data.envs);
      })
      .catch(err=>{
        if(err.message==="unauthorized" || err.message.startsWith("http 401")){
          logout();
        }else{
          toast(err.message);
        }
      });
  }

  function renderTabs(envs){
    const tabs=$("envTabs"); tabs.innerHTML="";
    ENV_NAMES.forEach(function(e,i){
      const b=document.createElement("div"); b.className="tab"; b.textContent=e;
      b.onclick=function(){ drawEnv(envs[e]||{DM:[],EA:[]}); setActive(i); };
      tabs.appendChild(b);
    });
    setActive(0); drawEnv(envs[ENV_NAMES[0]]||{DM:[],EA:[]});
    function setActive(idx){ tabs.querySelectorAll(".tab").forEach((n,k)=>n.classList.toggle("active",k===idx)); }
  }

  function drawEnv(env){
    const mount=$("envMount"); mount.innerHTML="";
    [["Dream Mapper","DM"],["Encore Anywhere","EA"]].forEach(([section,key])=>{
      const box=document.createElement("div"); box.className="box";
      const head=document.createElement("div"); head.textContent=section; head.style.fontWeight="700"; head.style.marginBottom="8px"; box.appendChild(head);

      const actions=document.createElement("div"); actions.className="row"; actions.style.margin="6px 0 10px 0";
      const bStartAll=btn("Start all","ok",()=>bulkAction(env[key]||[],"start"));
      const bStopAll=btn("Stop all","bad",()=>bulkAction(env[key]||[],"stop"));
      actions.appendChild(bStartAll); actions.appendChild(bStopAll);
      box.appendChild(actions);

      const list= env[key]||[];
      const wrap=document.createElement("div"); wrap.className="stack";
      list.forEach(function(it){
        const line=document.createElement("div"); line.className="rowline";
        const left=document.createElement("div"); left.innerHTML="<b>"+it.name+"</b> <span class='mut'>("+it.id+")</span>"; line.appendChild(left);
        const state=(it.state||"").toLowerCase();
        const stateEl=document.createElement("div"); stateEl.className="state"; stateEl.textContent=state; line.appendChild(stateEl);

        if(state==="running"){ line.appendChild(btn("Stop","bad",()=>act(it.id,"stop"))); }
        else                 { line.appendChild(btn("Start","ok",()=>act(it.id,"start"))); }
        line.appendChild(btn("Services","",()=>openSvc(it)));
        wrap.appendChild(line);
      });
      box.appendChild(wrap); mount.appendChild(box);
    });
  }

  function btn(label, css, fn){ const b=document.createElement("button"); b.textContent=label; b.className="btn small "+css; b.onclick=fn; return b; }
  function act(id, what){
    http("/instance-action","POST",{id,action:what}, localStorage.getItem("jwt"))
      .then(()=>setTimeout(refresh,1200)).catch(e=>toast(e.message||"action failed"));
  }
  function bulkAction(items,what){
    const ids=items.map(x=>x.id);
    let p=Promise.resolve();
    ids.forEach(id=>{ p=p.then(()=>http("/instance-action","POST",{id,action:what}, localStorage.getItem("jwt")).catch(()=>{})); });
    p.then(()=>setTimeout(refresh,1500));
  }

  // ===== Services =====
  const svcCtx={id:"",name:"",type:"svcweb"};
  function openSvc(it){
    svcCtx.id=it.id; svcCtx.name=it.name||"";
    const nm=(svcCtx.name||"").toLowerCase();
    svcCtx.type = nm.includes("sql") ? "sql" : "svcweb";
    $("svcTitle").textContent="Services on "+svcCtx.name;

    if(svcCtx.type==="sql"){
      $("svcFilter").style.display="none";
      $("btnRefreshSvc").style.display="none";
      $("btnIIS").style.display="none";
      $("svcHint").textContent="Showing SQL Server & SQL Agent services.";
    }else{
      $("svcFilter").style.display="inline-block";
      $("btnRefreshSvc").style.display="inline-block";
      $("btnIIS").style.display="inline-block";
      $("svcHint").textContent="Type a fragment (e.g. 'w3svc', 'app', 'redis') then press Refresh. Press Esc to close.";
    }
    $("svcBody").innerHTML="";
    $("svcModal").style.display="flex";
    svcRefresh();
  }
  function closeSvc(){ $("svcModal").style.display="none"; }

  document.addEventListener("keydown", (e)=>{
    if(e.key==="Escape" && $("svcModal").style.display==="flex"){ closeSvc(); }
    if(e.key==="Enter" && $("svcModal").style.display==="flex" && svcCtx.type!=="sql"){ svcRefresh(); }
  });

  function svcRefresh(){
    const body={id:svcCtx.id, mode:"list", instanceName:svcCtx.name};
    if(svcCtx.type!=="sql"){ body.pattern=$("svcFilter").value.trim(); }
    http("/services","POST", body, localStorage.getItem("jwt")).then(function(res){
      const mount=$("svcBody"); mount.innerHTML="";
      if(res.error){
        let tip="";
        if(res.error==="not_connected"){ tip="SSM target not connected. Check SSM Agent and IAM instance profile."; }
        else if(res.error==="denied"){ tip="SSM access denied. Check Lambda role and instance profile permissions."; }
        const d=document.createElement("div"); d.className="error"; d.textContent="SSM error: "+res.error+(res.reason? " ("+res.reason+")":"")+". "+tip; mount.appendChild(d); return;
      }
      let svcs = Array.isArray(res.services)? res.services : [];
      if(svcCtx.type!=="sql" && !$("svcFilter").value.trim()){
        const msg=document.createElement("div"); msg.className="mut"; msg.textContent="Enter text to filter services."; mount.appendChild(msg); return;
      }
      const g=document.createElement("div"); g.className="grid";
      svcs.forEach(s=>{
        const name=(s.Name||"").toString();
        const disp=(s.DisplayName||"").toString();
        const st=(s.Status||"").toString().toLowerCase(); // running / stopped
        const n=document.createElement("div"); n.textContent=name;
        const d=document.createElement("div"); d.textContent=disp||"";
        const bStart=btn("Start","ok",()=>svcAction("start",name));
        const bStop =btn("Stop","bad",()=>svcAction("stop", name));
        if(st==="running"){ bStart.disabled=true; } else { bStop.disabled=true; }
        g.appendChild(n); g.appendChild(d); g.appendChild(bStart); g.appendChild(bStop);
      });
      mount.appendChild(g);
    }).catch(()=>toast("internal error"));
  }

  function svcAction(what,name){
    http("/services","POST",{id:svcCtx.id, mode:what, service:name}, localStorage.getItem("jwt"))
      .then(()=>svcRefresh()).catch(()=>toast("service action failed"));
  }
  function svcIISReset(){
    http("/services","POST",{id:svcCtx.id, mode:"iisreset"}, localStorage.getItem("jwt"))
      .then(()=>{toast("IIS reset sent"); svcRefresh();}).catch(()=>toast("failed"));
  }

  // ===== Boot =====
  (function init(){
    renderUser();
    refresh(); // gate stays on until /instances succeeds with a valid JWT
  })();
</script>
</body>
</html>
