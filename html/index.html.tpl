<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>EC2 Dashboard</title>
  <style>
    :root{
      --bg:#0e1420; --panel:#0f182a; --line:#243453; --ink:#e5ecff; --muted:#90a7d7;
      --pill:#17233c; --pill-line:#2b3f6a; --btn:#2a3b63; --btn-line:#3a5088;
      --ok:#244e33; --ok-line:#2f7a4d; --bad:#592b2b; --bad-line:#a34b4b;
      --badge:#111a2e; --badge-line:#263656;
    }
    *{box-sizing:border-box}
    body{margin:0;background:var(--bg);color:var(--ink);font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Helvetica,Arial,sans-serif}
    h1,h2,h3{margin:0 0 8px}
    .wrap{max-width:1160px;margin:24px auto;padding:0 12px}
    .row{display:flex;gap:10px;align-items:center}
    .space{justify-content:space-between}
    .badge{background:var(--badge);border:1px solid var(--badge-line);border-radius:12px;padding:6px 10px;color:#a9c1ff;display:inline-flex;gap:8px;align-items:center}
    .btn{background:var(--btn);border:1px solid var(--btn-line);color:var(--ink);border-radius:8px;padding:8px 14px;cursor:pointer}
    .btn:disabled{opacity:.45;cursor:not-allowed}
    .btn.red{background:var(--bad);border-color:var(--bad-line)}
    .btn.green{background:var(--ok);border-color:var(--ok-line)}
    .btn.ghost{background:transparent;border-color:var(--btn-line)}
    .tabs{display:flex;gap:8px;flex-wrap:wrap;margin:12px 0}
    .tab{background:var(--pill);border:1px solid var(--pill-line);padding:8px 12px;border-radius:18px;cursor:pointer}
    .tab.active{outline:2px solid #5272c6}
    .card{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:16px;margin-top:16px;box-shadow:0 0 35px rgba(0,0,0,.25)}
    .grid{display:grid;grid-template-columns:1fr auto auto;gap:10px;align-items:center}
    .muted{color:var(--muted)}
    .chips{display:flex;gap:10px;flex-wrap:wrap}
    .chip{background:var(--pill);border:1px solid var(--pill-line);border-radius:10px;padding:6px 10px}
    .modal{position:fixed;inset:0;display:none;align-items:center;justify-content:center;background:rgba(0,0,0,.55);z-index:10}
    .modal>.inner{background:var(--panel);border:1px solid var(--line);border-radius:18px;max-width:860px;width:94%;padding:18px}
    .input{background:#101a2e;border:1px solid #283a63;color:var(--ink);border-radius:8px;padding:8px 10px}
    .split{display:flex;gap:10px;flex-wrap:wrap}
    .toast{position:fixed;top:12px;right:12px;background:#2b2132;color:#ffd7ef;border:1px solid #5a3c63;padding:8px 10px;border-radius:8px;display:none;z-index:11}
  </style>
</head>
<body>
<div class="wrap">

  <!-- header -->
  <div class="row space">
    <h2>EC2 Dashboard</h2>
    <div class="row">
      <span id="userBadge" class="badge" style="display:none;"></span>
      <button id="signOutBtn" class="btn" style="display:none;">Sign out</button>
      <button id="loginBtn" class="btn">Login</button>
    </div>
  </div>

  <!-- counters -->
  <div class="row space" style="margin-top:12px;">
    <div class="badge">
      <span>Total: <b id="t_total">0</b></span>
      <span>Running: <b id="t_run">0</b></span>
      <span>Stopped: <b id="t_stop">0</b></span>
    </div>
    <div class="row">
      <button id="refreshBtn" class="btn">Refresh</button>
    </div>
  </div>

  <!-- env tabs -->
  <div id="envTabs" class="tabs"></div>

  <!-- env cards -->
  <div id="envBlocks"></div>

</div>

<!-- modal -->
<div id="modal" class="modal">
  <div class="inner">
    <div class="row space" style="margin-bottom:8px;">
      <h3 id="modalTitle" style="margin:0;"></h3>
      <div class="row">
        <button id="ssmPingBtn" class="btn">SSM Ping</button>
        <button id="modalClose" class="btn">Close</button>
      </div>
    </div>

    <div class="split" style="margin:10px 0;">
      <input id="svcFilter" class="input" style="min-width:280px" placeholder="Type to filter (svc/web/sql/agent/ssm/winrm)"/>
      <button id="svcRefresh" class="btn">Refresh</button>
      <button id="iisBtn" class="btn">IIS Reset</button>
      <button id="sqlBtn" class="btn">SQL Info</button>
    </div>

    <div id="svcArea"></div>
  </div>
</div>

<div id="toast" class="toast"></div>

<script>
/* ---------- Config from Terraform ---------- */
const API = "${api_base_url}";
const ENV_NAMES = "${env_names}".split(",").filter(Boolean);
const READ_ONLY_ROLE = "viewer";

/* ---------- State ---------- */
let token = localStorage.getItem("token") || "";
let user  = JSON.parse(localStorage.getItem("user") || "null");
let cacheByEnv = {};
let currentTab = "";
let currentInst = null;

/* ---------- Helpers ---------- */
function toast(msg, ms=3500){ const t=document.getElementById('toast'); t.innerText=msg; t.style.display='block'; setTimeout(()=>t.style.display='none',ms); }
function authz(){ return token ? {"Authorization":"Bearer "+token} : {}; }
function readOnly(){ return !user || !user.role || user.role.toLowerCase()===READ_ONLY_ROLE; }
function showUser(){
  const b=document.getElementById('userBadge'), so=document.getElementById('signOutBtn'), li=document.getElementById('loginBtn');
  if(user && token){ b.style.display='inline-flex'; b.textContent = (user.name||user.username)+" • "+(user.role||""); so.style.display='inline-block'; li.style.display='none'; }
  else{ b.style.display='none'; so.style.display='none'; li.style.display='inline-block'; }
}
function badgeState(state){
  const s=(state||"").toLowerCase();
  if(s==="running") return `<span class="chip" style="border-color:#2e7; background:#173;">running</span>`;
  if(s==="stopped") return `<span class="chip" style="border-color:#e72; background:#431;">stopped</span>`;
  return `<span class="chip">$${state||"unknown"}</span>`;
}

/* ---------- Auth UI ---------- */
document.getElementById('loginBtn').onclick = async ()=>{
  const u = prompt("Username:","admin"); if(!u) return;
  const p = prompt("Password:",""); if(p===null) return;
  try{
    const r = await fetch(API+"/login",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({username:u,password:p})});
    const j = await r.json(); if(!r.ok) throw new Error(j.error || "login failed");
    token=j.token; user=j.user; localStorage.setItem("token",token); localStorage.setItem("user",JSON.stringify(user));
    showUser(); loadInstances();
  }catch(e){ toast(e.message); }
};
document.getElementById('signOutBtn').onclick = ()=>{
  localStorage.removeItem('token'); localStorage.removeItem('user'); token=""; user=null; showUser();
  document.getElementById('envTabs').innerHTML=""; document.getElementById('envBlocks').innerHTML="";
};

/* ---------- Instances ---------- */
document.getElementById('refreshBtn').onclick = ()=>loadInstances();

async function loadInstances(){
  if(!token){ toast("Please login"); return; }
  try{
    const r = await fetch(API+"/instances",{headers:authz()});
    const j = await r.json(); if(!r.ok) throw new Error(j.error||"internal");
    document.getElementById('t_total').innerText=j.summary.total;
    document.getElementById('t_run').innerText=j.summary.running;
    document.getElementById('t_stop').innerText=j.summary.stopped;

    cacheByEnv = j.envs || {};
    const envList = ENV_NAMES.length ? ENV_NAMES : Object.keys(cacheByEnv);
    const tabs = envList.map(e => `<div class="tab $${currentTab===e ? "active":""}" data-tab="$${e}">$${e}</div>`).join("");
    document.getElementById('envTabs').innerHTML = tabs;
    if(!currentTab && envList.length) currentTab = envList[0];
    document.querySelectorAll('[data-tab]').forEach(el => el.onclick = (ev)=>{ currentTab = ev.target.getAttribute('data-tab'); renderEnvCards(); });

    renderEnvCards();
  }catch(e){ toast(e.message); }
}

function renderEnvCards(){
  const env = currentTab;
  const data = cacheByEnv[env] || {DM:[],EA:[]};
  const blocks = [];
  for(const block of ["Dream Mapper","Encore Anywhere"]){
    const key = block.startsWith("Dream") ? "DM" : "EA";
    const arr = data[key] || [];
    const canBulk = !readOnly() && arr.length>0;
    const hdr =
      `<div class="row space"><h3>$${block}</h3>
        <div class="row">
          <button class="btn green" data-bulk='$${JSON.stringify({env,blk:key,action:"start"})}' $${canBulk?"":"disabled"}>Start All</button>
          <button class="btn red" data-bulk='$${JSON.stringify({env,blk:key,action:"stop"})}'  $${canBulk?"":"disabled"}>Stop All</button>
        </div>
      </div>`;

    const rows = arr.map(it => instRow(it)).join("") || `<div class="muted">No instances</div>`;
    blocks.push(`<div class="card">$${hdr}$${rows}</div>`);
  }
  document.getElementById('envBlocks').innerHTML = blocks.join("");

  document.querySelectorAll('[data-bulk]').forEach(b => b.onclick = async (e)=>{
    if(readOnly()) return;
    const cfg = JSON.parse(e.currentTarget.getAttribute('data-bulk'));
    await bulkAction(cfg.env, cfg.blk, cfg.action);
  });
  wireInstanceButtons();
}

function instRow(it){
  const isRunning = (it.state||"").toLowerCase()==="running";
  const startDis = readOnly() || isRunning ? "disabled":"";
  const stopDis  = readOnly() || !isRunning ? "disabled":"";
  return `<div class="grid" style="margin-top:8px; border-top:1px solid var(--line); padding-top:8px;">
    <div><b>$${it.name}</b> <span class="muted">( $${it.id} )</span></div>
    <div>$${badgeState(it.state)}</div>
    <div class="row" style="justify-content:flex-end; gap:8px;">
      <button class="btn green" data-start="$${it.id}" $${startDis}>Start</button>
      <button class="btn red" data-stop="$${it.id}"  $${stopDis}>Stop</button>
      <button class="btn" data-services='$${JSON.stringify(it)}'>Services</button>
    </div>
  </div>`;
}

function wireInstanceButtons(){
  document.querySelectorAll("[data-start]").forEach(b => b.onclick = async (e)=>{
    if(readOnly()) return;
    const id=e.currentTarget.getAttribute("data-start");
    await instAction(id,"start");
  });
  document.querySelectorAll("[data-stop]").forEach(b => b.onclick = async (e)=>{
    if(readOnly()) return;
    const id=e.currentTarget.getAttribute("data-stop");
    await instAction(id,"stop");
  });
  document.querySelectorAll("[data-services]").forEach(b => b.onclick = (e)=>{
    const it = JSON.parse(e.currentTarget.getAttribute("data-services"));
    openModal(it);
  });
}

async function instAction(id, action){
  try{
    const r=await fetch(API+"/instance-action",{method:"POST",headers:{...authz(),"content-type":"application/json"},body:JSON.stringify({id,action})});
    const j=await r.json(); if(!r.ok) throw new Error(j.error||"internal");
    toast(`${action} requested`);
    await loadInstances();
  }catch(e){ toast(e.message); }
}

async function bulkAction(env, blk, action){
  const arr = (cacheByEnv[env] && cacheByEnv[env][blk]) ? cacheByEnv[env][blk] : [];
  for(const it of arr){
    if(action==="start" && (it.state||"").toLowerCase()==="running") continue;
    if(action==="stop"  && (it.state||"").toLowerCase()!=="running") continue;
    try{
      await fetch(API+"/instance-action",{method:"POST",headers:{...authz(),"content-type":"application/json"},body:JSON.stringify({id:it.id,action})});
    }catch(_){}
  }
  toast(`${action} requested for ${blk} in ${env}`);
  setTimeout(loadInstances, 1500);
}

/* ---------- Services Modal ---------- */
function openModal(inst){
  currentInst = inst;
  document.getElementById('modalTitle').innerText = `Services on $${inst.name}`;
  document.getElementById('svcArea').innerHTML = '';
  document.getElementById('modal').style.display='flex';
  document.getElementById('iisBtn').disabled = readOnly();
  fetchServices("");
}

document.getElementById('modalClose').onclick = ()=>{ document.getElementById('modal').style.display='none'; };
document.getElementById('svcRefresh').onclick = ()=> fetchServices(document.getElementById('svcFilter').value.trim());

document.getElementById('ssmPingBtn').onclick = async ()=>{
  if(!currentInst) return;
  const r = await fetch(API+"/ssm-ping",{method:"POST",headers:{...authz(),"content-type":"application/json"},body:JSON.stringify({id:currentInst.id})});
  const j = await r.json(); if(!r.ok){ toast(j.error||"internal"); return; }
  toast(`Host: $${j.ping.Host} @ $${j.ping.Time}`);
};

document.getElementById('iisBtn').onclick = async ()=>{
  if(readOnly() || !currentInst) return;
  const r = await fetch(API+"/services",{method:"POST",headers:{...authz(),"content-type":"application/json"},body:JSON.stringify({id:currentInst.id,mode:"iisreset"})});
  const j = await r.json(); if(!r.ok){ toast(j.error||"internal"); return; }
  renderServices(j.services);
};

document.getElementById('sqlBtn').onclick = async ()=>{
  if(!currentInst) return;
  const r = await fetch(API+"/services",{method:"POST",headers:{...authz(),"content-type":"application/json"},body:JSON.stringify({id:currentInst.id,mode:"sqlinfo"})});
  const j = await r.json(); if(!r.ok){ toast(j.error||"internal"); return; }
  const s = j.services || [];
  const os = j.os || {};
  const vers = (j.sql||[]).map(x => `<span class="chip">SQL $${x.Instance} — $${x.Version} ($${x.PatchLevel})</span>`).join(" ");
  const svc = Array.isArray(s) ? s : (s ? [s] : []);
  document.getElementById('svcArea').innerHTML =
    `<div class="chips" style="margin-bottom:8px;">
       <span class="chip">OS: $${os.Caption||"?"} $${os.Version||""} ($${os.BuildNumber||""})</span>
       $${vers || `<span class="muted">No SQL version data</span>`}
     </div>
     $${svc.map(row => svcRow(row)).join("")}`;
};

async function fetchServices(pattern){
  if(!currentInst) return;
  const r = await fetch(API+"/services",{method:"POST",headers:{...authz(),"content-type":"application/json"},body:JSON.stringify({id:currentInst.id,mode:"list",pattern})});
  const j = await r.json();
  if(!r.ok){ document.getElementById('svcArea').innerHTML = `<div class="muted">$${j.error||"internal"}</div>`; return; }
  renderServices(j.services);
}

function renderServices(list){
  const arr = Array.isArray(list) ? list : (list ? [list] : []);
  if(arr.length===0){ document.getElementById('svcArea').innerHTML = `<div class="muted">No matching services</div>`; return; }
  document.getElementById('svcArea').innerHTML = arr.map(row => svcRow(row)).join("");
  wireSvcButtons();
}

function svcRow(row){
  const name=row.Name||row.name||"?"; const st=(row.Status||"").toLowerCase();
  const on = st==="running";
  const startDis = readOnly() || on ? "disabled":"";
  const stopDis  = readOnly() || !on ? "disabled":"";
  return `<div class="row space" style="border-top:1px solid var(--line); padding:8px 2px; margin-top:4px;">
    <div><b>$${name}</b> <span class="muted">$${st||"unknown"}</span></div>
    <div class="row" style="gap:8px;">
      <button class="btn green" data-sstart="$${name}" $${startDis}>Start</button>
      <button class="btn red" data-sstop="$${name}"  $${stopDis}>Stop</button>
    </div>
  </div>`;
}

function wireSvcButtons(){
  document.querySelectorAll("[data-sstart]").forEach(b => b.onclick = async (e)=>{
    if(readOnly()) return;
    const svc=e.currentTarget.getAttribute("data-sstart");
    const r=await fetch(API+"/services",{method:"POST",headers:{...authz(),"content-type":"application/json"},body:JSON.stringify({id:currentInst.id,mode:"start",service:svc})});
    const j=await r.json(); if(!r.ok){ toast(j.error||"internal"); return; }
    renderServices(j.services);
  });
  document.querySelectorAll("[data-sstop]").forEach(b => b.onclick = async (e)=>{
    if(readOnly()) return;
    const svc=e.currentTarget.getAttribute("data-sstop");
    const r=await fetch(API+"/services",{method:"POST",headers:{...authz(),"content-type":"application/json"},body:JSON.stringify({id:currentInst.id,mode:"stop",service:svc})});
    const j=await r.json(); if(!r.ok){ toast(j.error||"internal"); return; }
    renderServices(j.services);
  });
}

/* ---------- boot ---------- */
showUser();
if(token) loadInstances();
</script>
</body>
</html>
