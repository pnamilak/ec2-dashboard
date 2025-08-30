<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>EC2 Dashboard</title>
  <style>
    body{background:#0e1420;color:#e5ecff;font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Helvetica,Arial,sans-serif;margin:0}
    .wrap{max-width:1100px;margin:24px auto;padding:0 12px}
    .row{display:flex;align-items:center;gap:10px;justify-content:space-between}
    .badge{background:#111a2e;border:1px solid #263656;border-radius:12px;padding:6px 10px;color:#a9c1ff}
    .btn{background:#2a3b63;border:1px solid #3a5088;color:#e5ecff;border-radius:8px;padding:8px 14px;cursor:pointer}
    .btn:disabled{opacity:.45;cursor:not-allowed}
    .btn.red{background:#592b2b;border-color:#a34b4b}
    .btn.green{background:#244e33;border-color:#2f7a4d}
    .card{background:#0f182a;border:1px solid #243453;border-radius:16px;padding:16px;margin-top:16px;box-shadow:0 0 35px rgba(0,0,0,.25)}
    .pill{background:#17233c;border:1px solid #2b3f6a;border-radius:18px;padding:8px 12px;margin-right:8px;display:inline-block}
    .grid{display:grid;grid-template-columns:1fr auto auto;gap:10px;align-items:center}
    .muted{color:#90a7d7}
    .right{float:right}
    .modal{position:fixed;inset:0;display:none;align-items:center;justify-content:center;background:rgba(0,0,0,.55)}
    .modal>.inner{background:#0f182a;border:1px solid #243453;border-radius:18px;max-width:780px;width:92%;padding:18px}
    .tok{background:#192544;border:1px solid #2b3f6a;border-radius:10px;padding:6px 8px;display:inline-block;margin:4px 6px}
    .input{background:#101a2e;border:1px solid #283a63;color:#e5ecff;border-radius:8px;padding:8px 10px}
    .topright{position:fixed;top:12px;right:12px}
    .toast{position:fixed;top:12px;right:12px;background:#2b2132;color:#ffd7ef;border:1px solid #5a3c63;padding:8px 10px;border-radius:8px;display:none}
    a { color:#a9c1ff; }
  </style>
</head>
<body>
<div class="wrap">
  <div class="row">
    <h2>EC2 Dashboard</h2>
    <div>
      <span id="userBadge" class="badge" style="margin-right:8px;display:none;"></span>
      <button id="signOutBtn" class="btn" style="display:none;">Sign out</button>
      <button id="loginBtn" class="btn">Login</button>
    </div>
  </div>

  <div id="summaryBar" class="badge" style="display:flex;gap:10px;align-items:center;margin-top:10px;">
    <span>Total: <b id="t_total">0</b></span>
    <span>Running: <b id="t_run">0</b></span>
    <span>Stopped: <b id="t_stop">0</b></span>
    <button id="refreshBtn" class="btn right">Refresh</button>
  </div>

  <div id="envTabs" style="margin-top:12px;"></div>
  <div id="envBlocks"></div>
</div>

<div id="modal" class="modal">
  <div class="inner">
    <div class="row">
      <h3 id="modalTitle" style="margin:0;"></h3>
      <div>
        <button id="ssmPingBtn" class="btn">SSM Ping</button>
        <button id="modalClose" class="btn">Close</button>
      </div>
    </div>
    <div style="margin:10px 0;">
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
const API = "${api_base_url}";
const ENV_NAMES = "${env_names}".split(",").filter(Boolean);
const READ_ONLY_ROLE = "viewer";

let token = localStorage.getItem("token") || "";
let user  = JSON.parse(localStorage.getItem("user") || "null");

function toast(msg, ms=3500){ const t=document.getElementById('toast'); t.innerText=msg; t.style.display='block'; setTimeout(()=>t.style.display='none',ms); }
function authz(){ return token ? {"Authorization":"Bearer "+token} : {}; }

function showUser(){
  const b=document.getElementById('userBadge'), so=document.getElementById('signOutBtn'), li=document.getElementById('loginBtn');
  if(user && token){ b.style.display='inline-block'; b.innerText=`${user.name || user.username} • ${user.role}`; so.style.display='inline-block'; li.style.display='none'; }
  else{ b.style.display='none'; so.style.display='none'; li.style.display='inline-block'; }
}
document.getElementById('signOutBtn').onclick = () => { localStorage.removeItem('token'); localStorage.removeItem('user'); token=""; user=null; showUser(); document.getElementById('envBlocks').innerHTML=""; };

async function loginDialog(){
  const u = prompt("Username:","admin"); if(!u) return;
  const p = prompt("Password:",""); if(p===null) return;
  const r = await fetch(API+"/login",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({username:u,password:p})});
  const j = await r.json(); if(!r.ok){ toast(j.error || "login failed"); return; }
  token = j.token; user=j.user; localStorage.setItem("token",token); localStorage.setItem("user",JSON.stringify(user)); showUser(); loadInstances();
}
document.getElementById('loginBtn').onclick = loginDialog;

function roleReadOnly(){ return !user || !user.role || user.role.toLowerCase()===READ_ONLY_ROLE; }

function envTitle(env){ return `<span class="pill">${env}</span>`; }

async function loadInstances(){
  if(!token){ toast("Please login"); return; }
  try{
    const r = await fetch(API+"/instances",{headers: authz()});
    const j = await r.json(); if(!r.ok) throw new Error(j.error || "internal");
    document.getElementById('t_total').innerText=j.summary.total;
    document.getElementById('t_run').innerText=j.summary.running;
    document.getElementById('t_stop').innerText=j.summary.stopped;

    const tabs = (ENV_NAMES.length?ENV_NAMES:Object.keys(j.envs)).map(envTitle).join("");
    document.getElementById('envTabs').innerHTML=tabs;

    const blocks = [];
    for(const [env, groups] of Object.entries(j.envs)){
      blocks.push(`<div class="card"><h3>${env}</h3>
        ${["DM","EA"].map(k => groups[k].map(it => instRow(it)).join("")).join("")}
      </div>`);
    }
    document.getElementById('envBlocks').innerHTML = blocks.join("");
    wireInstanceButtons();
  }catch(e){ toast(e.message || "internal"); }
}
function instRow(it){
  const state = it.state==="running" ? "running" : it.state;
  const disabled = roleReadOnly() ? "disabled" : "";
  return `<div class="grid" style="margin-top:8px;">
    <div><b>${it.name}</b> <span class="muted">( ${it.id} )</span></div>
    <div class="muted">${state}</div>
    <div>
      <button class="btn red" data-stop="${it.id}" ${disabled}>Stop</button>
      <button class="btn" data-services='${JSON.stringify(it)}'>Services</button>
    </div>
  </div>`;
}
function wireInstanceButtons(){
  document.querySelectorAll("[data-stop]").forEach(b => b.onclick = async (e)=>{
    if(roleReadOnly()) return;
    const id=e.target.getAttribute("data-stop");
    const r=await fetch(API+"/instance-action",{method:"POST",headers:{...authz(),"content-type":"application/json"},body:JSON.stringify({id,action:"stop"})});
    const j=await r.json(); if(!r.ok){ toast(j.error||"internal"); return; } toast("Stop requested"); loadInstances();
  });
  document.querySelectorAll("[data-services]").forEach(b => b.onclick = (e)=>{
    const it = JSON.parse(e.target.getAttribute("data-services"));
    openModal(it);
  });
}

let currentInst = null;
function openModal(inst){
  currentInst = inst;
  document.getElementById('modalTitle').innerText = `Services on ${inst.name}`;
  document.getElementById('svcArea').innerHTML = '';
  document.getElementById('modal').style.display='flex';
  document.getElementById('iisBtn').disabled = roleReadOnly();
  fetchServices("");
}

document.getElementById('modalClose').onclick = ()=>{ document.getElementById('modal').style.display='none'; };
document.getElementById('svcRefresh').onclick = ()=> fetchServices(document.getElementById('svcFilter').value.trim());
document.getElementById('ssmPingBtn').onclick = async ()=>{
  const r = await fetch(API+"/ssm-ping",{method:"POST",headers:{...authz(),"content-type":"application/json"},body:JSON.stringify({id:currentInst.id})});
  const j = await r.json(); if(!r.ok){ toast(j.error||"internal"); return; }
  toast(`Host: ${j.ping.Host} @ ${j.ping.Time}`);
};
document.getElementById('iisBtn').onclick = async ()=>{
  if(roleReadOnly()) return;
  const r = await fetch(API+"/services",{method:"POST",headers:{...authz(),"content-type":"application/json"},body:JSON.stringify({id:currentInst.id,mode:"iisreset"})});
  const j = await r.json(); if(!r.ok){ toast(j.error||"internal"); return; }
  renderServices(j.services);
};
document.getElementById('sqlBtn').onclick = async ()=>{
  const r = await fetch(API+"/services",{method:"POST",headers:{...authz(),"content-type":"application/json"},body:JSON.stringify({id:currentInst.id,mode:"sqlinfo"})});
  const j = await r.json(); if(!r.ok){ toast(j.error||"internal"); return; }
  const s = j.services || [];
  const os = j.os || {};
  const vers = (j.sql||[]).map(x => `<div class="tok">SQL ${x.Instance} — ${x.Version} (${x.PatchLevel})</div>`).join("") || "<div class='muted'>No SQL version data</div>";
  const svc = Array.isArray(s) ? s : [s];
  document.getElementById('svcArea').innerHTML =
    `<div style="margin-bottom:8px;">
       <div class="tok">OS: ${os.Caption||"?"} ${os.Version||""} (${os.BuildNumber||""})</div>
     </div>
     <div style="margin-bottom:8px;">${vers}</div>
     ${svc.map(row => svcRow(row)).join("")}`;
};

async function fetchServices(pattern){
  const r = await fetch(API+"/services",{method:"POST",headers:{...authz(),"content-type":"application/json"},body:JSON.stringify({id:currentInst.id,mode:"list",pattern})});
  const j = await r.json(); if(!r.ok){ document.getElementById('svcArea').innerHTML = `<div class="muted">${j.error||"internal"}</div>`; return; }
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
  const startDis = roleReadOnly() || on ? "disabled":"";
  const stopDis  = roleReadOnly() || !on ? "disabled":"";
  return `<div class="row" style="border-bottom:1px solid #223456;padding:8px 2px;">
    <div><b>${name}</b></div>
    <div class="muted">${st||"unknown"}</div>
    <div>
      <button class="btn green" data-sstart="${name}" ${startDis}>Start</button>
      <button class="btn red" data-sstop="${name}" ${stopDis}>Stop</button>
    </div>
  </div>`;
}
function wireSvcButtons(){
  document.querySelectorAll("[data-sstart]").forEach(b => b.onclick = async (e)=>{
    if(roleReadOnly()) return;
    const svc=e.target.getAttribute("data-sstart");
    const r=await fetch(API+"/services",{method:"POST",headers:{...authz(),"content-type":"application/json"},body:JSON.stringify({id:currentInst.id,mode:"start",service:svc})});
    const j=await r.json(); if(!r.ok){ toast(j.error||"internal"); return; } renderServices(j.services);
  });
  document.querySelectorAll("[data-sstop]").forEach(b => b.onclick = async (e)=>{
    if(roleReadOnly()) return;
    const svc=e.target.getAttribute("data-sstop");
    const r=await fetch(API+"/services",{method:"POST",headers:{...authz(),"content-type":"application/json"},body:JSON.stringify({id:currentInst.id,mode:"stop",service:svc})});
    const j=await r.json(); if(!r.ok){ toast(j.error||"internal"); return; } renderServices(j.services);
  });
}

document.getElementById('refreshBtn').onclick = loadInstances;
showUser();
if(token) loadInstances();
</script>
</body>
</html>
