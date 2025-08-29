<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>EC2 Dashboard</title>
<style>
  body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;margin:0;background:#0b1220;color:#e6e6e6}
  .wrap{max-width:1100px;margin:0 auto;padding:24px}
  .card{background:#121a2a;border:1px solid #27314a;border-radius:16px;padding:16px;margin:12px 0;box-shadow:0 0 0 1px rgba(255,255,255,0.03) inset}
  input,button,select{border-radius:10px;border:1px solid #3a4c6b;background:#0f1625;color:#e6e6e6;padding:10px}
  .row{display:flex;gap:12px;flex-wrap:wrap}
  .col{flex:1}
  .tab{padding:8px 12px;border:1px solid #3a4c6b;border-bottom:none;border-radius:10px 10px 0 0;background:#0f1625;margin-right:6px;cursor:pointer}
  .tab.active{background:#1b2740}
  .inst{display:flex;align-items:center;justify-content:space-between;border:1px solid #33425e;border-radius:10px;padding:8px;margin:6px 0;background:#0f1625}
  .status.running{color:#3fd16f} .status.stopped{color:#ff8b8b} .status.terminated{color:#ffb38b}
  .muted{opacity:.8}
  .pill{padding:2px 8px;border-radius:999px;background:#22304d;border:1px solid #3a4c6b;margin-right:6px}
  dialog{border:none;border-radius:16px;background:#0f1625;color:#e6e6e6;box-shadow:0 10px 40px rgba(0,0,0,.6);width:min(700px,90vw)}
  .right{display:flex;gap:8px}
  .btn{cursor:pointer}
  .btn-green{background:#0a3;border-color:#093;color:#eaffea}
  .btn-green:hover{filter:brightness(1.1)}
  .btn-red{background:#b11;border-color:#822;color:#fee}
  .btn-red:hover{filter:brightness(1.1)}
  .btn-gray{background:#1b2740;border-color:#3a4c6b;color:#dbe2ff}
  .btn-gray:hover{filter:brightness(1.08)}
  #toasts{position:fixed;top:12px;right:12px;display:flex;flex-direction:column;gap:8px;z-index:50}
  .toast{background:#101826;border:1px solid #2b3a59;padding:10px 14px;border-radius:12px;box-shadow:0 8px 24px rgba(0,0,0,.35)}
</style>
</head>
<body>
<div class="wrap">
  <h2>EC2 Dashboard</h2>

  <div id="step1" class="card">
    <h3>Step 1: Email OTP (allowed domain: <span class="pill">@${allowed_email_domain}</span>)</h3>
    <div class="row">
      <div class="col"><input id="email" placeholder="you@${allowed_email_domain}" style="width:100%"/></div>
      <div><button class="btn btn-gray" onclick="requestOtp()">Request OTP</button></div>
    </div>
    <div class="row">
      <div class="col"><input id="otp" placeholder="Enter 6-digit OTP" style="width:100%"/></div>
      <div><button class="btn btn-gray" onclick="verifyOtp()">Verify OTP</button></div>
    </div>
    <div id="msg1" class="muted"></div>
  </div>

  <div id="step2" class="card" style="display:none">
    <h3>Step 2: Login</h3>
    <div class="row">
      <input id="username" placeholder="Username"/>
      <input id="password" type="password" placeholder="Password"/>
      <button class="btn btn-gray" onclick="login()">Login</button>
    </div>
    <div id="msg2" class="muted"></div>
  </div>

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
      <button class="btn btn-gray" onclick="loadServices()">Refresh</button>
      <button class="btn btn-gray" data-iis onclick="iisReset()">IIS Reset</button>
      <button class="btn btn-gray" onclick="closeSvc()">Close</button>
    </div>
    <div id="svcList" style="margin-top:12px"></div>
  </div>
</dialog>

<div id="toasts"></div>

<script>
const API = "${api_base_url}";
const ENV_NAMES = "${env_names}".split(",").filter(Boolean);
let TOKEN = localStorage.getItem("token") || null;
let CURRENT_ENV = null;
let SVC_CTX = { id:null, name:null };

function el(id){ return document.getElementById(id); }
function msg(id, t){ el(id).textContent = t; }
function toast(t){ const d=document.createElement('div'); d.className='toast'; d.textContent=t; el('toasts').appendChild(d); setTimeout(()=>d.remove(), 4500); }
function auth(){ return TOKEN ? {'Authorization':'Bearer '+TOKEN} : {}; }

async function requestOtp(){
  const email = el('email').value.trim();
  const r = await fetch(`$${API}/request-otp`, {method:"POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify({email})});
  const j = await r.json();
  msg('msg1', r.ok ? 'OTP sent. Check your email.' : (j.error || 'Failed'));
}
async function verifyOtp(){
  const email = el('email').value.trim();
  const code  = el('otp').value.trim();
  const r = await fetch(`$${API}/verify-otp`, {method:"POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify({email, code})});
  const j = await r.json();
  if(r.ok){ el('step2').style.display='block'; msg('msg1','OTP verified. Proceed to login.'); } else { msg('msg1', j.error || 'Failed'); }
}
async function login(){
  const username = el('username').value.trim();
  const password = el('password').value.trim();
  const r = await fetch(`$${API}/login`, {method:"POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify({username,password})});
  const j = await r.json();
  if(r.ok){ TOKEN = j.token; localStorage.setItem('token', TOKEN); showDash(); await loadDashboard(); }
  else { msg('msg2', j.error || 'Login failed'); }
}
function showDash(){
  if(el('step1')) el('step1').style.display='none';
  if(el('step2')) el('step2').style.display='none';
  el('dash').style.display='block';
}

async function loadDashboard(){
  const r = await fetch(`$${API}/instances`, {headers: auth()});
  const j = await r.json();
  if(!r.ok){ alert(j.error||'Auth failed'); return; }
  el('summary').innerHTML = `<span class="pill">Total: $${j.summary.total}</span>
  <span class="pill">Running: $${j.summary.running}</span>
  <span class="pill">Stopped: $${j.summary.stopped}</span>
  <button class="btn btn-gray" style="float:right" onclick="loadDashboard()">Refresh</button>`;
  renderEnvTabs(j.envs);
}

function renderEnvTabs(envs){
  const tabs = el('env-tabs'); tabs.innerHTML = '';
  ENV_NAMES.forEach((e,i)=>{
    const t = document.createElement('div');
    t.className = 'tab'+(i===0?' active':'');
    t.textContent = e;
    t.onclick = ()=>{ [...tabs.children].forEach(c=>c.classList.remove('active')); t.classList.add('active'); CURRENT_ENV=e; renderEnvPanel(envs,e); };
    tabs.appendChild(t);
  });
  CURRENT_ENV = ENV_NAMES[0]; renderEnvPanel(envs, CURRENT_ENV);
}

function isWebOrSvc(name){ const n=name.toLowerCase(); return n.includes('svc') || n.includes('web'); }
function isSql(name){ return name.toLowerCase().includes('sql'); }
function isRedis(name){ return name.toLowerCase().includes('redis'); }

function renderEnvPanel(envs, env){
  const p = el('env-panels'); const data = envs[env];
  p.innerHTML = '';
  ["DM","EA"].forEach((blk)=>{
    const blockName = blk==="DM" ? "Dream Mapper" : "Encore Anywhere";
    const card = document.createElement('div'); card.className='card';
    card.innerHTML = `<div class="block-title"><h3>$${blockName}</h3>
      <div class="right">
        <button class="btn btn-green" onclick="groupAction('$${env}','$${blk}','start')">Start All</button>
        <button class="btn btn-red"   onclick="groupAction('$${env}','$${blk}','stop')">Stop All</button>
      </div></div>
      <div id="list-$${env}-$${blk}"></div>`;
    p.appendChild(card);
    const c = card.querySelector(`#list-$${env}-$${blk}`);
    (data[blk]||[]).forEach(inst=>{
      const name = inst.name;
      const btnStartStop = (inst.state==='running')
        ? `<button class="btn btn-red"   onclick="act('$${inst.id}','stop','$${name}')">Stop</button>`
        : `<button class="btn btn-green" onclick="act('$${inst.id}','start','$${name}')">Start</button>`;
      const svcBtn  = `<button class="btn btn-gray" onclick="openServices('$${inst.id}','$${name.replaceAll("\"","&quot;")}')">Services</button>`;
      const html = `<div class="inst">
        <div><strong>$${name}</strong> <span class="muted">($${inst.id})</span></div>
        <div class="right">
          <span class="status $${inst.state}">$${inst.state}</span>
          ${btnStartStop}
          ${svcBtn}
        </div>
      </div>`;
      const div = document.createElement('div'); div.innerHTML = html; c.appendChild(div.firstChild);
    });
  });
}

async function act(id, action, name){
  toast(`${action==='start'?'Starting':'Stopping'}: ${name}`);
  await fetch(`$${API}/instance-action`, {method:"POST", headers:{"Content-Type":"application/json", ...auth()}, body: JSON.stringify({id, action})})
  pollUntilStable();
}

async function groupAction(env, block, action){
  toast(`${action==='start'?'Starting':'Stopping'} ALL in ${env} / ${block}`);
  await fetch(`$${API}/instance-action`, {method:"POST", headers:{"Content-Type":"application/json", ...auth()}, body: JSON.stringify({env, block, action})});
  pollUntilStable(60);
}

let pollTimer=null;
async function pollUntilStable(maxSecs=45){
  if(pollTimer) clearInterval(pollTimer);
  const start=Date.now();
  pollTimer=setInterval(async ()=>{
    await loadDashboard();
    if((Date.now()-start)/1000 > maxSecs){ clearInterval(pollTimer); }
  }, 3000);
}

function openServices(id, name){
  SVC_CTX.id = id; SVC_CTX.name=name;
  el('svcInstName').textContent = name;
  const iisBtn = document.querySelector('#svcDlg button[data-iis]');
  if(iisBtn){ iisBtn.style.display = (isWebOrSvc(name) ? 'inline-block' : 'none'); }
  document.getElementById('svcDlg').showModal();
  loadServices();
}
function closeSvc(){ document.getElementById('svcDlg').close(); }

async function loadServices(){
  const pattern = el('svcFilter').value.trim();
  const r = await fetch(`$${API}/services`, {method:"POST", headers:{"Content-Type":"application/json", ...auth()}, body: JSON.stringify({id:SVC_CTX.id, instanceName:SVC_CTX.name, mode:"list", pattern})});
  const j = await r.json();
  if(j.message) toast(j.message);
  const list = el('svcList'); list.innerHTML = '';
  (j.services||[]).forEach(s=>{
    const name = s.Name || s.name;
    const status = s.Status || s.status;
    const d = document.createElement('div'); d.className='inst';
    d.innerHTML = `<div>$${name} <span class="pill">$${status}</span></div>
      <div class="right">
        <button class="btn btn-green" onclick="svc('$${name}','start')">Start</button>
        <button class="btn btn-red"   onclick="svc('$${name}','stop')">Stop</button>
      </div>`;
    list.appendChild(d);
  });
}
async function svc(name, action){
  toast(`${action==='start'?'Starting':'Stopping'} service: ${name}`);
  await fetch(`$${API}/services`, {method:"POST", headers:{"Content-Type":"application/json", ...auth()}, body: JSON.stringify({id:SVC_CTX.id, service:name, mode:action})});
  setTimeout(loadServices, 1200);
}
async function iisReset(){
  toast("Performing IIS Reset...");
  await fetch(`$${API}/services`, {method:"POST", headers:{"Content-Type":"application/json", ...auth()}, body: JSON.stringify({id:SVC_CTX.id, mode:"iisreset"})});
}

/* Enter to submit (OTP + Login) */
['email','otp','username','password'].forEach(id=>{
  const e=el(id); if(!e) return;
  e.addEventListener('keydown', (ev)=>{
    if(ev.key==='Enter'){
      if(id==='email') requestOtp();
      else if(id==='otp') verifyOtp();
      else if(id==='username' || id==='password') login();
    }
  })
});

/* Persisted session: auto-enter dashboard if token exists */
window.addEventListener('load', async ()=>{
  if(TOKEN){ showDash(); await loadDashboard(); }
});
</script>
</body>
</html>
