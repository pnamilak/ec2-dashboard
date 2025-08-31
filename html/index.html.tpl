<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>EC2 Dashboard</title>
  <style>
    :root{
      --bg:#0e1624; --ink:#e6e9ef; --mut:#9aa4b2; --card:#162338;
      --green:#c8f7d4; --green-text:#0f3d22;
      --yellow:#fff0b8; --yellow-text:#563a00;
      --red:#ffd1d1; --red-text:#4a0b0b;
      --chip1:#2a3d6b; --chip2:#2e415f;
    }
    body{margin:0;background:radial-gradient(1000px 600px at 70% -200px,#22304e 5%,#0e1624 55%);color:var(--ink);font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,"Helvetica Neue",sans-serif}
    header{display:flex;align-items:center;justify-content:space-between;padding:14px 18px}
    .brand{font-weight:800;letter-spacing:.3px}
    .wrap{max-width:1100px;margin:0 auto;padding:0 16px 40px}
    .card{background:rgba(18,27,43,.96);border-radius:16px;padding:18px;box-shadow:0 8px 60px rgba(0,0,0,.4)}
    label{font-size:12px;color:#bcd}
    input,button{font:inherit}
    input[type=text],input[type=password],input[type=email],input[type=number]{width:100%;margin-top:6px;margin-bottom:12px;background:#0f1a2e;border:1px solid #243355;color:#e6e9ef;border-radius:10px;padding:10px 12px}
    .btn{padding:8px 12px;border-radius:12px;border:0;font-weight:700;cursor:pointer}
    .btn.mono{background:#1a2a45;color:#cfe6ff;border:1px solid #2c3e64}
    .btn-start{background:var(--green); color:var(--green-text)}
    .btn-stop{background:var(--red); color:var(--red-text)}
    .btn-svc{background:var(--yellow); color:var(--yellow-text)}
    .mut{color:var(--mut);font-size:12px}
    .err{color:#ffaaaa;font-size:12px;min-height:16px;margin-top:6px}
    .tabs{display:flex;gap:10px;flex-wrap:wrap;margin:16px 0}
    .tab{padding:6px 10px;border-radius:10px;background:#1a243b;border:1px solid #223356;cursor:pointer}
    .tab.active{background:#2a395e}
    .grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}
    .block{border:1px solid #2a3a62;border-radius:14px;background:var(--card)}
    .block h3{margin:0;padding:10px 12px;border-bottom:1px solid #2a3a62;display:flex;align-items:center;justify-content:space-between}
    .list{padding:10px 12px}
    .row{display:flex;align-items:center;justify-content:space-between;padding:8px 6px;border-bottom:1px dashed #2b3d63}
    .row:last-child{border-bottom:0}
    .tag{font-size:11px;padding:2px 6px;border-radius:8px;background:linear-gradient(90deg,var(--chip1),var(--chip2));color:#bfe1ff;margin-left:6px}
    dialog{background:#0f172a;color:#e6e9ef;border:1px solid #2a3a62;border-radius:12px;max-width:760px;width:90%}
    table{width:100%;border-collapse:collapse}
    th,td{border-bottom:1px solid #223356;padding:8px;text-align:left}
    .chip{background:linear-gradient(90deg,#a4b8ff,#a4ffd4); color:#061a22; padding:4px 8px; border-radius:10px; display:inline-block}
    .controls{display:flex; gap:8px; align-items:center}
  </style>
</head>
<body>
<header>
  <div class="brand">EC2 Dashboard</div>
  <div><button id="logout" class="btn mono">Logout</button></div>
</header>
<div class="wrap">
  <!-- OTP card -->
  <div id="otpCard" class="card" style="max-width:520px; margin:40px auto; display:none;">
    <div style="font-weight:800;font-size:20px;margin-bottom:6px">Verify your email</div>
    <div class="mut" style="margin-bottom:12px">Allowed domain: <b id="dom"></b></div>
    <label>Email</label>
    <input id="email" type="email" placeholder="you@gmail.com" autocomplete="email"/>
    <div class="controls">
      <button id="sendOtp" class="btn btn-svc">Send OTP</button>
      <input id="otp" type="text" inputmode="numeric" placeholder="Enter 6-digit OTP" style="max-width:180px" />
      <button id="verifyOtp" class="btn mono">Verify</button>
    </div>
    <div id="otpMsg" class="err"></div>
  </div>

  <!-- Dashboard -->
  <div id="dash" style="display:none">
    <div class="card" style="margin:14px 0">
      <div id="summary" class="mut">Loading summary…</div>
    </div>

    <div id="tabs" class="tabs"></div>
    <div id="content"></div>
  </div>
</div>

<dialog id="svcDlg">
  <form method="dialog">
    <h3 style="margin:6px 0 12px">Services – <span id="svcInst"></span></h3>
    <div class="controls" id="svcControls" style="margin-bottom:10px">
      <input id="svcFilter" placeholder="Type 2+ letters (SVC/WEB only)"/>
      <button id="btnFilter" class="btn btn-svc">List</button>
      <button id="btnIIS" class="btn mono">IIS reset</button>
    </div>
    <div style="max-height:60vh; overflow:auto">
      <table>
        <thead><tr><th>Name</th><th>Display Name</th><th>Status</th><th>Action</th></tr></thead>
        <tbody id="svcBody"></tbody>
      </table>
    </div>
    <div style="text-align:right;margin-top:12px"><button class="btn mono">Close</button></div>
  </form>
</dialog>

<script>
const API = (localStorage.getItem("api_base_url") || "${api_base_url}");
const ALLOWED_DOMAIN = "${allowed_email_domain}";

function http(path, method, obj){
  const hdr = {"content-type":"application/json"};
  const jwt = localStorage.getItem("jwt");
  if(jwt) hdr["authorization"] = "Bearer "+jwt;
  return fetch(API + path, {method, headers:hdr, body: method==="GET"?undefined:JSON.stringify(obj||{})})
    .then(async r=>{ const t=await r.text(); let d={}; try{d=t?JSON.parse(t):{};}catch(e){d={raw:t};}
      if(!r.ok) throw new Error((d&&d.error)||t||("http "+r.status)); return d; });
}
function $(id){ return document.getElementById(id); }
function show(el, on){ el.style.display = on?"block":"none"; }

let currentEnv = null, lastData = null;

function buildTabs(envs, active){
  const tabsEl = $("tabs"); tabsEl.innerHTML = "";
  const names = Object.keys(envs);
  names.forEach(t=>{
    const b = document.createElement("div");
    b.className = "tab" + (t===active ? " active" : "");
    b.textContent = t;
    b.onclick = () => { currentEnv = t; buildTabs(envs, currentEnv); renderCurrent(); };
    tabsEl.appendChild(b);
  });
}

function instanceRow(it){
  const row = document.createElement("div"); row.className='row';
  const left = document.createElement("div"); left.textContent = it.name; const tag=document.createElement('span'); tag.className='tag'; tag.textContent = it.state; left.appendChild(tag);
  const actions = document.createElement("div");
  const btn = document.createElement("button"); btn.className = it.state==='running' ? 'btn btn-stop' : 'btn btn-start'; btn.textContent = (it.state==='running')? 'Stop':'Start';
  btn.onclick = async ()=>{ btn.disabled=true; try{await http('/instance-action','POST',{id:it.id,action: it.state==='running'?'stop':'start'}); lastData=null; await refresh(currentEnv);} finally{btn.disabled=false;} };
  const svc = document.createElement("button"); svc.className='btn btn-svc'; svc.style.marginLeft='8px'; svc.textContent='Services';
  svc.onclick = ()=> openServices(it);
  actions.appendChild(btn); actions.appendChild(svc);
  row.appendChild(left); row.appendChild(actions);
  return row;
}

async function bulk(block, action){
  const envData = lastData.envs[currentEnv] || {DM:[],EA:[]};
  const ids = (envData[block]||[]).map(x=>x.id);
  if(!ids.length) return;
  await http('/bulk-action','POST',{ids, action});
  lastData = null; await refresh(currentEnv);
}

function renderCurrent(){
  const d = lastData; if(!d) return;
  const envData = (d.envs[currentEnv] || {DM:[],EA:[]});
  const content = $("content"); content.innerHTML = '';
  const grid = document.createElement('div'); grid.className='grid';

  function blockUI(blockKey, title, items){
    const box = document.createElement('div'); box.className='block';
    const h3 = document.createElement('h3'); h3.innerHTML = title +
      `<span><button class="btn mono" id="start_${blockKey}">Start all</button> <button class="btn mono" id="stop_${blockKey}">Stop all</button></span>`;
    const list = document.createElement('div'); list.className='list';
    items.forEach(it=> list.appendChild(instanceRow(it)) );
    box.appendChild(h3); box.appendChild(list); grid.appendChild(box);
    setTimeout(()=>{
      $("start_"+blockKey).onclick = ()=> bulk(blockKey,'start');
      $("stop_"+blockKey).onclick  = ()=> bulk(blockKey,'stop');
    });
  }

  blockUI('DM','Dream Mapper', envData.DM||[]);
  blockUI('EA','Encore Anywhere', envData.EA||[]);
  content.appendChild(grid);

  $("summary").textContent = `Env: ${currentEnv} | Total: ${d.summary.total} • Running: ${d.summary.running} • Stopped: ${d.summary.stopped}`;
}

async function refresh(desiredEnv){
  if(!lastData) lastData = await http('/instances','GET');
  const envs = lastData.envs;
  if(!desiredEnv) desiredEnv = Object.keys(envs)[0] || 'NAQA1';
  currentEnv = desiredEnv;
  buildTabs(envs, currentEnv);
  renderCurrent();
}

function openServices(it){
  const dlg = $("svcDlg");
  $("svcInst").textContent = it.name + ' ('+it.id+')';
  const nm = it.name.toLowerCase();
  const type = nm.includes('sql') ? 'sql' : (nm.includes('redis') ? 'redis' : ((/\bsvc\b|\bweb\b/.test(nm)) ? 'svcweb' : 'generic'));

  // Controls visibility
  const controls = $("svcControls");
  if (type === 'svcweb') {
    controls.style.display = 'flex';
    $("btnIIS").style.display = 'inline-block';
  } else {
    controls.style.display = (type==='generic' ? 'none' : 'none');
    $("btnIIS").style.display = 'none';
  }

  async function list(){
    let payload = { id: it.id, mode:'list', instanceName: it.name };
    if (type==='svcweb') {
      const pat = $("svcFilter").value.trim();
      if (!pat || pat.length < 2) { $("svcBody").innerHTML = ""; return; }
      payload.pattern = pat;
    }
    const r = await http('/services','POST', payload);
    const body = $("svcBody"); body.innerHTML='';
    (r.services||[]).forEach(s=>{
      const tr=document.createElement('tr');
      const disp = `<span class="chip">${s.DisplayName||''}</span>`;
      tr.innerHTML = `<td>${s.Name||''}</td><td>${disp}</td><td>${s.Status||''}</td>`;
      const td=document.createElement('td');
      const a=document.createElement('button');
      a.className = (s.Status==='Running'?'btn btn-stop':'btn btn-start');
      a.textContent = (s.Status==='Running'?'Stop':'Start');
      a.onclick = async ()=>{ a.disabled=true;
        try{ await http('/services','POST',{id:it.id, mode:(s.Status==='Running'?'stop':'start'), service:s.Name, instanceName: it.name});
             await list(); } finally{ a.disabled=false; } };
      td.appendChild(a); tr.appendChild(td); body.appendChild(tr);
    });
  }

  $("btnFilter").onclick = (e)=>{ e.preventDefault(); list(); };
  $("btnIIS").onclick    = async (e)=>{ e.preventDefault(); await http('/services','POST',{id:it.id, mode:'iisreset', instanceName: it.name}); };

  // auto-list for sql/redis
  if (type==='sql' || type==='redis') list();
  else $("svcBody").innerHTML='';

  dlg.showModal();
}

function isLoggedIn(){ return !!localStorage.getItem('jwt'); }
function logout(){ localStorage.removeItem('jwt'); localStorage.removeItem('role'); localStorage.removeItem('user'); location.reload(); }
$("logout").onclick = logout;

// OTP page
$("dom").textContent = ALLOWED_DOMAIN;
$("sendOtp").onclick = async function(){
  const email = $("email").value.trim().toLowerCase();
  if(!email.endsWith('@'+ALLOWED_DOMAIN)) { $("otpMsg").textContent='Only '+ALLOWED_DOMAIN+' allowed'; return; }
  $("otpMsg").textContent='Sending...';
  try{ await http('/request-otp','POST',{email}); $("otpMsg").textContent='OTP sent. Check your inbox.'; } catch(e){ $("otpMsg").textContent=e.message; }
};
$("verifyOtp").onclick = async function(){
  const email = $("email").value.trim().toLowerCase();
  const code  = $("otp").value.trim();
  if(!email || !code) { $("otpMsg").textContent='Enter email and OTP'; return; }
  try{
    const r = await http('/verify-otp','POST',{email,code});
    localStorage.setItem('ovt', r.ovt);
    localStorage.setItem('ovt_exp', String(Date.now()+ 5*60*1000));
    window.location.href = 'login.html';
  }catch(e){ $("otpMsg").textContent = e.message; }
};

// Entry routing
(async function init(){
  if(isLoggedIn()) { show($("dash"), true); await refresh('NAQA1'); }
  else { show($("otpCard"), true); }
})();
</script>
</body>
</html>
