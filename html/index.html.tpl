<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>EC2 Dashboard</title>
  <style>
    :root{
      --bg:#0e1624; --ink:#e6e9ef; --mut:#9aa4b2; --panel:#121b2b; --card:#162338;
      --tab:#1a243b; --tabA:#2a395e;

      /* mild summary colors */
      --m-total-1:#bed3ff; --m-total-2:#97bdff; --m-total-text:#0e1a2e;
      --m-run-1:#c9f2da;  --m-run-2:#9fe2bf;  --m-run-text:#0d281a;
      --m-stop-1:#e9eef6; --m-stop-2:#ced8e7; --m-stop-text:#0e1a2e;
    }
    body {
      margin:0;
      background: radial-gradient(circle at 50% 20%, #1a1f3b 0%, #0e1624 60%, #0a0f1a 100%);
      color: var(--ink);
      font-family: system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,"Helvetica Neue",sans-serif;
    }

    header{display:flex;align-items:center;justify-content:center;padding:26px 18px}
    .brand{font-weight:900;font-size:34px;letter-spacing:.4px;text-shadow:0 4px 14px rgba(0,0,0,.45)}
    #logout{position:absolute;right:18px;top:18px}

    .wrap{max-width:1120px;margin:0 auto;padding:0 16px 40px}
    .card{background:rgba(18,27,43,.96);border-radius:18px;padding:18px;box-shadow:0 12px 70px rgba(0,0,0,.45)}

    label{font-size:12px;color:#bcd}
    input,button{font:inherit}
    input[type=text],input[type=password],input[type=email],input[type=number]{width:100%;margin-top:6px;margin-bottom:12px;background:#0f1a2e;border:1px solid #243355;color:#e6e9ef;border-radius:10px;padding:10px 12px}

    /* Buttons */
    .btn{padding:10px 16px;border-radius:999px;border:0;font-weight:800;cursor:pointer;transition:transform .08s ease, box-shadow .08s ease}
    .btn:active{transform:translateY(2px)}
    .btn.mono{background:#1a2a45;color:#cfe6ff;border:1px solid #2c3e64;box-shadow:0 4px 0 #12213a, 0 10px 20px rgba(0,0,0,.25)}
    .btn-ghost{background:transparent;border:1px solid #31476f;color:#cfe6ff}
    .btn-start{background:linear-gradient(180deg,#bff3d1,#93dfb7); color:#0e2a1b; box-shadow:0 6px 0 #0d7d57, 0 14px 22px rgba(0,0,0,.18)}
    .btn-stop{background:linear-gradient(180deg,#ffd0c9,#ff8d80); color:#401212; box-shadow:0 6px 0 #a02323, 0 14px 22px rgba(0,0,0,.18)}
    .btn-svc{background:linear-gradient(180deg,#fff1b3,#ffcc63); color:#3a2500; box-shadow:0 6px 0 #b47a1a, 0 14px 22px rgba(0,0,0,.16)}

        /* Light pastel variants for bulk controls */
    .btn-startall{
      background:linear-gradient(180deg,#d9f9e2,#a7eec3);
      color:#0e2a1b; font-weight:700;
    }
    .btn-stopall{
      background:linear-gradient(180deg,#ffdede,#ff9b9b);
      color:#401212; font-weight:700;
    }
    .btn-iis-svc{
      background:linear-gradient(180deg,#d9e9ff,#a7c7ff);
      color:#0e1a2e; font-weight:700;
    }
    .btn-iis-web{
      background:linear-gradient(180deg,#f0d9ff,#d0a7ff);
      color:#2e0e3a; font-weight:700;
    }

    /* make bulk control bars wrap nicely onto a second row */
    .bulk-controls{display:flex;flex-wrap:wrap;gap:8px;align-items:center;justify-content:flex-end}
    .bulk-subrow{display:flex;gap:8px;width:100%;justify-content:flex-end;margin-top:8px}


    .mut{color:var(--mut);font-size:12px}
    .err{color:#ffaaaa;font-size:12px;min-height:16px;margin-top:6px}

    .tabs{display:flex;gap:10px;flex-wrap:wrap;margin:16px 0}
    .tab{padding:9px 14px;border-radius:12px;background:var(--tab);border:1px solid #223356;cursor:pointer}
    .tab.active{background:var(--tabA)}
    .tab:first-child{font-weight:800}

    .grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}
    .block{border:1px solid #2a3a62;border-radius:14px;background:var(--card)}
    .block h3{margin:0;padding:12px 12px;border-bottom:1px solid #2a3a62;display:flex;align-items:center;justify-content:space-between}
    .list{padding:10px 12px}
    .row{display:flex;align-items:center;justify-content:space-between;padding:9px 6px;border-bottom:1px dashed #2b3d63}
    .row:last-child{border-bottom:0}
    .tag{font-size:11px;padding:2px 6px;border-radius:8px;background:linear-gradient(90deg,#2a3d6b,#2e415f);color:#bfe1ff;margin-left:6px}

    dialog{background:#0f172a;color:#e6e9ef;border:1px solid #2a3a62;border-radius:12px;max-width:820px;width:92%}
    table{width:100%;border-collapse:collapse}
    th,td{border-bottom:1px solid #223356;padding:8px;text-align:left}
    .chip{background:linear-gradient(90deg,#a4b8ff,#a4ffd4); color:#061a22; padding:4px 8px; border-radius:10px; display:inline-block}
    .controls{display:flex; gap:8px; align-items:center}

    /* Summary tiles — vertical list (mild) */
    .vstats{display:flex;flex-direction:column;gap:12px}
    .stat{display:flex;align-items:center;justify-content:space-between;padding:18px 20px;border-radius:14px;border:1px solid #223356;box-shadow:0 8px 22px rgba(0,0,0,.20)}
    .stat .label{font-weight:800;letter-spacing:.4px}
    .stat .num{font-size:30px;font-weight:900}

    .s-total{background:linear-gradient(180deg,var(--m-total-1),var(--m-total-2)); color:var(--m-total-text)}
    .s-run{background:linear-gradient(180deg,var(--m-run-1),var(--m-run-2)); color:var(--m-run-text)}
    .s-stop{background:linear-gradient(180deg,var(--m-stop-1),var(--m-stop-2)); color:var(--m-stop-text)}
  
/* Read-only disabled look (additive) */
.btn-disabled, .btn-disabled:hover { opacity:.45 !important; cursor:not-allowed !important; pointer-events:none !important; filter:grayscale(18%); }

/* --- Compact & lighter IIS bulk buttons (DM/EA – SVC/WEB) --- */
#dm-iis-svc, #dm-iis-web, #ea-iis-svc, #ea-iis-web {
  padding: 6px 10px !important;     /* smaller like the row above */
  font-size: 12px !important;
  border-radius: 12px !important;
  line-height: 1.1;
  box-shadow: 0 4px 14px rgba(0,0,0,.18);
  border: 1px solid transparent;    /* individual colors below */
}

/* very light, professional palettes */
#dm-iis-svc, #ea-iis-svc {
  background: linear-gradient(180deg, #e9f2ff, #d6e7ff) !important; /* pale blue */
  color: #0e1f36 !important;
  border-color: #5377aa !important;
}
#dm-iis-web, #ea-iis-web {
  background: linear-gradient(180deg, #f6e8f5, #edd6ed) !important; /* pale lilac/rose */
  color: #2b1b2d !important;
  border-color: #875b89 !important;
}

/* keep them visually aligned with the header control row */
#dm-iis-svc, #dm-iis-web, #ea-iis-svc, #ea-iis-web { margin-left: 6px !important; }

</style>
</head>
<body>
<header>
  <div class="brand">EC2 Dashboard</div>
  <button id="logout" class="btn mono">Logout</button>
</header>

<div class="wrap">
  <!-- OTP card -->
  <div id="otpCard" class="card" style="max-width:520px; margin:40px auto; display:none;">
    <div style="font-weight:800;font-size:20px;margin-bottom:6px;text-align:center">Verify your email</div>
    <div class="mut" style="margin-bottom:12px;text-align:center">Allowed domain: <b id="dom" style="margin-left:6px"></b></div>
    <label>Email</label>
    <input id="email" type="email" placeholder="you@domain.com" autocomplete="email"/>
    <div class="controls" style="justify-content:center">
      <button id="sendOtp" class="btn btn-svc">Send OTP</button>
      <input id="otp" type="text" inputmode="numeric" placeholder="Enter 6-digit OTP" style="max-width:180px" />
      <button id="verifyOtp" class="btn btn-ghost">Verify</button>
    </div>
    <div id="otpMsg" class="err" style="text-align:center"></div>
  </div>

  <!-- Dashboard -->
  <div id="dash" style="display:none">
    <div class="card" style="margin:14px 0; display:flex; align-items:center; justify-content:space-between;">
      <div id="summary" class="mut">Loading summary…</div>
      <div class="controls"><button id="btnRefreshTop" class="btn btn-ghost">Refresh</button></div>
    </div>

    <div id="tabs" class="tabs"></div>
    <div id="content"></div>
  </div>
</div>

<!-- Services dialog -->
<dialog id="svcDlg">
  <form method="dialog">
    <h3 style="margin:6px 0 12px">Services – <span id="svcInst"></span></h3>
    <div class="controls" id="svcControls" style="margin-bottom:10px">
      <!-- CHANGED placeholder so it’s not “SVC/WEB only” -->
      <input id="svcFilter" placeholder="Type 2+ letters"/>
      <button id="btnFilter" class="btn btn-svc">List</button>
      <button id="btnIIS" class="btn mono">IIS reset</button>
    </div>
    <div style="max-height:60vh; overflow:auto">
      <table>
        <thead><tr><th>Name</th><th>Display Name</th><th>Status</th><th>Action</th></tr></thead>
        <tbody id="svcBody"></tbody>
      </table>
    </div>
    <div id="svcMsg" class="mut" style="margin-top:8px"></div>
    <div style="text-align:right;margin-top:12px"><button class="btn mono">Close</button></div>
  </form>
</dialog>

<script>
const API = (localStorage.getItem("api_base_url") || "${api_base_url}");
const ALLOWED_DOMAIN = "${allowed_email_domain}";
const ENV_LABEL_MAP = { "DEV": "DevMini" };

function labelFor(envKey){ const k=(envKey||"").toUpperCase(); return ENV_LABEL_MAP[k] || envKey; }
function http(path, method, obj){
  const hdr = {"Content-Type":"application/json"};
  const jwt = localStorage.getItem("jwt");
  if (jwt) hdr["Authorization"] = "Bearer " + jwt;
  return fetch(API + path, {
    method,
    headers: hdr,
    body: method === "GET" ? undefined : JSON.stringify(obj || {})
  }).then(async r => {
    const t = await r.text();
    let d = {};
    try { d = t ? JSON.parse(t) : {}; } catch { d = { raw: t }; }
    if (!r.ok) throw new Error((d && d.error) || t || ("http " + r.status));
    return d;
  });
}

function $(id){ return document.getElementById(id); }

/* ----- Toast shim (dashboard page) ----- */
(function ensureToastShim(){
  if (!window.toast) {
    window.toast = function(msg){
      try{
        // Reuse a single floating div
        let t = document.getElementById('__dash_toast');
        if (!t) {
          t = document.createElement('div');
          t.id = '__dash_toast';
          t.style.position = 'fixed';
          t.style.left = '50%';
          t.style.bottom = '28px';
          t.style.transform = 'translateX(-50%)';
          t.style.background = 'rgba(0,0,0,.8)';
          t.style.color = '#fff';
          t.style.padding = '10px 14px';
          t.style.borderRadius = '10px';
          t.style.fontSize = '14px';
          t.style.zIndex = '9999';
          t.style.boxShadow = '0 8px 24px rgba(0,0,0,.35)';
          t.style.maxWidth = '70vw';
          t.style.textAlign = 'center';
          t.style.pointerEvents = 'none';
          document.body.appendChild(t);
        }
        t.textContent = String(msg || '');
        t.style.opacity = '1';
        setTimeout(()=>{ t.style.transition='opacity .35s ease'; t.style.opacity='0'; }, 1600);
      }catch(e){ try{ alert(msg); }catch(_){} }
    };
  }
})();

function show(el, on){ el.style.display = on?"block":"none"; }

let currentTab = "Summary", lastData = null;

function buildTabs(envs){
  const tabsEl = $("tabs"); tabsEl.innerHTML = "";
  const mk = (key, active)=> {
    const b = document.createElement("div");
    b.className = "tab" + (active ? " active" : "");
    b.textContent = key === "Summary" ? "Summary" : labelFor(key);
    b.onclick = () => { currentTab = key; render(); };
    tabsEl.appendChild(b);
  };
  mk("Summary", currentTab === "Summary");
  Object.keys(envs).forEach(t => mk(t, currentTab===t));
}

function instanceRow(it){
  const row = document.createElement("div"); row.className='row';
  const left = document.createElement("div"); left.textContent = it.name; const tag=document.createElement('span'); tag.className='tag'; tag.textContent = it.state; left.appendChild(tag);
  const actions = document.createElement("div");
  const btn = document.createElement("button"); btn.className = it.state==='running' ? 'btn btn-stop' : 'btn btn-start'; btn.textContent = (it.state==='running')? 'Stop':'Start';
  // FIX: backend expects { id, op }
  btn.onclick = async ()=>{ btn.disabled=true; try{await http('/instance-action','POST',{id:it.id,op: it.state==='running'?'stop':'start'}); await refresh(); } finally{btn.disabled=false;} };
  const svc = document.createElement("button"); svc.className='btn btn-svc'; svc.style.marginLeft='8px'; svc.textContent='Services';
  svc.onclick = ()=> openServices(it);
  actions.appendChild(btn); actions.appendChild(svc);
  row.appendChild(left); row.appendChild(actions);
  return row;
}

async function bulk(block, action){
  const envData = lastData.envs[currentTab] || {DM:[],EA:[]};
  const ids = (envData[block]||[]).map(x=>x.id);
  if(!ids.length) return;
  // FIX: backend expects { op, instanceIds }
  await http('/bulk-action','POST',{op: action, instanceIds: ids});
  await refresh();
}

/* -------- Summary + Env renders -------- */
function computeEnvTotals(envKey){
  const e = lastData.envs[envKey] || {DM:[],EA:[]};
  const items = [...(e.DM||[]), ...(e.EA||[])];
  const by = {total:items.length, running:0, stopped:0};
  items.forEach(x=>{ if(x.state==='running') by.running++; if(x.state==='stopped') by.stopped++; });
  return by;
}

function statRow(cls, label, num){
  const div = document.createElement('div');
  div.className = `stat ${cls}`;
  div.innerHTML = `<div class="label">${label}</div><div class="num">${num}</div>`;
  return div;
}

function renderSummary(){
  const d = lastData; if(!d) return;
  const content = $("content"); content.innerHTML = '';
  const card = document.createElement('div'); card.className='card';
  const box = document.createElement('div'); box.className='vstats';

  box.appendChild(statRow('s-total', 'Total',   d.summary.total ?? 0));
  box.appendChild(statRow('s-run',   'Running', d.summary.running ?? 0));
  box.appendChild(statRow('s-stop',  'Stopped', d.summary.stopped ?? 0));

  card.innerHTML = `<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px">
      <div style="font-size:20px;font-weight:900">Summary</div>
      <div class="controls"><button id="btnRefresh" class="btn btn-ghost">Refresh</button></div>
    </div>`;
  card.appendChild(box);
  content.appendChild(card);
  $("btnRefresh").onclick = refresh;

  $("summary").textContent = `Summary • Total: ${d.summary.total ?? 0} • Running: ${d.summary.running ?? 0} • Stopped: ${d.summary.stopped ?? 0}`;
}

/* --------- ADD: helpers for bulk IIS reset --------- */
function _isSvcName(name){
  const n = String(name||"").toLowerCase();
  return n.includes("svc") || n.includes("service") || /(^|[-_.])app(\d+)?($|[-_.])/.test(n);
}
function _isWebName(name){
  const n = String(name||"").toLowerCase();
  return n.includes("web") || n.includes("iis") || n.includes("front");
}

function _isSqlName(name){
  const n = String(name||"").toLowerCase();
  return n.includes("sql") || n.includes("mssql") || n.includes("postgres") || n.includes("mysql");
}
function _isRedisName(name){
  const n = String(name||"").toLowerCase();
  return n.includes("redis") || n.includes("cache");
}
function _isRabbitName(name){
  const n = String(name||"").toLowerCase();
  return n.includes("rabbit") || n.includes("mq") || n.includes("rabbitmq");
}

async function _startOneInstance(id){
  // uses the same API/http shim you already have
  await http('/instance-action', 'POST', { id, op:'start' });
}

// Start All in strict order: SQL -> Redis -> RabbitMQ -> SVC -> WEB -> (others)
async function startAllOrdered(blockKey){
  const envData = (lastData && lastData.envs && lastData.envs[currentTab]) ? lastData.envs[currentTab] : {DM:[],EA:[]};
  const items = (envData[blockKey] || []);

  // bucketize
  const sql    = [];
  const redis  = [];
  const rabbit = [];
  const svc    = [];
  const web    = [];
  const other  = [];

  for (const it of items){
    const nm = it.name || it.instanceName || "";
    if      (_isSqlName(nm))    sql.push(it);
    else if (_isRedisName(nm))  redis.push(it);
    else if (_isRabbitName(nm)) rabbit.push(it);
    else if (_isSvcName(nm))    svc.push(it);
    else if (_isWebName(nm))    web.push(it);
    else                        other.push(it);
  }

  // sequential fan-out per bucket
  const order = [sql, redis, rabbit, svc, web, other];
  for (const bucket of order){
    for (const it of bucket){
      try { await _startOneInstance(it.id); } catch(e){ /* continue */ }
    }
  }
  await refresh();
}
async function _iisresetOne(id){
  const hdr = {"content-type":"application/json"};
  const jwt = localStorage.getItem("jwt"); if (jwt) hdr["authorization"] = "Bearer "+jwt;
  const r = await fetch(API+'/services',{method:'POST', headers:hdr, body:JSON.stringify({instanceId:id, op:'iisreset'})});
  try{ return await r.json(); }catch{ return {ok:false}; }
}
async function _iisResetGroup(blockKey, kind){
  // lightweight readonly check (keeps your existing guards intact)
  const role = (localStorage.getItem('role')||'').toLowerCase();
  if (["readonly","read","viewer","ro"].includes(role)) { try{ alert("IIS reset is not permitted for Readonly users."); }catch{} return; }

  const envData = lastData.envs[currentTab] || {DM:[],EA:[]};
  const items = (envData[blockKey] || []);
  const picks = items.filter(x => {
    const nm = x.name || x.instanceName || "";
    return kind === 'svc' ? _isSvcName(nm) : _isWebName(nm);
  });

  const msgEl = $(`${blockKey.toLowerCase()}-iis-msg`);
  const btnSvc = $(`${blockKey.toLowerCase()}-iis-svc`);
  const btnWeb = $(`${blockKey.toLowerCase()}-iis-web`);

  if (!picks.length) { if (msgEl) msgEl.textContent = `No ${kind.toUpperCase()} servers`; toast(`No ${kind.toUpperCase()} servers found in ${blockKey}`); return; }

  if (btnSvc) btnSvc.disabled = true;
  if (btnWeb) btnWeb.disabled = true;
  if (msgEl) msgEl.textContent = `IIS reset in progress on ${picks.length} ${kind.toUpperCase()}…`;
  try { toast(`IIS reset fan-out to ${blockKey} ${kind.toUpperCase()} sent`); } catch{}

  let ok=0, fail=0;
  for (const p of picks) {
    try { const j = await _iisresetOne(p.id); if (j && j.ok) ok++; else fail++; }
    catch { fail++; }
  }

  if (btnSvc) btnSvc.disabled = false;
  if (btnWeb) btnWeb.disabled = false;
  if (msgEl) msgEl.textContent = `Completed • OK: ${ok}  Fail: ${fail}`;
}

/* -------- Environment render (unchanged, plus ADD: second row) -------- */
function renderEnv(){
  const d = lastData; if(!d) return;
  const envTotals = computeEnvTotals(currentTab);
  $("summary").textContent = `Env: ${labelFor(currentTab)} • Total: ${envTotals.total} • Running: ${envTotals.running} • Stopped: ${envTotals.stopped}`;

  const envData = (d.envs[currentTab] || {DM:[],EA:[]});
  const content = $("content"); content.innerHTML = '';
  const grid = document.createElement('div'); grid.className='grid';

  function blockUI(blockKey, title, items){
    const box = document.createElement('div'); box.className='block';
    const h3 = document.createElement('h3'); 
    h3.innerHTML = `
      <span>${title}</span>
      <span class="controls bulk-controls">
        <button class="btn btn-ghost" id="envRefresh_${blockKey}">Refresh</button>
        <button class="btn btn-startall" id="start_${blockKey}">Start all</button>
        <button class="btn btn-stopall"  id="stop_${blockKey}">Stop all</button>

        <!-- second row only for IIS buttons -->
        <span class="bulk-subrow">
          <button class="btn btn-iis-svc" id="${blockKey.toLowerCase()}-iis-svc">IIS RESET ALL SVC</button>
          <button class="btn btn-iis-web" id="${blockKey.toLowerCase()}-iis-web">IIS RESET ALL WEB</button>
        </span>
      </span>`;

    const list = document.createElement('div'); list.className='list';
    items.forEach(it=> list.appendChild(instanceRow(it)) );
    box.appendChild(h3);
    /* removed duplicate extra IIS row here */
    box.appendChild(list);
    grid.appendChild(box);

    setTimeout(()=>{
      $("start_"+blockKey).onclick = ()=> startAllOrdered(blockKey);
      $("stop_"+blockKey).onclick  = ()=> bulk(blockKey,'stop');
      $("envRefresh_"+blockKey).onclick  = refresh;

      /* wire IIS buttons in header */
      const svcBtn = $(`${blockKey.toLowerCase()}-iis-svc`);
      const webBtn = $(`${blockKey.toLowerCase()}-iis-web`);
      if (svcBtn) svcBtn.onclick = ()=> _iisResetGroup(blockKey,'svc');
      if (webBtn) webBtn.onclick = ()=> _iisResetGroup(blockKey,'web');
    });
  }

  blockUI('DM','Dream Mapper', envData.DM||[]);
  blockUI('EA','Encore Anywhere', envData.EA||[]);
  content.appendChild(grid);
}

function render(){
  if(!lastData) return;
  buildTabs(lastData.envs);
  if(currentTab === "Summary") renderSummary();
  else renderEnv();
}

async function refresh(){
  lastData = await http('/instances','GET');
  if(currentTab !== "Summary" && !(currentTab in lastData.envs)) currentTab = "Summary";
  render();
}
$("btnRefreshTop").onclick = refresh;

/* -------- Services modal logic (Ubuntu + Windows safe) -------- */
function openServices(it){
  const dlg = $("svcDlg");
  if (!dlg) return;

  // Title
  const inst = $("svcInst");
  if (inst) inst.textContent = it.name || it.id;

  // Stash info on the dialog element
  dlg.dataset.iid   = it.id || "";
  dlg.dataset.iname = it.name || "";
  dlg.dataset.os    = (it.platform || "").toLowerCase();   // "linux" | "windows"

  const isLinux = dlg.dataset.os === "linux";
  const isWin   = dlg.dataset.os === "windows";

  // Decide a mode from instance name
  const nm = (it.name || "").toLowerCase();
  let mode = "filter";
  if (nm.includes("sql")) mode = "sql";
  else if (nm.includes("redis")) mode = "redis";
  else if (nm.includes("rabbit") || nm.includes("rabbitmq") || (nm.includes("mq") && !nm.includes("sqs"))) mode = "rabbit";
  dlg.dataset.mode = mode;

  // Reset UI
  $("svcFilter").value = (mode === "sql") ? "SQL" : "";
  $("svcMsg").textContent = "";
  $("svcBody").innerHTML = "";

  // IIS button appears only for Windows + generic filter mode
  const iisBtn = $("btnIIS");
  if (iisBtn) iisBtn.style.display = (isWin && mode === "filter") ? "" : "none";

  /* IMPORTANT: No auto-listing on open — user must type 2+ letters and click List */
  dlg.showModal();
}


// services.js  (load only on the dashboard page)
var SVC_JS_VER = "svc-2025-09-16j";

function _q(id){ return document.getElementById(id); }
function _txt(id,v){ var el=_q(id); if(el) el.textContent=v; }
function _prettifyName(n){ if(!n) return n; return String(n).replace(/\.service$/,'').replace(/-/g,' '); }
function _first(obj, keys){
  if(!obj) return undefined;
  for(var i=0;i<keys.length;i++){
    var k = keys[i];
    if(obj[k]!=null) return obj[k];
  }
  return undefined;
}


function parseNameDisplayStatusText(txt){
  if(!txt || typeof txt !== "string") return [];


  var nameRe = /Name\s*:\s*([^\r\n]+)/ig, hit, starts = [];
  while ((hit = nameRe.exec(txt))) starts.push({ idx: hit.index });

  var items = [];
  if (starts.length) {
    for (var i = 0; i < starts.length; i++) {
      var s = starts[i].idx;
      var e = (i + 1 < starts.length) ? starts[i+1].idx : txt.length;
      var block = txt.slice(s, e);

      var name    = (block.match(/Name\s*:\s*([^\r\n]+)/i) || [])[1] || "";
      var display = (block.match(/DisplayName\s*:\s*([^\r\n]+)/i) || [])[1] || "";
      var status  = (block.match(/Status\s*:\s*([^\r\n]+)/i) || [])[1] || "";

      items.push({ name: name, display: display, status: String(status).toLowerCase() });
    }
    return items;
  }


  var lines = txt.split(/\r?\n/).map(function(s){ return s.trim(); }).filter(Boolean);
  var cur = null;
  for (var j=0; j<lines.length; j++){
    var m = lines[j].match(/(Name|DisplayName|Status)\s*:\s*(.*)/i);
    if(!m) continue;
    var key = m[1].toLowerCase();
    var val = m[2];
    if (key === "name") {
      if (cur) items.push(cur);
      cur = { name: val };
    } else {
      if (!cur) cur = {};
      if (key === "displayname") cur.display = val;
      if (key === "status")      cur.status  = String(val).toLowerCase();
    }
  }
  if (cur) items.push(cur);
  return items;
}


// Convert "messy arrays" into canonical "Name:/DisplayName:/Status:" lines
function arrayToNDSLines(arr){
  var lines = [];
  for(var i=0;i<arr.length;i++){
    var x = arr[i];

    // Already a useful object with target fields? convert straight
    if(x && typeof x==="object" && (
       x.Name!=null || x.name!=null || x.Service!=null || x.service!=null ||
       x.DisplayName!=null || x.display!=null || x.Description!=null || x.description!=null ||
       x.Status!=null || x.status!=null || x.State!=null || x.state!=null || x.ActiveState!=null || x.activeState!=null)){

      var nm = x.Name!=null ? x.Name : (x.name!=null ? x.name :
               (x.Service!=null ? x.Service :
               (x.service!=null ? x.service :
               (x.Unit!=null ? x.Unit : x.unit))));
      var dp = x.DisplayName!=null ? x.DisplayName : (x.display!=null ? x.display :
               (x.Description!=null ? x.Description : x.description));
      var st = x.Status!=null ? x.Status : (x.status!=null ? x.status :
               (x.State!=null ? x.State :
               (x.state!=null ? x.state :
               (x.ActiveState!=null ? x.ActiveState : x.activeState))));

      if(nm!=null) lines.push("Name: " + nm);
      if(dp!=null) lines.push("DisplayName: " + dp);
      if(st!=null) lines.push("Status: " + st);
      continue;
    }

    // {Key:'Name',Value:'redis-server.service'}
    if(x && typeof x==="object" && (x.Key!=null || x.key!=null) && (x.Value!=null || x.value!=null)){
      var k = String(x.Key!=null ? x.Key : x.key);
      var v = x.Value!=null ? x.Value : x.value;
      lines.push(k + ": " + v);
      continue;
    }

    // single-field object like { "Name: redis-server.service": "" } or { Name: "redis..." }
    if(x && typeof x==="object"){
      var ks = Object.keys(x);
      if(ks.length===1){
        var only = ks[0];
        var val = x[only];
        if(/^(Name|DisplayName|Status)\b/i.test(only)){
          lines.push(only + (String(val).length ? (": " + val) : ""));
          continue;
        }
        if(/^(Name|DisplayName|Status)$/i.test(only)){
          lines.push(only + ": " + val);
          continue;
        }
      }
    }

    // string line: could be "Name: ..." or noise
    if(typeof x==="string"){
      var s = x.trim();
      if(s) lines.push(s);
      continue;
    }
  }
  return lines;
}

// --- NEW: normalize ANY services payload shape into [{name,display,status}] ---
function normalizeServicesResponse(r){
  // Try the most common containers first
  let raw = (r && r.services != null) ? r.services
         : (r && r.data && r.data.services != null) ? r.data.services
         : (r && r.items != null) ? r.items
         : (r && r.raw != null) ? r.raw   // our http() returns {raw: "..."} on non-JSON
         : r;

  let items = [];

  // 1) If a single text blob -> parse "Name/DisplayName/Status" lines
  if (typeof raw === "string") {
    items = parseNameDisplayStatusText(raw);
  }
  // 2) Arrays: strings, messy objects, or good objects
  else if (Array.isArray(raw)) {
    // flatten just in case
    if (raw.flat) raw = raw.flat(4);

    if (raw.every(x => typeof x === "string")) {
      items = parseNameDisplayStatusText(raw.join("\n"));
    } else {
      // “good” objects already?
      const good = raw.filter(x => x && typeof x === "object" &&
        ("name" in x || "Name" in x || "DisplayName" in x || "status" in x || "Status" in x));
      if (good.length) {
        items = good.map(x => ({
          name:    x.name || x.Name || x.service || x.Service || x.Unit || x.unit || "",
          display: x.display || x.Display || x.DisplayName || x.description || x.Description ||
                   x.displayName || x.longName || x.LongName || (x.name || x.Name || ""),
          status:  String(x.status || x.Status || x.state || x.State || x.activeState || x.ActiveState ||
                          x.SubStatus || x.subStatus || "unknown").toLowerCase()
        }));
      } else {
        // convert weird objects to lines first, then parse
        const lines = arrayToNDSLines(raw);
        items = parseNameDisplayStatusText(lines.join("\n"));
      }
    }
  }
  // 3) Single object (possibly already normalized)
  else if (raw && typeof raw === "object") {
    // Some shapes carry stdout
    if (typeof raw.stdout === "string") {
      items = parseNameDisplayStatusText(raw.stdout);
    } else {
      items = [{
        name:    raw.name || raw.Name || raw.service || raw.Service || raw.Unit || raw.unit || "",
        display: raw.display || raw.Display || raw.DisplayName || raw.description || raw.Description ||
                 raw.displayName || (raw.name || raw.Name || ""),
        status:  String(raw.status || raw.Status || raw.state || raw.State || raw.activeState || raw.ActiveState ||
                        "unknown").toLowerCase()
      }];
    }
  }

  // Final cleanup + de-dup + ensure display fallback
  items = (items || []).map(it => ({
    name:    it.name    || it.Name    || "",
    display: it.display || it.Display || it.DisplayName || it.Description || it.name || it.Name || "—",
    status:  String(it.status || it.Status || "unknown").toLowerCase()
  }));

  // Treat “failed/inactive/dead” as stopped (UI-friendly)
  items.forEach(it => {
    if (/(^failed$|^inactive$|^dead$)/.test(it.status)) it.status = "stopped";
  });

  // de-dup by name+status (best effort)
  const seen = new Set();
  items = items.filter(it => {
    const k = `${it.name}|${it.display}|${it.status}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return !!(it.name || it.display || it.status);
  });

  return items;
}


async function listServices(){
  const dlg = _q("svcDlg");
  if (!dlg) { console.warn("[svc] svcDlg not found; skipping."); return; }

  const iid  = dlg.dataset.iid;
  let   mode = (dlg.dataset.mode || "filter").toLowerCase();
  const filt = _q("svcFilter");
  let   qval = (filt && filt.value ? filt.value : "").trim();

  // Defaults for quick filters
  if (!qval) {
    if (mode === "sql")    qval = "sql";
    if (mode === "redis")  qval = "redis|redis-server";
    if (mode === "rabbit") qval = "rabbit|rabbitmq|rabbitmq-server";
    if (filt && qval) filt.value = qval;
  }
  if (qval.length >= 2) mode = "filter";

  _txt("svcMsg","Listing…");
  const bodyEl = _q("svcBody");
  if (bodyEl) bodyEl.innerHTML = "";

  // --- helpers (use the ones already defined earlier if you prefer) ---
  function normalizeToItems(payload){
    // Pick the raw payload
    let raw = (payload && payload.services != null) ? payload.services
            : (payload && payload.data && payload.data.services != null) ? payload.data.services
            : (payload && payload.items != null) ? payload.items
            : payload;

    // If it's a string like:
    //   Name: xxx\nDisplayName: yyy\nStatus: zzz\n...
    if (typeof raw === "string") {
      raw = parseNameDisplayStatusText(raw);
    }
    // If it's an array but not of objects (e.g. strings/kv pairs), convert to N/D/S lines first
    else if (Array.isArray(raw)) {
      const allObjs = raw.every(x => x && typeof x === "object");
      if (!allObjs) {
        const lines = arrayToNDSLines(raw);
        raw = parseNameDisplayStatusText(lines.join("\n"));
      }
    } else {
      raw = [];
    }

    // Map to canonical fields and clean up status
    const items = raw.map(x => {
      const name =
        x.name || x.Name || x.service || x.Service ||
        x.unit || x.Unit || x.Id || x.id || "";
      const display =
        x.display || x.Display || x.DisplayName ||
        x.description || x.Description || name || "—";
      let primary =
        x.status || x.Status || x.state || x.State ||
        x.activeState || x.ActiveState || "";
      const sub = x.sub || x.Sub || x.subState || x.SubState || "";

      let status = (primary && sub) ? (String(primary)+":"+String(sub)) : (primary || "unknown");
      status = String(status).toLowerCase();
      if (status === "failed" || status === "inactive" || status === "dead") status = "stopped";
      if (!status) status = "unknown";

      return { name, display, status };
    });

    // Drop rows that are completely blank
    return items.filter(it => (it.name||it.display||it.status).trim());
  }

  try{
    const r = await http("/services","POST",{ instanceId: iid, op: "list", mode, query: qval });

    // Unwrap Lambda-proxy style {body:"…"} if that’s what we got
    let payload = r;
    if (r && typeof r.body === "string") {
      try { payload = JSON.parse(r.body); } catch { /* keep r */ }
    }

    const items = normalizeToItems(payload);

    if (payload && payload.ok === false) {
      _txt("svcMsg", payload.error ? ("Error: " + payload.error) : "Request failed.");
      return;
    }
    if (!items.length) {
      _txt("svcMsg","No matching services.");
      return;
    }

    _txt("svcMsg","");
    items.forEach((s) => {
      const isRun = (s.status==="running" || s.status==="active" || /(^active:|:running$)/.test(s.status));
      const tr = document.createElement("tr");
      tr.dataset.name = s.name || "";
      tr.innerHTML =
        '<td>'+(s.name||"—")+'</td>'+
        '<td>'+(s.display||"—")+'</td>'+
        '<td>'+(s.status||"unknown")+'</td>'+
        '<td>'+(s.name
            ? '<button class="btn '+(isRun?'btn-stop':'btn-start')+'" data-op="'+(isRun?'stop':'start')+'">'+(isRun?'Stop':'Start')+'</button>'
            : '')+
        '</td>';
      bodyEl.appendChild(tr);
    });

    // Optional: see what the client rendered
    console.debug("[svc] normalized items:", items);

  } catch(e){
    console.error("[svc] listServices error:", e);
    _txt("svcMsg","Error: "+(e && e.message ? e.message : e));
  }
}






// Wire dialog buttons
$("btnFilter").onclick = (e) => { e.preventDefault(); listServices(); };
$("btnIIS").onclick    = async (e) => {
  e.preventDefault();
  const dlg = $("svcDlg");
  try {
    await http("/services", "POST", {
      instanceId: dlg.dataset.iid,
      op: "iisreset",
      id: dlg.dataset.iid,             // backwards compatible fields
      instanceName: dlg.dataset.iname
    });
    $("svcMsg").textContent = "IIS reset sent.";
  } catch (err) {
    $("svcMsg").textContent = "IIS reset error: " + (err?.message || err);
  }
};

/* --- Delegated Start/Stop handler (survives re-renders) --- */
(() => {
  const tbody = document.getElementById('svcBody');
  const dlg = document.getElementById('svcDlg');
  if (!tbody || !dlg || tbody._delegateBound) return;

  tbody.addEventListener('click', async (e) => {
    const btn = e.target.closest('button[data-op], button');
    if (!btn) return;

    const op = (btn.dataset.op || btn.textContent || '').trim().toLowerCase() === 'stop' ? 'stop' : 'start';
    const tr = btn.closest('tr');
    const svcName = tr?.dataset?.name || tr?.querySelector('td')?.textContent?.trim() || '';
    const iid = dlg.dataset.iid || '';
    const iname = dlg.dataset.iname || '';
    if (!svcName || (op !== 'start' && op !== 'stop')) return;

    btn.disabled = true;
    try {
      await http('/services','POST', {
        instanceId: iid,
        op,
        serviceName: svcName,
        id: iid,
        service: svcName,
        instanceName: iname
      });
      const filterBtn = document.getElementById('btnFilter');
      if (filterBtn && filterBtn.offsetParent !== null) filterBtn.click();
      else openServices({ id: iid, name: iname }); // refresh for sql/redis
    } finally {
      btn.disabled = false;
    }
  }, true);

  tbody._delegateBound = true;
})();

/* -------- Auto-logout on idle (no UI changes) -------- */
// logs out after 15 minutes of no user activity.
(function setupIdleLogout(){
  const IDLE_MS = 20 * 60 * 1000;
  let last = Date.now();
  const bump = () => { last = Date.now(); };
  ["mousemove","mousedown","keydown","touchstart","scroll","click"].forEach(ev =>
    document.addEventListener(ev, bump, true)
  );
  setInterval(() => {
    if (Date.now() - last > IDLE_MS) {
      try { alert("Session idle for 20 minutes. Please log in again."); } catch(e){}
      localStorage.removeItem('jwt');
      localStorage.removeItem('role');
      localStorage.removeItem('user');
      location.reload();
    }
  }, 30000);
})();

/* -------- session / login -------- */
function isLoggedIn(){ return !!localStorage.getItem('jwt'); }
function logout(){ localStorage.removeItem('jwt'); localStorage.removeItem('role'); localStorage.removeItem('user'); location.reload(); }
$("logout").onclick = logout;

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

(async function init(){
  if(isLoggedIn()) { show($("dash"), true); await refresh(); }
  else { show($("otpCard"), true); }
})();

/* ---------------- PROFIlE DROPDOWN (local copy, fixed) ---------------- */
(function(){
  const jwt = () => {
    const t = localStorage.getItem("jwt");
    return (t && t !== "undefined" && t !== "null") ? t : "";
  };
  function decodeJwtPayloadSafe(t) {
    try {
      const p = t.split(".")[1]; if (!p) return {};
      const b = p.replace(/-/g, "+").replace(/_/g, "/");
      const json = decodeURIComponent(atob(b).split("").map(c => "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2)).join(""));
      return JSON.parse(json || "{}");
    } catch { return {}; }
  }
  function escapeHtml(s) {
    return String(s).replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;")
      .replaceAll('"',"&quot;").replaceAll("'","&#039;");
  }
  function titleCaseWords(s){
    return s.replace(/\b([a-z])/g, m => m.toUpperCase());
  }

  function getIdentity() {
    const payload = decodeJwtPayloadSafe(jwt());
    let name = payload.name || payload.displayName || ((payload.given_name || "") + (payload.family_name ? (" " + payload.family_name) : ""));
    let email = payload.email || payload.upn || "";
    let role = (payload.role || payload.Role || "").toLowerCase();

    // fallback from localStorage.user
    if (localStorage.getItem("user")) {
      try {
        const u = JSON.parse(localStorage.getItem("user"));
        if (!name)  name  = u.name || u.displayName || u.username || name;
        if (!email) email = u.email || u.username || email;
        if (!role)  role  = (u.role || role || "user").toLowerCase();
      } catch {}
    }

    // as a last resort, derive a friendly name from email (avoid duplicating username)
    if (!name) {
      const local = (email || "").split("@")[0] || "";
      if (local) name = titleCaseWords(local.replace(/[._-]+/g, " "));
    }
    if (!name) name = "User";
    if (!email) email = "unknown@example.com";

    return { name, email, role };
  }

  window.ensureProfileDropdown = function ensureProfileDropdown(){
    const logoutNode = document.querySelector("#logout");
    if (!logoutNode) return;

    const { name, email, role } = getIdentity();
    const initials = (name || "U").split(/\s+/).map(s=>s[0]).join("").slice(0,2).toUpperCase();
    const roleLabel = (role || "user").charAt(0).toUpperCase() + (role || "user").slice(1);
    const IS_READONLY = ["readonly","read","viewer","ro"].includes(role);

    const wrap = document.createElement("div");
    wrap.style.position="absolute";
    wrap.style.right="18px";
    wrap.style.top="18px";
    wrap.style.display="inline-block";
    wrap.setAttribute("data-profile-wrap","1");

    const btn=document.createElement("button");
    btn.type="button";
    btn.style.display="inline-flex";
    btn.style.alignItems="center";
    btn.style.gap="8px";
    btn.style.padding="6px 10px";
    btn.style.border="1px solid rgba(255,255,255,0.15)";
    btn.style.background="transparent";
    btn.style.color="inherit";
    btn.style.borderRadius="999px";
    btn.style.cursor="pointer";

    const avatar=document.createElement("div"); avatar.textContent=initials;
    avatar.style.width="28px"; avatar.style.height="28px"; avatar.style.borderRadius="50%";
    avatar.style.display="inline-flex"; avatar.style.alignItems="center"; avatar.style.justifyContent="center";
    avatar.style.fontWeight="700"; avatar.style.userSelect="none";
    avatar.style.background="rgba(255,255,255,0.12)";
    avatar.style.border="1px solid rgba(255,255,255,0.15)";

    const caret=document.createElement("span"); caret.textContent="▾"; caret.style.opacity=".8"; caret.style.fontSize="12px";
    btn.appendChild(avatar); btn.appendChild(caret);

    const dd=document.createElement("div"); dd.setAttribute("role","menu");
    dd.style.position="absolute"; dd.style.right="0"; dd.style.top="calc(100% + 8px)";
    dd.style.minWidth="260px"; dd.style.background="var(--panel, #121b2b)";
    dd.style.border="1px solid rgba(255,255,255,0.12)"; dd.style.borderRadius="12px";
    dd.style.boxShadow="0 8px 24px rgba(0,0,0,0.35)"; dd.style.padding="10px";
    dd.style.display="none"; dd.style.zIndex="1000";

    const prof=document.createElement("div");
    prof.style.display="grid"; prof.style.gridTemplateColumns="36px 1fr"; prof.style.gap="10px";
    const av2=avatar.cloneNode(true); av2.style.width="36px"; av2.style.height="36px";
    const meta=document.createElement("div");
    meta.innerHTML =
      `<div style="font-weight:700">${escapeHtml(name)}</div>
       <div style="opacity:.8;font-size:12px">${escapeHtml(email)}</div>
       <div style="opacity:.8;font-size:12px">Access: ${escapeHtml(roleLabel)}</div>`;
    prof.appendChild(av2); prof.appendChild(meta);

    const signout=document.createElement("button");
    signout.type="button"; signout.textContent="Sign out"; styleBtn(signout);

    dd.appendChild(prof); dd.appendChild(line());

    if (!IS_READONLY) {
      const settings=document.createElement("button");
      settings.type="button"; settings.textContent="Settings"; styleBtn(settings);
      dd.appendChild(settings);
      // ensure settings opens the modal here on index page too
      settings.addEventListener("click",(e)=>{ 
        e.preventDefault(); 
        dd.style.display="none"; 
        if (typeof showSettingsPicker === "function") showSettingsPicker(); 
        else if (typeof showSettingsModal === "function") showSettingsModal(); // fallback
      });

    }

    dd.appendChild(signout);
    wrap.appendChild(btn); wrap.appendChild(dd);
    logoutNode.replaceWith(wrap);

    btn.addEventListener("click",(e)=>{ e.stopPropagation(); const open=dd.style.display!=="none"; dd.style.display=open?"none":"block"; });
    document.addEventListener("click",()=>{ dd.style.display="none"; },{capture:true});
    signout.addEventListener("click",()=>{ localStorage.clear(); location.reload(); });

    function styleBtn(b){ b.style.width="100%"; b.style.padding="8px 10px"; b.style.border="1px solid rgba(255,255,255,0.15)"; b.style.background="transparent"; b.style.color="inherit"; b.style.borderRadius="8px"; b.style.cursor="pointer"; }
    function line(){ const r=document.createElement("div"); r.style.height="1px"; r.style.background="rgba(255,255,255,0.08)"; r.style.margin="8px 0"; return r; }
  };
})();

/* Ensure Profile dropdown replaces Logout (runs after inline binding) */
(function(){
  function ensureProfile(){
    if (typeof ensureProfileDropdown === "function") {
      try { ensureProfileDropdown(); } catch(e){ console.error(e); }
    }
  }
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", ensureProfile, { once:true });
  } else {
    ensureProfile();
  }
})();

/* --- ADDED: Settings modal on index page (same as login page) --- */
(function addSettingsModalSupport(){
  // reuse hdrs/http base we already have
  function hdrs(){
    const h = {"Content-Type":"application/json"};
    const tok = localStorage.getItem("jwt");
    if (tok) h["Authorization"] = "Bearer " + tok;
    return h;
  }
  window.showSettingsModal = function showSettingsModal(){
    let modal = document.getElementById("settingsModal");
    if (modal) { modal.style.display = "flex"; return; }

    modal = document.createElement("div");
    modal.id = "settingsModal";
    modal.style.position = "fixed";
    modal.style.top = "0"; modal.style.left = "0";
    modal.style.width = "100%"; modal.style.height = "100%";
    modal.style.background = "rgba(0,0,0,0.6)";
    modal.style.display = "flex";
    modal.style.alignItems = "center";
    modal.style.justifyContent = "center";
    modal.style.zIndex = "2000";

    modal.innerHTML = `
      <div style="background:#162338; padding:20px; border-radius:12px; width:360px; color:#fff">
        <h3 style="margin-top:0">Create User</h3>
        <label>Name<br><input id="setName" style="width:100%"></label><br>
        <label>Email<br><input id="setEmail" style="width:100%"></label><br>
        <label>Username<br><input id="setUser" style="width:100%"></label><br>
        <label>Password<br><input type="password" id="setPass" style="width:100%"></label><br>
        <label>Access<br>
          <select id="setAccess" style="width:100%">
            <option value="admin">Admin</option>
            <option value="readonly">Readonly</option>
          </select>
        </label><br><br>
        <div style="display:flex; gap:10px; justify-content:flex-end">
          <button id="createUserBtn" class="btn ok" type="button">Create User</button>
          <button id="closeSet" class="btn danger" type="button">Close</button>
        </div>
      </div>
    `;

    document.body.appendChild(modal);

    modal.querySelector("#closeSet").onclick = () => { modal.style.display = "none"; };

    modal.querySelector("#createUserBtn").onclick = async () => {
      const name = modal.querySelector("#setName").value.trim();
      const email = modal.querySelector("#setEmail").value.trim();
      const username = modal.querySelector("#setUser").value.trim();
      const passwordRaw = modal.querySelector("#setPass").value.trim();
      const role  = (modal.querySelector("#setAccess").value || "readonly").toLowerCase();

      if (!name || !email || !username || !passwordRaw) { toast("All fields required"); return; }

      // Ensure password is stored as "plain:<password>"
      const password = passwordRaw.startsWith("plain:") ? passwordRaw : `plain:${passwordRaw}`;

      // Payload matches the exact SSM JSON you confirmed works:
      const payload = {
        username,
        email,
        role,        // "admin" | "readonly"
        password,    // "plain:****"
        name
      };

      try {
        const r = await fetch(`${API}/create-user`, {
          method: "POST",
          headers: hdrs(),
          body: JSON.stringify(payload)
        });
        const j = await r.json();
        if (!j.ok) throw new Error(j.error || "create_failed");
        toast("User created");
        modal.style.display = "none";
      } catch (e) {
        toast("Error: " + (e?.message || e));
      }
    };

  };
  // --- Small Settings picker that leads to the existing Create User modal ---
  window.showSettingsPicker = function showSettingsPicker(){
    let m = document.getElementById("settingsPicker");
    if (!m) {
      m = document.createElement("div");
      m.id = "settingsPicker";
      Object.assign(m.style, {
        position: "fixed", inset: "0", background: "rgba(0,0,0,.55)",
        display: "flex", alignItems: "center", justifyContent: "center",
        zIndex: 3000
      });

      const card = document.createElement("div");
      card.className = "card";
      card.style.maxWidth = "360px";
      card.style.width = "92%";
      card.style.borderRadius = "14px";
      card.style.padding = "16px";

      card.innerHTML = `
        <div style="font-weight:900;font-size:18px;margin-bottom:10px">Settings</div>
        <div class="controls" style="flex-direction:column;align-items:stretch;gap:8px">
          <button id="btnCreateUser" class="btn mono">Create New User</button>
          <!-- You can add more items later (Change Password, etc.) -->
        </div>
        <div style="text-align:right;margin-top:14px">
          <button id="btnCloseSettingsPicker" class="btn btn-ghost">Close</button>
        </div>
      `;

      m.appendChild(card);
      document.body.appendChild(m);

      // wiring
      m.querySelector("#btnCloseSettingsPicker").onclick = () => { m.style.display = "none"; };
      m.querySelector("#btnCreateUser").onclick = () => {
        m.style.display = "none";
        if (window.showSettingsModal) showSettingsModal(); // uses your existing Create User modal
      };
    }
    m.style.display = "flex";
  };

})();


/* =======================================================================
   Readonly popup guard for Start/Stop + Start all/Stop all
   ======================================================================= */
(function addReadonlyPopupGuard(){
  function isRO(){
    try {
      const r = (localStorage.getItem('role') || localStorage.getItem('access') || '').toLowerCase();
      if (r) return ['readonly','read','viewer','ro'].includes(r);
    } catch {}
    try {
      const t = localStorage.getItem('jwt') || '';
      if (t && t.includes('.')) {
        const p = JSON.parse(decodeURIComponent(escape(atob(t.split('.')[1].replace(/-/g,'+').replace(/_/g,'/')))));
        const fromJwt = String(p.access || p.role || '').toLowerCase();
        if (fromJwt) return ['readonly','read','viewer','ro'].includes(fromJwt);
      }
    } catch {}
    return false;
  }
  function roNotice(msg){
    try { alert(msg || 'This action is not permitted for Readonly users.'); } catch {}
  }
  function isDanger(el){
    if (!el) return false;
    const b = el.closest && el.closest('button');
    if (!b) return false;
    const dop = (b.dataset && b.dataset.op) || '';
    const txt = (b.textContent || b.innerText || '').trim().toLowerCase();
    return dop === 'start' || dop === 'stop' ||
           txt === 'start' || txt === 'stop' ||
           txt === 'start all' || txt === 'stop all';
  }
  document.addEventListener('click', function(e){
    if (!isRO()) return;
    const btn = e.target.closest && e.target.closest('button');
    if (!btn) return;
    if (isDanger(btn)) {
      e.preventDefault(); e.stopPropagation(); e.stopImmediatePropagation && e.stopImmediatePropagation();
      roNotice('Start/Stop is not permitted for Readonly users.');
      return false;
    }
  }, true);
})();
</script>
</body>
</html>
