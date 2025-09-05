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
    body{margin:0;background:radial-gradient(1100px 680px at 70% -240px,#263557 5%,#0e1624 58%);color:var(--ink);font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,"Helvetica Neue",sans-serif}

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
    <input id="email" type="email" placeholder="you@gmail.com" autocomplete="email"/>
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

<!-- Services dialog (your original markup) -->
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
  const hdr = {"content-type":"application/json"};
  const jwt = localStorage.getItem("jwt");
  if(jwt) hdr["authorization"] = "Bearer "+jwt;
  return fetch(API + path, {method, headers:hdr, body: method==="GET"?undefined:JSON.stringify(obj||{})})
    .then(async r=>{ const t=await r.text(); let d={}; try{d=t?JSON.parse(t):{};}catch(e){d={raw:t};}
      if(!r.ok) throw new Error((d&&d.error)||t||("http "+r.status)); return d; });
}
function $(id){ return document.getElementById(id); }
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
  btn.onclick = async ()=>{ btn.disabled=true; try{await http('/instance-action','POST',{id:it.id,action: it.state==='running'?'stop':'start'}); await refresh(); } finally{btn.disabled=false;} };
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
  await http('/bulk-action','POST',{ids, action});
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

function renderEnv(){
  const d = lastData; if(!d) return;
  const envTotals = computeEnvTotals(currentTab);
  $("summary").textContent = `Env: ${labelFor(currentTab)} • Total: ${envTotals.total} • Running: ${envTotals.running} • Stopped: ${envTotals.stopped}`;

  const envData = (d.envs[currentTab] || {DM:[],EA:[]});
  const content = $("content"); content.innerHTML = '';
  const grid = document.createElement('div'); grid.className='grid';

  function blockUI(blockKey, title, items){
    const box = document.createElement('div'); box.className='block';
    const h3 = document.createElement('h3'); h3.innerHTML = `<span>${title}</span>
      <span class="controls">
        <button class="btn btn-ghost" id="envRefresh_${blockKey}">Refresh</button>
        <button class="btn mono" id="start_${blockKey}">Start all</button>
        <button class="btn mono" id="stop_${blockKey}">Stop all</button>
      </span>`;
    const list = document.createElement('div'); list.className='list';
    items.forEach(it=> list.appendChild(instanceRow(it)) );
    box.appendChild(h3); box.appendChild(list); grid.appendChild(box);
    setTimeout(()=>{
      $("start_"+blockKey).onclick = ()=> bulk(blockKey,'start');
      $("stop_"+blockKey).onclick  = ()=> bulk(blockKey,'stop');
      $("envRefresh_"+blockKey).onclick  = refresh;
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

/* -------- Services modal logic (wrapped as a proper function) -------- */
function openServices(it){
  const dlg = $("svcDlg");
  if (!dlg) return;

  const inst = $("svcInst");
  if (inst) inst.textContent = it.name || it.id;

  // Decide type from instance name (sql/redis/filter)
  const nm = (it.name || "").toLowerCase();
  let type = "filter";
  if (nm.includes("sql")) type = "sql";
  else if (nm.includes("redis")) type = "redis";

  $("svcMsg").textContent = "";
  $("svcBody").innerHTML = "";
  const f = $("svcFilter"); if (f) f.value = "";

  async function list(){
    // Map whatever we used to pass to API "mode"
    const toMode = t => {
      t = (t || "").toLowerCase();
      if (t.includes("sql"))   return "sql";
      if (t.includes("redis")) return "redis";
      return "filter"; // web/filter case
    };

    const mode = toMode(type);
    let payload = { instanceId: it.id, op: "list", mode };

    if (mode === "filter") {
      const pat = $("svcFilter").value.trim();
      if (pat.length < 2) {
        $("svcBody").innerHTML = "";
        $("svcMsg").textContent = "Enter 2+ letters to list services (for SVC/WEB).";
        return;
      }
      payload.query = pat; // new field name ("pattern" -> "query")
    }

    try{
      const r = await http('/services','POST', payload);
      const items = r.services || [];
      const body = $("svcBody"); body.innerHTML='';
      if (!items.length){
        $("svcMsg").textContent = r.error ? `No services (${r.error})` : "No matching services.";
        return;
      }
      $("svcMsg").textContent = '';
      items.forEach(s=>{
        const tr=document.createElement('tr');
        const disp = `<span class="chip">${s.DisplayName || s.display || ''}</span>`;
        const name = s.Name || s.name || '';
        const st   = s.Status || s.status || '';
        tr.innerHTML = `<td>${name}</td><td>${disp}</td><td>${st}</td>`;
        const td=document.createElement('td');
        const a=document.createElement('button');
        const isRun = (st==='Running' || st==='running');
        a.className = (isRun ? 'btn btn-stop' : 'btn btn-start');
        a.textContent = (isRun ? 'Stop' : 'Start');
        a.onclick = async ()=>{ a.disabled=true;
          try{
            await http('/services','POST',{
              // new API contract for service actions
              instanceId: it.id,
              op: (s.Status === 'Running' ? 'stop' : 'start'),
              serviceName: s.Name,

              // keep legacy fields for safety
              id: it.id,
              service: s.Name,
              instanceName: it.name
            });
            await list();
          } finally { a.disabled = false; }
        };

        td.appendChild(a); tr.appendChild(td); body.appendChild(tr);
      });
    }catch(e){
      $("svcBody").innerHTML = "";
      $("svcMsg").textContent = "Error: " + e.message;
    }
  }

  $("btnFilter").onclick = (e) => { 
  e.preventDefault(); 
  list(); 
  };

  $("btnIIS").onclick = async (e) => { 
    e.preventDefault();
    try {
      await http('/services', 'POST', {
        // new contract
        instanceId: it.id,
        op: 'iisreset',

        // legacy fields (harmless; keep for compatibility)
        id: it.id,
        instanceName: it.name
      });
      $("svcMsg").textContent = "IIS reset sent.";
    } catch (err) {
      $("svcMsg").textContent = "IIS reset error: " + (err?.message || err);
    }
  };

  // For SQL/Redis we can list immediately; SVC/WEB waits for user filter
  if (type==='sql' || type==='redis') list();

  dlg.showModal();
}

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
</script>
</body>
</html>
