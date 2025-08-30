<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <meta http-equiv="cache-control" content="no-cache"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>EC2 Dashboard</title>
  <style>
    :root { --bg:#0f172a; --panel:#131c33; --muted:#8ea0c2; --text:#dce6ff; --chip:#1e293b;
            --ok:#18a058; --warn:#eab308; --bad:#ef4444; --btn:#23314e; --btn2:#3b82f6; }
    html,body{height:100%}
    body{margin:0;background:var(--bg);color:var(--text);font:14px/1.4 system-ui,Segoe UI,Roboto,Arial}
    .wrap{max-width:1080px;margin:32px auto;padding:0 12px}
    h1{margin:0 0 16px 0}
    .row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
    .chip{background:var(--chip);border-radius:999px;padding:6px 12px;color:#cde;display:inline-flex;gap:8px}
    .btn{background:var(--btn);border:0;color:#cde;border-radius:9px;padding:7px 12px;cursor:pointer}
    .btn:hover{filter:brightness(1.15)}
    .btn.pri{background:var(--btn2);color:white}
    .btn.good{background:var(--ok);color:white}
    .btn.bad{background:var(--bad);color:white}
    .btn.ghost{background:#1f2937}
    .btn[disabled]{opacity:.4;cursor:not-allowed}
    .right{margin-left:auto}
    .tabs{display:flex;gap:8px;margin:10px 0 16px}
    .tab{padding:6px 10px;border-radius:8px;background:#0b1224;color:#a9b8d9;cursor:pointer}
    .tab.active{background:#1a2544;color:#e9f1ff}
    .card{background:var(--panel);border-radius:12px;padding:12px;margin:12px 0}
    .box{border-radius:12px;background:#0b1429;padding:10px 12px;display:flex;align-items:center;gap:10px}
    .muted{color:var(--muted)}
    .pill{border-radius:999px;padding:4px 8px}
    .state{font-weight:600}
    .state.running{color:#8af0b0}
    .state.stopped{color:#f6b2b2}
    .grid{display:grid;gap:8px}
    .inst{display:flex;align-items:center;gap:10px;padding:10px;border-radius:10px;background:#0c1326}
    .inst .name{font-weight:600}
    .inst .iid{color:#6f86a9;font-size:12px}
    .inst .actions{margin-left:auto;display:flex;gap:8px}
    /* modal */
    .modal{position:fixed;inset:0;background:rgba(0,0,0,.5);display:none;align-items:center;justify-content:center;padding:16px;z-index:10}
    .modal.show{display:flex}
    .dialog{width:min(900px,96vw);max-height:80vh;overflow:auto;background:var(--panel);border-radius:14px;padding:16px}
    .list{background:#0b1429;border-radius:10px;padding:8px;max-height:52vh;overflow:auto}
    .svc-row{display:flex;align-items:center;gap:10px;padding:8px;border-radius:8px}
    .svc-row:hover{background:#0e1933}
    .svc-name{min-width:220px;font-family:ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace}
    .svc-status{font-weight:600}
    .svc-status.running{color:#7ff0aa}
    .svc-status.stopped{color:#ffb5b5}
    .hint{font-size:12px;color:#9fb2d6;margin-top:8px}
    input,select{background:#0b1327;border:1px solid #1f2c48;color:#dfe7ff;border-radius:8px;padding:8px 10px}
    .w250{width:250px}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="row">
      <h1>EC2 Dashboard</h1>
      <div class="chip right"><b>Total:</b> <span id="tot">0</span></div>
      <div class="chip"><b>Running:</b> <span id="run">0</span></div>
      <div class="chip"><b>Stopped:</b> <span id="stop">0</span></div>
      <button id="btnLogin" class="btn right">Login</button>
      <div id="who" class="chip" style="display:none"></div>
      <button id="btnLogout" class="btn" style="display:none">Sign out</button>
      <button id="btnRefresh" class="btn">Refresh</button>
    </div>

    <div id="tabs" class="tabs"></div>
    <div id="envContainer"></div>
  </div>

  <!-- Login modal (OTP first, then user/pw) -->
  <div id="loginModal" class="modal show">
    <div class="dialog" style="max-width:560px">
      <h3 style="margin:0 0 8px">Sign in</h3>

      <div class="tabs">
        <div id="tabOtp" class="tab active">Email OTP</div>
        <div id="tabCred" class="tab">User / Password</div>
      </div>

      <div id="paneOtp">
        <div class="row" style="gap:6px;margin:8px 0">
          <input id="otpEmail" class="w250" placeholder="name@${allowed_email_domain}">
          <button id="btnReqOtp" class="btn pri">Request OTP</button>
        </div>
        <div class="row" style="gap:6px;margin:6px 0">
          <input id="otpCode" class="w250" placeholder="6-digit code">
          <button id="btnVerifyOtp" class="btn pri">Verify OTP</button>
        </div>
        <div class="hint">Allowed domain: <b>${allowed_email_domain}</b></div>
      </div>

      <div id="paneCred" style="display:none">
        <div class="row" style="gap:6px;margin:8px 0">
          <input id="username" class="w250" placeholder="username">
        </div>
        <div class="row" style="gap:6px;margin:6px 0">
          <input id="password" class="w250" type="password" placeholder="password">
          <button id="btnDoLogin" class="btn pri">Login</button>
        </div>
        <div class="hint">Tip: give a user the role <code>read</code> for demo-only; it disables Start/Stop.</div>
      </div>

      <div class="row" style="margin-top:12px">
        <button id="btnCloseLogin" class="btn right">Close</button>
      </div>
    </div>
  </div>

  <!-- Services modal -->
  <div id="svcModal" class="modal">
    <div class="dialog">
      <div class="row">
        <h3 id="svcTitle" style="margin:0">Services</h3>
        <div class="right"></div>

        <input id="svcFilter" class="w250" placeholder="Type to filter (svc/web)">
        <button id="btnSvcRefresh" class="btn">Refresh</button>
        <button id="btnIisReset" class="btn">IIS Reset</button>
        <button id="btnSvcClose" class="btn">Close</button>
      </div>
      <div id="svcList" class="list" style="margin-top:10px"></div>
      <div id="svcHint" class="hint"></div>
    </div>
  </div>

<script>
const API_BASE = "${api_base_url}";
const ALLOWED_DOMAIN = "${allowed_email_domain}";
const ENV_NAMES = "${env_names}".split(",").filter(x=>x);
let TOKEN=null, ROLE=null, USER=null;
let ENV_DATA=null; // from /instances
let currentServices = { id:null, name:null, kind:null };
const q = sel => document.querySelector(sel);

// ---------- small helpers ----------
function toast(msg){ alert(msg); }
function hdr(){ return TOKEN ? { "Authorization":"Bearer "+TOKEN, "content-type":"application/json"} : {"content-type":"application/json"} }
async function api(path, method="GET", body=null){
  const res = await fetch(API_BASE+path, { method, headers: hdr(), body: body ? JSON.stringify(body):undefined });
  const txt = await res.text();
  let data = {};
  try{ data = JSON.parse(txt); }catch{ data = {raw:txt}; }
  if(!res.ok){ throw new Error(data.error || res.statusText || "request failed"); }
  return data;
}
function disableStarts(buttons, yes){ buttons.forEach(b=>b.disabled = yes); }

// ---------- login modal ----------
const loginModal = q("#loginModal");
const tabOtp = q("#tabOtp"), tabCred = q("#tabCred");
const paneOtp = q("#paneOtp"), paneCred = q("#paneCred");
function switchPane(which){
  const isOtp = which==="otp";
  tabOtp.classList.toggle("active", isOtp);
  tabCred.classList.toggle("active", !isOtp);
  paneOtp.style.display = isOtp ? "" : "none";
  paneCred.style.display = isOtp ? "none" : "";
}
tabOtp.onclick = ()=>switchPane("otp");
tabCred.onclick = ()=>switchPane("cred");
q("#btnCloseLogin").onclick = ()=> loginModal.classList.remove("show");
q("#btnLogin").onclick = ()=> loginModal.classList.add("show");

q("#btnReqOtp").onclick = async ()=>{
  const email = q("#otpEmail").value.trim();
  if(!email || !email.toLowerCase().endsWith("@"+ALLOWED_DOMAIN)) return toast("Use "+ALLOWED_DOMAIN+" email");
  try{
    await api("/request-otp","POST",{email});
    toast("OTP sent. Check your inbox.");
  }catch(e){ toast(e.message); }
};
q("#btnVerifyOtp").onclick = async ()=>{
  const email = q("#otpEmail").value.trim();
  const code  = q("#otpCode").value.trim();
  if(!email || !code) return toast("Enter email + code");
  try{
    await api("/verify-otp","POST",{email, code});
    toast("Email verified. Now sign in with username/password.");
    switchPane("cred");
  }catch(e){ toast(e.message); }
};
q("#btnDoLogin").onclick = async ()=>{
  const username = q("#username").value.trim();
  const password = q("#password").value.trim();
  if(!username || !password) return toast("Enter username/password");
  try{
    const r = await api("/login","POST",{username, password});
    TOKEN=r.token; ROLE=r.role; USER=r.user;
    loginModal.classList.remove("show");
    q("#btnLogin").style.display="none";
    q("#btnLogout").style.display="";
    q("#who").style.display="inline-flex";
    q("#who").innerText = `${USER.name || USER.username} • ${ROLE}`;
    await refreshAll();
  }catch(e){ toast(e.message); }
};
q("#btnLogout").onclick = ()=>{
  TOKEN=null; ROLE=null; USER=null;
  q("#btnLogin").style.display="";
  q("#btnLogout").style.display="none";
  q("#who").style.display="none";
  ENV_DATA=null; q("#envContainer").innerHTML=""; q("#tabs").innerHTML="";
  q("#tot").innerText="0"; q("#run").innerText="0"; q("#stop").innerText="0";
  loginModal.classList.add("show"); switchPane("otp");
};

// ---------- instances & tabs ----------
async function refreshAll(){
  try{
    const data = await api("/instances","GET");
    ENV_DATA = data.envs || {};
    q("#tot").innerText  = data.summary.total;
    q("#run").innerText  = data.summary.running;
    q("#stop").innerText = data.summary.stopped;
    buildTabs();
  }catch(e){ toast(e.message); }
}
function buildTabs(){
  const tabs = q("#tabs"); tabs.innerHTML="";
  (ENV_NAMES.length?ENV_NAMES:Object.keys(ENV_DATA)).forEach((env, idx)=>{
    const t = document.createElement("div");
    t.className = "tab"+(idx===0?" active":"");
    t.innerText = env;
    t.onclick = ()=>{ [...tabs.children].forEach(x=>x.classList.remove("active")); t.classList.add("active"); renderEnv(env); };
    tabs.appendChild(t);
    if(idx===0) renderEnv(env);
  });
}
function renderEnv(env){
  const root = q("#envContainer"); root.innerHTML="";
  const blocks = ENV_DATA[env] || {"DM":[],"EA":[]};
  for(const [group, arr] of Object.entries(blocks)){
    const card = document.createElement("div"); card.className="card";
    card.innerHTML = `<div style="font-weight:700;margin:6px 0">${group==="DM"?"Dream Mapper":"Encore Anywhere"}</div>`;
    const grid = document.createElement("div"); grid.className="grid";
    arr.forEach(x=>{
      const row = document.createElement("div"); row.className="inst";
      row.innerHTML = `
        <div class="name">${x.name}</div>
        <div class="iid">(${x.id})</div>
        <span class="state ${x.state}">${x.state}</span>
        <div class="actions">
          <button class="btn good btnStart">Start</button>
          <button class="btn bad btnStop">Stop</button>
          <button class="btn ghost btnSvc">Services</button>
        </div>`;
      const btnStart = row.querySelector(".btnStart");
      const btnStop  = row.querySelector(".btnStop");
      const btnSvc   = row.querySelector(".btnSvc");
      btnStart.disabled = (ROLE==="read") || x.state!=="stopped";
      btnStop.disabled  = (ROLE==="read") || x.state!=="running";
      btnStart.onclick  = ()=> doInstance(x.id,"start");
      btnStop.onclick   = ()=> doInstance(x.id,"stop");
      btnSvc.onclick    = ()=> openServices(x);
      grid.appendChild(row);
    });
    card.appendChild(grid);
    root.appendChild(card);
  }
}
async function doInstance(id, action){
  if(ROLE==="read") return;
  try{
    await api("/instance-action","POST",{id, action});
    await refreshAll();
  }catch(e){ toast(e.message); }
}
q("#btnRefresh").onclick = refreshAll;

// ---------- services ----------
const svcModal = q("#svcModal");
const svcTitle = q("#svcTitle");
const svcList  = q("#svcList");
const svcFilter= q("#svcFilter");
const btnIis   = q("#btnIisReset");
q("#btnSvcClose").onclick = ()=> svcModal.classList.remove("show");
q("#btnSvcRefresh").onclick = ()=> loadServices();

function inferKindByName(name){
  const n = name.toLowerCase();
  if(n.includes("sql")) return "sql";
  if(n.includes("redis")) return "redis";
  if(n.includes("web") || n.includes("svc")) return "web";
  return "generic";
}
function openServices(inst){
  currentServices = { id:inst.id, name:inst.name, kind:inferKindByName(inst.name) };
  svcTitle.innerText = `Services on ${inst.name}`;
  const k = currentServices.kind;
  const showFilter = (k==="web" || k==="generic");
  svcFilter.parentElement.style.display = showFilter ? "" : "none";
  btnIis.style.display = (k==="web") ? "" : "none";
  svcFilter.value = "";
  svcModal.classList.add("show");
  loadServices();
}
async function loadServices(){
  const body = { id: currentServices.id, name: currentServices.name, mode:"list", pattern: svcFilter.value.trim() };
  try{
    const r = await api("/services","POST", body);
    currentServices.kind = r.kind || currentServices.kind;
    renderSvcList(r.services || []);
    q("#svcHint").innerText = currentServices.kind==="sql"
      ? "Showing SQL Server & SQL Agent services (default + named instances)."
      : (currentServices.kind==="web" ? "Filter lists services whose Name or DisplayName contains the text. IIS Reset available."
                                     : (currentServices.kind==="redis" ? "Showing redis* services." : ""));
  }catch(e){
    renderSvcList([]);
    q("#svcHint").innerText = e.message || "Error";
  }
}
function renderSvcList(items){
  svcList.innerHTML = "";
  if(!items || (Array.isArray(items) && items.length===0)){ svcList.innerHTML="<div class='muted' style='padding:8px'>No services</div>"; return; }
  (Array.isArray(items) ? items : [items]).forEach(s=>{
    const row = document.createElement("div"); row.className="svc-row";
    const nm = s.Name || s.name || "";
    const dn = s.DisplayName || s.displayName || nm;
    const st = (s.Status || s.status || "").toLowerCase();
    row.innerHTML = `
      <div class="svc-name">${nm}</div>
      <div class="muted" style="flex:1">${dn}</div>
      <div class="svc-status ${st}">${st || "-"}</div>
      <div class="actions">
        <button class="btn good actStart">Start</button>
        <button class="btn bad actStop">Stop</button>
      </div>`;
    const bStart = row.querySelector(".actStart");
    const bStop  = row.querySelector(".actStop");
    bStart.disabled = ROLE==="read" || st==="running";
    bStop.disabled  = ROLE==="read" || st!=="running";
    bStart.onclick  = ()=> doSvc(nm,"start");
    bStop.onclick   = ()=> doSvc(nm,"stop");
    svcList.appendChild(row);
  });
}
async function doSvc(name, action){
  if(ROLE==="read") return;
  try{
    const r = await api("/services","POST",{ id: currentServices.id, name: currentServices.name, mode:action, service:name });
    renderSvcList(r.services || []);
  }catch(e){ toast(e.message); }
}
btnIis.onclick = async ()=>{
  if(ROLE==="read") return;
  try{
    await api("/services","POST",{ id: currentServices.id, name: currentServices.name, mode:"iisreset" });
    await loadServices();
  }catch(e){ toast(e.message); }
};
svcFilter.oninput = ()=> {
  if(currentServices.kind==="web" || currentServices.kind==="generic") loadServices();
};

// ---------- boot ----------
switchPane("otp"); // OTP first
</script>
</body>
</html>
