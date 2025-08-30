<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>EC2 Dashboard</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  :root { --bg:#0f1522; --card:#0e1526; --ink:#e6eefc; --muted:#98a7c6; --edge:#1c2742; --chip:#121b2d;
          --btn:#2a3b63; --btn-ok:#1f8b4c; --btn-bad:#c14646; --btn-info:#4164cc; }
  body { background:var(--bg); color:var(--ink); font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,"Helvetica Neue",Arial,"Noto Sans"; margin:0;}
  .wrap { max-width:1100px; margin:24px auto 80px; padding:0 16px; }
  h1 { font-size:22px; margin:0 0 14px 0; }
  .pill { display:inline-block; padding:8px 12px; border-radius:12px; background:var(--chip); margin-right:8px; font-size:14px; }
  .row { display:flex; align-items:center; justify-content:space-between; gap:10px; }
  .btn { border:0; border-radius:10px; padding:8px 14px; cursor:pointer; background:var(--btn); color:#cfe1ff; }
  .btn:disabled { opacity:.5; cursor:not-allowed; }
  .btn-green { background:var(--btn-ok); color:#fff;}
  .btn-red   { background:var(--btn-bad); color:#fff;}
  .btn-blue  { background:var(--btn-info); color:#fff;}
  .muted { color:var(--muted); }
  .card { background:var(--card); border:1px solid var(--edge); border-radius:14px; padding:14px; box-shadow:0 8px 20px rgb(0 0 0 / .25); }
  .grid { display:grid; gap:10px; }
  .inst { display:flex; justify-content:space-between; align-items:center; padding:10px 12px; background:#0c1322; border:1px solid #1b2746; border-radius:10px; }
  .right { display:flex; gap:8px; align-items:center; }
  .tabs { display:flex; gap:10px; margin:12px 0; flex-wrap:wrap; }
  .tab { background:#121b2c; border:1px solid var(--edge); color:#cfe1ff; padding:8px 12px; border-radius:10px; cursor:pointer; }
  .status { color:#98f5b0; margin-right:6px; }
  dialog { border:0; border-radius:14px; padding:0; background:var(--card); color:var(--ink); }
  dialog .pad { padding:16px 18px; min-width:720px; }
  input[type=text]{ background:#0c1322; border:1px solid #1b2746; color:#d7e6ff; padding:10px 12px; border-radius:10px; width:280px; }
  .topbar { display:flex; justify-content:space-between; align-items:center; margin-bottom:14px;}
  .topright { display:flex; align-items:center; gap:10px; }
  .toast { position:fixed; top:16px; right:16px; padding:10px 12px; border-radius:8px; background:#223155; color:#d8e6ff; z-index:9999; }
  .hint { font-size:12px; color:var(--muted); margin-top:4px; }
</style>
</head>
<body>
<div class="wrap">
  <div class="topbar">
    <h1>EC2 Dashboard</h1>
    <div class="topright">
      <span id="userPill" class="pill muted">guest · user</span>
      <button id="btnSignout" class="btn" onclick="logout()">Sign out</button>
    </div>
  </div>

  <div class="row" style="gap:10px; margin-bottom:10px; flex-wrap:wrap;">
    <span class="pill">Total: <b id="tTotal">0</b></span>
    <span class="pill">Running: <b id="tRun">0</b></span>
    <span class="pill">Stopped: <b id="tStop">0</b></span>
    <div style="flex:1 1 auto;"></div>
    <button class="btn" onclick="load()">Refresh</button>
  </div>

  <div id="envTabs" class="tabs"></div>
  <div id="container"></div>
</div>

<dialog id="svcDlg">
  <div class="pad">
    <div class="row" style="margin-bottom:8px;">
      <div><b>Services on <span id="svcInstName"></span></b></div>
      <div class="right"></div>
    </div>

    <div class="row" style="margin-bottom:10px; gap:8px;">
      <input id="svcFilter" type="text" placeholder="Type to filter (for SVC/WEB)" style="display:none;">
      <div class="right">
        <button id="btnRefresh" class="btn" onclick="loadServices()">Refresh</button>
        <button id="btnIIS" class="btn" style="display:none;" onclick="iisReset()">IIS Reset</button>
        <button id="btnPing" class="btn" onclick="ssmPing()">SSM Ping</button>
        <button class="btn" onclick="el('svcDlg').close()">Close</button>
      </div>
    </div>

    <div id="svcList" class="grid" style="margin-bottom:8px;"></div>
    <div id="sqlInfo" class="muted" style="display:none; margin-top:6px;"></div>
    <div id="svcDiag" class="muted" style="white-space:pre-wrap;"></div>
    <div class="hint">If a request fails, the dialog will auto-run <b>SSM Ping</b> and show the reason here.</div>
  </div>
</dialog>

<div id="toaster"></div>

<script>
  // --- config injected by Terraform ---
  const API = "${api_base_url}";
  const ALLOWED_DOMAIN = "${allowed_email_domain}";
  const ENV_NAMES = "${env_names}".split(",").filter(Boolean);

  // --- helpers ---
  function auth(){ return {"Authorization": localStorage.getItem("token") || ""}; }
  function el(id){ return document.getElementById(id); }
  function toast(msg){ const t=document.createElement("div"); t.className="toast"; t.textContent=msg; document.body.appendChild(t); setTimeout(()=>t.remove(), 3500); }

  function setUserPill(){
    let name = "guest", role = "user";
    try { const u = JSON.parse(localStorage.getItem("user") || "{}"); name = u.name || u.username || "user"; role = (u.role || "user").toLowerCase(); } catch {}
    el("userPill").textContent = `${name} · ${role}`;
    // Signout always visible; if no token, show "guest · user" but button still there
  }
  function logout(){ localStorage.clear(); location.reload(); }
  function currentRole(){ try{ return (JSON.parse(localStorage.getItem("user")||"{}").role||"user").toLowerCase(); }catch{return "user";} }

  // --- state ---
  let DATA = null, TAB = null, ROLE = "user";
  const SVC_CTX = { id:"", name:"" };

  // --- list instances ---
  function load(){
    fetch(API + "/instances", {headers:auth()})
      .then(r => r.json().then(j => ({ok:r.ok,j})))
      .then(res => {
        if(!res.ok){ toast(res.j.error||"Error"); return; }
        DATA = res.j;
        el("tTotal").textContent = res.j.summary.total;
        el("tRun").textContent   = res.j.summary.running;
        el("tStop").textContent  = res.j.summary.stopped;
        buildTabs();
        renderEnv(TAB || ENV_NAMES[0] || Object.keys(res.j.envs)[0]);
      });
  }

  function buildTabs(){
    const tabs = el("envTabs"); tabs.innerHTML = "";
    const names = ENV_NAMES.length ? ENV_NAMES : Object.keys(DATA.envs);
    names.forEach(n=>{
      const b=document.createElement("button"); b.className="tab"; b.textContent=n;
      b.onclick=()=>{TAB=n; renderEnv(n);}
      tabs.appendChild(b);
    });
  }

  function instRow(inst){
    const r = document.createElement("div"); r.className="inst";
    const left = document.createElement("div");
    left.innerHTML = `<span class="status">${inst.state||""}</span><b>${inst.name}</b> <span class="muted">(${inst.id})</span>`;
    const right = document.createElement("div"); right.className="right";

    const btnStart = document.createElement("button"); btnStart.className="btn btn-green"; btnStart.textContent="Start All";
    btnStart.onclick=()=>bulk(inst.id,"start");
    const btnStop  = document.createElement("button"); btnStop.className="btn btn-red"; btnStop.textContent="Stop All";
    btnStop.onclick=()=>bulk(inst.id,"stop");
    const btnSvc   = document.createElement("button"); btnSvc.className="btn btn-blue"; btnSvc.textContent="Services";
    btnSvc.onclick=()=>openServices(inst.id, inst.name);

    const ro = (ROLE!=="admin"); btnStart.disabled=ro; btnStop.disabled=ro;

    right.append(btnStart, btnStop, btnSvc);
    r.append(left, right);
    return r;
  }

  function renderEnv(env){
    const wrap = el("container"); wrap.innerHTML=""; ROLE = currentRole();

    ["DM","EA"].forEach(block=>{
      const card = document.createElement("div"); card.className="card";
      const title = document.createElement("div"); title.innerHTML = `<b>${block==="DM" ? "Dream Mapper" : "Encore Anywhere"}</b>`;
      card.append(title);

      (DATA.envs[env] && DATA.envs[env][block] || []).forEach(i=> card.appendChild(instRow(i)));
      wrap.appendChild(card);
    });
  }

  function bulk(id, action){
    fetch(API + "/instance-action", {
      method:"POST",
      headers: Object.assign({"Content-Type":"application/json"}, auth()),
      body: JSON.stringify({id, action})
    }).then(r=>r.json().then(j=>({ok:r.ok,j}))).then(res=>{
      toast(res.ok ? (res.j.message||"ok") : (res.j.error||"error"));
    });
  }

  // -------------------- Services modal --------------------
  function rowForService(name){
    const d = document.createElement("div"); d.className="inst";
    const left = document.createElement("div"); left.textContent = name;
    const right = document.createElement("div"); right.className="right";
    const bStart = document.createElement("button"); bStart.className="btn btn-green"; bStart.textContent="Start";
    const bStop  = document.createElement("button"); bStop.className="btn btn-red";   bStop.textContent="Stop";
    const ro = (ROLE!=="admin"); bStart.disabled = ro; bStop.disabled = ro;
    bStart.onclick = ()=>svc(name,"start");
    bStop.onclick  = ()=>svc(name,"stop");
    right.append(bStart,bStop);
    d.append(left,right);
    return d;
  }

  function openServices(id, name){
    SVC_CTX.id = id; SVC_CTX.name = name;
    el("svcInstName").textContent = name;
    el("svcDiag").textContent = "";
    el("sqlInfo").style.display="none"; el("sqlInfo").textContent="";
    const n = name.toLowerCase();

    // default controls
    el("svcFilter").style.display = "none";
    const iisBtn = el("btnIIS"); iisBtn.style.display = "none";
    const ro = (ROLE!=="admin"); iisBtn.disabled = ro; el("btnRefresh").disabled=false; el("btnPing").disabled=false;

    // show filter + IIS for svc/web
    if(n.includes("svc") || n.includes("web")){
      el("svcFilter").style.display = "inline-block";
      iisBtn.style.display = "inline-block";
    }

    el("svcDlg").showModal();

    if(n.includes("sql")){
      loadSQLPack();   // preferred path
    } else if (n.includes("redis")){
      loadServicesFixed(["Redis"]);
    } else {
      loadServices();
    }
  }

  function loadServicesFixed(list){
    const svcList = el("svcList"); svcList.innerHTML="";
    list.forEach(n => svcList.appendChild(rowForService(n)));
    // fetch current status for visibility
    list.forEach(n => fetchServiceStatus(n));
  }

  function fetchServiceStatus(svcName){
    fetch(API + "/services", {
      method:"POST",
      headers: Object.assign({"Content-Type":"application/json"}, auth()),
      body: JSON.stringify({id:SVC_CTX.id, mode:"list", pattern: svcName})
    }).then(r=>r.json().then(j=>({ok:r.ok,j}))).then(res=>{
      if(!res.ok) return;
      const arr = Array.isArray(res.j.services) ? res.j.services : (res.j.services ? [res.j.services] : []);
      if(arr.length){
        const svcList = el("svcList"); svcList.innerHTML="";
        arr.forEach(s => svcList.appendChild(rowForService(s.Name||s.name||"")));
      }
    });
  }

  function loadServices(){
    const svcList = el("svcList"); svcList.innerHTML=""; el("svcDiag").textContent="";
    const pattern = el("svcFilter").value.trim();
    fetch(API + "/services", {
      method:"POST",
      headers: Object.assign({"Content-Type":"application/json"}, auth()),
      body: JSON.stringify({id:SVC_CTX.id, mode:"list", pattern})
    })
    .then(r=>r.json().then(j=>({ok:r.ok,j})))
    .then(res=>{
      if(!res.ok){ failAndPing(res.j); return; }
      let arr = res.j.services || [];
      if(!Array.isArray(arr)) arr = [arr];
      if(arr.length===0) svcList.innerHTML = '<div class="muted">No matching services.</div>';
      arr.forEach(s => svcList.appendChild(rowForService(s.Name||s.name||"")));
    })
    .catch(e => failAndPing({error:String(e)}));
  }

  function loadSQLPack(){
    const svcList = el("svcList"); svcList.innerHTML=""; el("svcDiag").textContent="";
    // 1) Try full sqlinfo (status + OS + versions)
    fetch(API + "/services", {
      method:"POST",
      headers: Object.assign({"Content-Type":"application/json"}, auth()),
      body: JSON.stringify({id:SVC_CTX.id, mode:"sqlinfo"})
    })
    .then(r=>r.json().then(j=>({ok:r.ok,j})))
    .then(res=>{
      if(!res.ok){
        // 2) Fallback: show core SQL service names so user still sees/start/stops them
        svcList.appendChild(rowForService("MSSQLSERVER"));
        svcList.appendChild(rowForService("SQLSERVERAGENT"));
        // also try to fetch their current status quickly:
        fetchServiceStatus("MSSQLSERVER");
        fetchServiceStatus("SQLSERVERAGENT");
        failAndPing(res.j);
        return;
      }
      let svcs = res.j.services || [];
      if(!Array.isArray(svcs)) svcs = [svcs];
      if(svcs.length===0) svcList.innerHTML = '<div class="muted">No SQL services found.</div>';
      svcs.forEach(s => svcList.appendChild(rowForService(s.Name||s.name||"")));

      const os = res.j.os || {};
      const list = res.j.sql || [];
      const lines = [];
      if(os && (os.Caption||os.Version)) lines.push("OS: " + (os.Caption||"") + " (" + (os.Version||"") + ")");
      if(Array.isArray(list) && list.length){
        lines.push("SQL Instances:");
        list.forEach(x => lines.push(" - " + (x.Instance||"") + "  " + (x.Version||"") + (x.PatchLevel ? "  ("+x.PatchLevel+")" : "")));
      }
      if(lines.length){
        el("sqlInfo").style.display="block";
        el("sqlInfo").textContent = lines.join("\n");
      }
    })
    .catch(e=>{
      // same fallback on network/parse error
      svcList.appendChild(rowForService("MSSQLSERVER"));
      svcList.appendChild(rowForService("SQLSERVERAGENT"));
      fetchServiceStatus("MSSQLSERVER");
      fetchServiceStatus("SQLSERVERAGENT");
      failAndPing({error:String(e)});
    });
  }

  function svc(service, mode){
    fetch(API + "/services", {
      method:"POST",
      headers: Object.assign({"Content-Type":"application/json"}, auth()),
      body: JSON.stringify({id:SVC_CTX.id, mode, service})
    }).then(r=>r.json().then(j=>({ok:r.ok,j}))).then(res=>{
      if(!res.ok){ failAndPing(res.j); return; }
      // refresh list
      const n = (SVC_CTX.name||"").toLowerCase();
      if(n.includes("sql")) loadSQLPack(); else loadServices();
    }).catch(e=> failAndPing({error:String(e)}));
  }

  function iisReset(){
    toast("Performing IIS Reset…");
    fetch(API + "/services", {
      method:"POST",
      headers: Object.assign({"Content-Type":"application/json"}, auth()),
      body: JSON.stringify({id:SVC_CTX.id, mode:"iisreset"})
    }).then(r=>r.json().then(j=>({ok:r.ok,j}))).then(res=>{
      if(res.ok){ toast("IIS Reset completed"); loadServices(); }
      else { failAndPing(res.j); }
    }).catch(e=> failAndPing({error:String(e)}));
  }

  // Diagnostics + unified failure handler
  function failAndPing(msg){
    toast(msg && msg.error ? msg.error : "internal");
    el("svcDiag").textContent = (msg && msg.error) ? ("Error: " + msg.error) : "Error: internal";
    ssmPing(); // auto run
  }

  function ssmPing(){
    fetch(API + "/ssm-ping", {
      method:"POST",
      headers: Object.assign({"Content-Type":"application/json"}, auth()),
      body: JSON.stringify({id:SVC_CTX.id})
    }).then(r=>r.json().then(j=>({ok:r.ok,j}))).then(res=>{
      if(res.ok){
        el("svcDiag").textContent = "SSM status: " + (res.j.status||"") +
          "\nmanaged: " + res.j.managed + "\n\nstdout:\n" + (res.j.stdout||"") +
          (res.j.stderr ? ("\n\nstderr:\n"+res.j.stderr) : "");
      } else {
        el("svcDiag").textContent = "SSM ping failed: " + (res.j.error || "internal");
      }
    }).catch(e=>{
      el("svcDiag").textContent = "SSM ping failed: " + String(e);
    });
  }

  // --- boot ---
  (function init(){
    setUserPill();
    load();
  })();
</script>
</body>
</html>
