<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>EC2 Control Dashboard</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <style>
    :root{
      --bg1:#0b1020; --bg2:#0a122b;
      --card:#0f172a; --card2:#0b1326;
      --text:#eaf2ff; --muted:#9bb2d8;
      --brand1:#22d3ee; --brand2:#6366f1; --brand3:#06b6d4;
      --green:#22c55e; --red:#ef4444; --amber:#f59e0b;
      --border:rgba(255,255,255,.12);
      --shadow-lg: 0 20px 50px rgba(3,8,35,.55);
      --shadow-sm: 0 8px 24px rgba(3,8,35,.35);
      --radius:18px;
      --ring: 0 0 0 4px rgba(99,102,241,.22);
    }
    body{
      margin:0; min-height:100vh; color:var(--text);
      background:
        radial-gradient(900px 600px at 15% -10%, rgba(34,211,238,.22), transparent 55%),
        radial-gradient(800px 650px at 110% 10%, rgba(99,102,241,.18), transparent 60%),
        linear-gradient(180deg, var(--bg1), var(--bg2));
      font-family: Inter, system-ui, Segoe UI, Arial, sans-serif;
    }
    body::before{
      content:""; position:fixed; inset:0; pointer-events:none; opacity:.08;
      background:
        linear-gradient(90deg, #fff 1px, transparent 1px) 0 0/34px 34px,
        linear-gradient(#fff 1px, transparent 1px) 0 0/34px 34px;
      mix-blend-mode:overlay;
    }
    .container{ width:min(1150px, calc(100% - 40px)); margin:42px auto; }

    .hero{
      display:flex; align-items:center; justify-content:space-between; gap:16px;
      padding:18px 22px; border-radius:20px;
      background:linear-gradient(180deg, #111a3c, #0c1530);
      border:1px solid var(--border); box-shadow:var(--shadow-lg);
      position:relative; overflow:hidden;
    }
    .hero::after{ content:""; position:absolute; right:-120px; top:-120px; width:240px; height:240px;
      background: radial-gradient(closest-side, rgba(34,211,238,.16), transparent); }
    .brand{ display:flex; align-items:center; gap:12px; }
    .logo{ width:42px; height:42px; border-radius:12px;
      background: conic-gradient(from 220deg, var(--brand2), var(--brand1), var(--brand3), var(--brand2));
      box-shadow: 0 0 32px rgba(34,211,238,.25); }
    .title{ font-size:22px; font-weight:800; letter-spacing:.2px;
      background:linear-gradient(90deg, var(--brand1), var(--brand2));
      -webkit-background-clip:text; background-clip:text; color:transparent; }
    .subtitle{ color:var(--muted); font-size:14px; }

    .card{ margin-top:18px; background:linear-gradient(180deg, var(--card), var(--card2));
      border:1px solid var(--border); border-radius:var(--radius); box-shadow:var(--shadow-lg); padding:22px; }

    /* Login */
    #loginForm label{ display:block; margin:10px 0 8px; font-weight:600; color:#c2d3f3; }
    #loginForm input{ width:100%; padding:12px 14px; border-radius:12px; border:1px solid #25345f;
      background:#0d1a36; color:#eaf2ff; outline:0; transition:.18s; box-shadow:var(--shadow-sm); }
    #loginForm input:focus{ border-color:#4f6cf7; box-shadow:var(--ring); }
    .btn{ display:inline-block; padding:10px 18px; border-radius:999px; border:0; cursor:pointer; font-weight:800;
      background:linear-gradient(180deg, var(--brand1), var(--brand2)); color:#041127;
      box-shadow:0 2px 0 rgba(2,6,23,.28), 0 14px 28px rgba(11,25,70,.5); transition:transform .08s ease, filter .18s ease; }
    .btn:hover{ filter:brightness(1.04); } .btn:active{ transform:translateY(2px); }
    .btn-start{ background:linear-gradient(180deg, #7df0a3, var(--green)); color:#062013; }
    .btn-stop { background:linear-gradient(180deg, #ff9b9b, var(--red));  color:#210707; }
    .btn-ghost{ background:transparent; border:1px dashed var(--border); color:#cfe6ff; }

    /* Tabs */
    .tabs{ display:flex; flex-wrap:wrap; gap:8px; margin:-6px 0 14px 0; padding-bottom:12px; border-bottom:1px dashed var(--border); }
    .tab{ padding:10px 14px; border-radius:12px; border:1px solid var(--border);
      background:#0f1c3a; color:#cfe6ff; cursor:pointer; font-weight:700; font-size:14px; transition: all .15s ease; }
    .tab:hover{ box-shadow: var(--shadow-sm); }
    .tab.active{ color:#031230; background:linear-gradient(180deg, var(--brand1), var(--brand2)); border-color: transparent; }

    /* Table */
    table{ width:100%; border-collapse:separate; border-spacing:0; margin-top:6px; }
    thead th{ text-align:left; font-size:14px; color:#cfe0ff; background:#0a1837;
      padding:12px 14px; border-bottom:1px solid #223055; position:sticky; top:0; z-index:1; }
    tbody td{ padding:12px 14px; border-bottom:1px dashed #213055; font-size:15px; color:#eaf2ff; }

    .badge{ display:inline-block; padding:6px 10px; border-radius:999px; font-weight:800; font-size:12px; }
    .ok{   background:rgba(34,197,94,.18); color:#9af0b7; border:1px solid rgba(34,197,94,.35); }
    .stop{ background:rgba(239,68,68,.18); color:#ffb2b2; border:1px solid rgba(239,68,68,.32); }
    .pend{ background:rgba(245,158,11,.18); color:#ffd79a; border:1px solid rgba(245,158,11,.35); }

    .status-dot{ width:8px; height:8px; border-radius:50%; display:inline-block; margin-right:8px; vertical-align:middle; }
    .dot-ok{ background:#22c55e; } .dot-stop{ background:#ef4444; } .dot-pend{ background:#f59e0b; }

    .row-actions{ display:flex; gap:8px; }
    .hidden{ display:none; }
    .foot{ margin-top:10px; color:#9ab0d6; font-size:12px; text-align:right; opacity:.85; }

    /* Modal */
    .modal{
      position:fixed; inset:0; background:rgba(0,0,0,.5);
      display:flex; align-items:center; justify-content:center; z-index:50;
    }
    /* keep modal hidden until opened */
    .modal.hidden { display: none !important; }

    .modal-card{ width:min(560px, calc(100% - 28px)); background:linear-gradient(180deg, #0e1731, #0b1227);
      border:1px solid var(--border); border-radius:16px; box-shadow:var(--shadow-lg); padding:18px; }
    .modal-head{ display:flex; align-items:center; justify-content:space-between; gap:10px; margin-bottom:10px; }
    .close{ background:transparent; color:#cfe0ff; border:1px dashed var(--border); border-radius:10px; padding:6px 10px; cursor:pointer; }
    .kv{ display:grid; grid-template-columns: 140px 1fr; gap:8px; margin:8px 0; color:#cfe6ff; }
    .svc-row{ display:flex; gap:8px; align-items:center; margin:12px 0; }
    .svc-row input{ flex:1; padding:10px 12px; border-radius:10px; border:1px solid #25345f; background:#0d1a36; color:#eaf2ff; }
  </style>
</head>
<body>
  <div class="container">
    <div class="hero">
      <div class="brand">
        <div class="logo"></div>
        <div>
          <div class="title">EC2 Instance Control</div>
          <div class="subtitle">Start / Stop by environment with one click</div>
        </div>
      </div>
    </div>

    <!-- Login -->
    <form class="card" id="loginForm" onsubmit="login(); return false;">
      <label>Username</label>
      <input type="text" id="username" placeholder="Enter username" autocomplete="username" />
      <label>Password</label>
      <input type="password" id="password" placeholder="Enter password" autocomplete="current-password" />
      <div style="margin-top:14px; display:flex; gap:12px; align-items:center;">
        <button class="btn" type="submit">Sign in</button>
        <span id="loginStatus" style="color:#ffb2b2; font-weight:700;"></span>
      </div>
    </form>

    <!-- Dashboard -->
    <div id="dashboard" class="card hidden">
      <div class="tabs" id="envTabs"></div>

      <table id="instTable">
        <thead>
          <tr>
            <th style="width:34%">Name</th>
            <th style="width:32%">Instance ID</th>
            <th style="width:14%">Status</th>
            <th style="width:20%">Action</th>
          </tr>
        </thead>
        <tbody></tbody>
      </table>

      <div class="foot">Tip: Click a tab to switch environments. Actions update live.</div>
    </div>
  </div>

  <!-- Details Modal -->
  <div id="detailsModal" class="modal hidden" aria-hidden="true">
    <div class="modal-card">
      <div class="modal-head">
        <div style="font-weight:800; font-size:16px;">Instance details</div>
        <button class="close" onclick="closeDetails()">Close</button>
      </div>
      <div class="kv"><div>Name</div><div id="dName"></div></div>
      <div class="kv"><div>Instance ID</div><div id="dId"></div></div>
      <div class="kv"><div>State</div><div id="dState"></div></div>

      <div style="margin-top:10px; font-weight:700; color:#cfe6ff;">Service status</div>
      <div class="svc-row">
        <input id="svcName" placeholder="Service name (e.g., MSSQLSERVER)" value="MSSQLSERVER" />
        <button class="btn-ghost" onclick="refreshService();return false;">Refresh</button>
        <button class="btn-start" onclick="serviceStart();return false;">Start</button>
        <button class="btn-stop"  onclick="serviceStop();return false;">Stop</button>
      </div>
      <div class="kv"><div>Status</div><div id="svcStatus">—</div></div>
      <div class="kv"><div>OS</div><div id="svcOS">—</div></div>
    </div>
  </div>

  <script>
    const API_ENDPOINT = "${api_url}/instances";
    const ENVIRONMENTS = ["NAQA1","NAQA2","NAQA3","NAQA6","APQA1","EUQA1"];

    let encodedToken = "";
    let activeEnv = "";
    let currentInstance = { id:"", name:"", state:"" };

    document.addEventListener('DOMContentLoaded', function () {
      var dash = document.getElementById('dashboard');
      if (dash) dash.classList.add('hidden');

      // keep modal hidden at start (belt & suspenders)
      var modal = document.getElementById('detailsModal');
      if (modal) modal.classList.add('hidden');

      if (modal) {
        modal.addEventListener('click', function(e){
          if (e.target.id === 'detailsModal') closeDetails();
        });
      }
    });

    function login() {
      var user = document.getElementById("username").value.trim();
      var pass = document.getElementById("password").value.trim();
      if (!user || !pass) { document.getElementById("loginStatus").innerText = "Enter username and password"; return; }

      // FIXED: removed stray quote
      encodedToken = btoa(user + ":" + pass);

      var form = document.getElementById("loginForm"); if (form) form.remove();
      var dash = document.getElementById("dashboard"); dash.classList.remove("hidden");

      buildTabs(); setActiveEnv(ENVIRONMENTS[0]);
    }

    function buildTabs(){
      var tabs = document.getElementById("envTabs"); tabs.innerHTML = "";
      for (var i=0;i<ENVIRONMENTS.length;i++){
        (function(env){
          var btn = document.createElement("button"); btn.className = "tab"; btn.textContent = env;
          btn.onclick = function(){ setActiveEnv(env); }; tabs.appendChild(btn);
        })(ENVIRONMENTS[i]);
      }
    }
    function markActiveTab(){
      var tabEls = document.querySelectorAll(".tab");
      for (var i=0;i<tabEls.length;i++){
        if (tabEls[i].textContent === activeEnv) tabEls[i].classList.add("active");
        else tabEls[i].classList.remove("active");
      }
    }
    function setActiveEnv(env){ activeEnv = env; markActiveTab(); fetchInstances(); }

    async function fetchInstances() {
      if (!activeEnv) return;
      var tbody = document.querySelector("#instTable tbody");
      tbody.innerHTML = "<tr><td colspan='4' style='padding:18px;color:#9db4d6;'>Loading "+ activeEnv +"…</td></tr>";
      try{
        var res = await fetch(API_ENDPOINT + "?action=list&env=" + encodeURIComponent(activeEnv), { headers: { "Authorization": encodedToken }});
        var data = await res.json();
        tbody.innerHTML = "";
        for (var i=0; i<data.length; i++){
          var inst = data[i]; var state = (inst.State || "").toLowerCase();
          var dotClass  = (state === "running") ? "dot-ok" : (state.indexOf("pending") !== -1 ? "dot-pend" : "dot-stop");
          var pillClass = (state === "running") ? "ok"     : (state.indexOf("pending") !== -1 ? "pend"     : "stop");
          var actionTxt = (state === "running") ? "Stop" : "Start";
          var btnClass  = (state === "running") ? "btn btn-stop" : "btn btn-start";

          var row = document.createElement("tr");

          var tdName = document.createElement("td"); tdName.textContent = inst.Name || ""; row.appendChild(tdName);
          var tdId   = document.createElement("td"); tdId.textContent   = inst.InstanceId || ""; row.appendChild(tdId);

          var tdState = document.createElement("td");
          var dot = document.createElement("span"); dot.className = "status-dot " + dotClass;
          var pill= document.createElement("span"); pill.className= "badge " + pillClass; pill.textContent = inst.State || "";
          tdState.appendChild(dot); tdState.appendChild(pill); row.appendChild(tdState);

          var tdAction = document.createElement("td"); tdAction.className = "row-actions";
          var btn = document.createElement("button"); btn.className = btnClass; btn.textContent = actionTxt;
          (function(instanceId, currentState){ btn.onclick = function(){ toggleInstance(instanceId, currentState); }; })(inst.InstanceId, inst.State);
          tdAction.appendChild(btn);

          var details = document.createElement("button"); details.className = "btn-ghost"; details.textContent = "Details";
          (function(i){ details.onclick = function(){ openDetails(i); }; })(inst);
          tdAction.appendChild(details);

          row.appendChild(tdAction);
          tbody.appendChild(row);
        }
        if (data.length === 0){
          tbody.innerHTML = "<tr><td colspan='4' style='padding:18px;color:#9db4d6;'>No instances found for "+ activeEnv +".</td></tr>";
        }
      }catch(e){
        tbody.innerHTML = "<tr><td colspan='4' style='padding:18px;color:#ffb2b2;'>Failed to load instances for "+ activeEnv +".</td></tr>";
      }
    }

    async function toggleInstance(id, state) {
      var action = (state && state.toLowerCase() === "running") ? "stop" : "start";
      try{
        await fetch(API_ENDPOINT + "?action=" + action + "&instance_id=" + encodeURIComponent(id), { headers: { "Authorization": encodedToken }});
        setTimeout(fetchInstances, 900);
      }catch(e){ alert("Action failed."); }
    }

    /* ---- Details modal + service controls ---- */
    function openDetails(inst){
      currentInstance = { id: inst.InstanceId || "", name: inst.Name || "", state: inst.State || "" };
      document.getElementById("dName").textContent  = currentInstance.name;
      document.getElementById("dId").textContent    = currentInstance.id;
      document.getElementById("dState").textContent = currentInstance.state;
      document.getElementById("svcStatus").textContent = "—";
      document.getElementById("svcOS").textContent = "—";
      var modal = document.getElementById("detailsModal");
      if (modal) modal.classList.remove("hidden");
      refreshService();
    }
    function closeDetails(){
      var modal = document.getElementById("detailsModal");
      if (modal && !modal.classList.contains("hidden")) modal.classList.add("hidden");
    }

    async function refreshService(){
      var svc = document.getElementById("svcName").value.trim() || "MSSQLSERVER";
      document.getElementById("svcStatus").textContent = "Checking…";
      try{
        var res = await fetch(API_ENDPOINT + "?action=service_status&instance_id=" + encodeURIComponent(currentInstance.id) + "&service=" + encodeURIComponent(svc), { headers: { "Authorization": encodedToken }});
        var data = await res.json();
        document.getElementById("svcStatus").textContent = data.Status || "unknown";
        document.getElementById("svcOS").textContent     = data.OS || "—";
      }catch(e){
        document.getElementById("svcStatus").textContent = "error";
      }
    }
    async function serviceStart(){
      var svc = document.getElementById("svcName").value.trim() || "MSSQLSERVER";
      document.getElementById("svcStatus").textContent = "Starting…";
      try{
        await fetch(API_ENDPOINT + "?action=service_start&instance_id=" + encodeURIComponent(currentInstance.id) + "&service=" + encodeURIComponent(svc), { headers: { "Authorization": encodedToken }});
        setTimeout(refreshService, 1200);
      }catch(e){ document.getElementById("svcStatus").textContent = "error"; }
    }
    async function serviceStop(){
      var svc = document.getElementById("svcName").value.trim() || "MSSQLSERVER";
      document.getElementById("svcStatus").textContent = "Stopping…";
      try{
        await fetch(API_ENDPOINT + "?action=service_stop&instance_id=" + encodeURIComponent(currentInstance.id) + "&service=" + encodeURIComponent(svc), { headers: { "Authorization": encodedToken }});
        setTimeout(refreshService, 1200);
      }catch(e){ document.getElementById("svcStatus").textContent = "error"; }
    }
  </script>
</body>
</html>
