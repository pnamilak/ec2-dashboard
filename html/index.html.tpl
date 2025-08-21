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
      --text:#e5f0ff; --muted:#9db4d6;
      --brand1:#22d3ee; --brand2:#6366f1; --brand3:#06b6d4;
      --green:#22c55e; --red:#ef4444; --amber:#f59e0b;
      --border:rgba(255,255,255,.12);
      --ring: 0 0 0 4px rgba(99,102,241,.22);
      --radius:18px;
      --shadow-lg: 0 20px 50px rgba(3,8,35,.55);
      --shadow-sm: 0 8px 24px rgba(3,8,35,.35);
      --glow: 0 0 40px rgba(34,211,238,.25);
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
    .container{ width:min(1200px, calc(100% - 40px)); margin:42px auto; }

    .hero{
      display:flex; align-items:center; justify-content:space-between; gap:16px;
      padding:18px 22px; border-radius:20px; background:linear-gradient(180deg, #0e1731, #0b1227);
      box-shadow: var(--shadow-lg);
      border:1px solid var(--border);
      position:relative; overflow:hidden;
    }
    .hero::after{
      content:""; position:absolute; right:-120px; top:-120px; width:240px; height:240px;
      background: radial-gradient(closest-side, rgba(34,211,238,.16), transparent);
      filter: blur(1px);
    }
    .brand{ display:flex; align-items:center; gap:12px; }
    .logo{
      width:38px; height:38px; border-radius:10px;
      background: conic-gradient(from 220deg, var(--brand2), var(--brand1), var(--brand3), var(--brand2));
      box-shadow: var(--glow);
    }
    .title{
      font-size:22px; font-weight:800; letter-spacing:.2px;
      background:linear-gradient(90deg, var(--brand1), var(--brand2));
      -webkit-background-clip:text; background-clip:text; color:transparent;
    }
    .subtitle{ color:var(--muted); font-size:14px; }

    .card{
      margin-top:18px; background:linear-gradient(180deg, var(--card), var(--card2));
      border:1px solid var(--border); border-radius:var(--radius);
      box-shadow: var(--shadow-lg); padding:22px;
    }

    #loginForm label{ display:block; font-weight:600; color:#b9c8e9; margin:12px 0 8px; }
    #loginForm input{
      width:100%; padding:12px 14px; border-radius:12px; border:1px solid #223055; background:#0d1a36; color:#eaf2ff;
      outline:0; transition:.18s; box-shadow: var(--shadow-sm);
    }
    #loginForm input:focus{ border-color:#4f6cf7; box-shadow:var(--ring); }

    .btn{
      display:inline-block; padding:10px 18px; border-radius:999px; border:0; cursor:pointer; color:#051028; font-weight:800;
      background:linear-gradient(180deg, var(--brand1), var(--brand2));
      box-shadow:0 2px 0 rgba(2,6,23,.28), 0 14px 28px rgba(11,25,70,.5);
      transition:transform .08s ease, box-shadow .12s ease, filter .18s ease;
    }
    .btn:hover{ filter:brightness(1.03); }
    .btn:active{ transform:translateY(2px); }

    .tabs{ display:flex; flex-wrap:wrap; gap:8px; margin-bottom:16px; border-bottom:1px dashed var(--border); padding-bottom:12px; }
    .tab{
      padding:10px 14px; border-radius:12px; border:1px solid var(--border);
      background:#0f1c3a; color:#cfe6ff; cursor:pointer; font-weight:700; font-size:14px;
      transition: all .15s ease;
    }
    .tab:hover{ box-shadow: var(--shadow-sm); }
    .tab.active{
      color:#031230;
      background:linear-gradient(180deg, var(--brand1), var(--brand2));
      border-color: transparent;
    }

    table{ width:100%; border-collapse:separate; border-spacing:0; margin-top:6px; }
    thead th{
      text-align:left; font-size:14px; color:#cfe0ff; background:#0a1837;
      padding:12px 14px; border-bottom:1px solid #223055; position:sticky; top:0; z-index:1;
    }
    tbody td{ padding:12px 14px; border-bottom:1px dashed #213055; font-size:15px; color:#eaf2ff; }

    .badge{ display:inline-block; padding:6px 10px; border-radius:999px; font-weight:800; font-size:12px; }
    .ok    { background:rgba(34,197,94,.18); color:#9af0b7; border:1px solid rgba(34,197,94,.35); }
    .stop  { background:rgba(239,68,68,.18); color:#ffb2b2; border:1px solid rgba(239,68,68,.32); }
    .pend  { background:rgba(245,158,11,.18); color:#ffd79a; border:1px solid rgba(245,158,11,.35); }

    .btn-start{ background:linear-gradient(180deg, #7df0a3, var(--green)); color:#041216; }
    .btn-stop { background:linear-gradient(180deg, #ff9b9b, var(--red));  color:#230606; }

    .hidden{ display:none; }
    .row-actions{ display:flex; gap:8px; }
    .status-dot{ width:8px; height:8px; border-radius:50%; display:inline-block; margin-right:8px; vertical-align:middle; }
    .dot-ok{ background:#22c55e; } .dot-stop{ background:#ef4444; } .dot-pend{ background:#f59e0b; }

    .foot{ margin-top:14px; color:#9ab0d6; font-size:12px; text-align:right; opacity:.8; }
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

    <form class="card" id="loginForm" onsubmit="login();return false;">
      <label>Username</label>
      <input type="text" id="username" placeholder="Enter username" autocomplete="username" />
      <label>Password</label>
      <input type="password" id="password" placeholder="Enter password" autocomplete="current-password" />
      <div style="margin-top:14px; display:flex; gap:12px; align-items:center;">
        <button class="btn" type="submit">Sign in</button>
        <span id="loginStatus" style="color:#ffb2b2; font-weight:700;"></span>
      </div>
    </form>

    <div id="dashboard" class="card hidden">
      <div class="tabs" id="envTabs"></div>

      <table id="instTable">
        <thead>
          <tr>
            <th style="width:36%">Name</th>
            <th style="width:34%">Instance ID</th>
            <th style="width:15%">Status</th>
            <th style="width:15%">Action</th>
          </tr>
        </thead>
        <tbody></tbody>
      </table>

      <div class="foot">Tip: Click a tab to switch environments. Actions update live.</div>
    </div>
  </div>

  <script>
    // Terraform should only substitute this one:
    const API_ENDPOINT = "${api_url}/instances";

    const ENVIRONMENTS = ["PRQA1","PRQA2","PRQA3","PRQA6","PNQA1","AVQA1"];
    let encodedToken = "";
    let activeEnv = "";

    document.addEventListener("DOMContentLoaded", () => {
      const dash = document.getElementById("dashboard");
      if (dash) dash.classList.add("hidden");
    });

    function login(){
      const u = document.getElementById("username").value.trim();
      const p = document.getElementById("password").value.trim();
      if(!u || !p){
        document.getElementById("loginStatus").innerText = "Enter username and password";
        return;
      }
      encodedToken = btoa(u + ":" + p);

      document.getElementById("loginForm").remove();
      const dash = document.getElementById("dashboard");
      dash.classList.remove("hidden");

      buildTabs();
      setActiveEnv(ENVIRONMENTS[0]);
    }

    function buildTabs(){
      const tabs = document.getElementById("envTabs");
      tabs.innerHTML = "";
      ENVIRONMENTS.forEach(env => {
        const btn = document.createElement("button");
        btn.className = "tab";
        btn.innerText = env;
        btn.onclick = () => setActiveEnv(env);
        tabs.appendChild(btn);
      });
    }

    function markActiveTab(){
      const all = document.querySelectorAll(".tab");
      all.forEach(btn => {
        if(btn.innerText === activeEnv) btn.classList.add("active");
        else btn.classList.remove("active");
      });
    }

    async function setActiveEnv(env){
      activeEnv = env;
      markActiveTab();
      await fetchInstances();
    }

    async function fetchInstances(){
      const tbody = document.querySelector("#instTable tbody");
      tbody.innerHTML = `<tr><td colspan="4" style="padding:18px;color:#9db4d6;">Loading $${activeEnv}…</td></tr>`;

      try{
        const res = await fetch(`$${API_ENDPOINT}?action=list&env=$${encodeURIComponent(activeEnv)}`, {
          headers: { "Authorization": encodedToken }
        });
        const data = await res.json();

        tbody.innerHTML = "";
        data.forEach(inst => {
          const row = document.createElement("tr");

          const state = (inst.State || "").toLowerCase();
          const dot  = state === "running" ? "dot-ok" : (state.includes("pending") ? "dot-pend" : "dot-stop");
          const pill = state === "running" ? "ok" : (state.includes("pending") ? "pend" : "stop");
          const actionText  = state === "running" ? "Stop" : "Start";
          const actionClass = state === "running" ? "btn btn-stop" : "btn btn-start";

          row.innerHTML =
            `<td>$${inst.Name || ""}</td>` +
            `<td>$${inst.InstanceId || ""}</td>` +
            `<td><span class="status-dot ${dot}"></span><span class="badge ${pill}">$${inst.State}</span></td>` +
            `<td class="row-actions"><button class="${actionClass}" onclick="toggleInstance('$${inst.InstanceId}','$${inst.State}')">${actionText}</button></td>`;

          tbody.appendChild(row);
        });

        if(data.length === 0){
          tbody.innerHTML = `<tr><td colspan="4" style="padding:18px;color:#9db4d6;">No instances found for $${activeEnv}.</td></tr>`;
        }
      }catch(err){
        tbody.innerHTML = `<tr><td colspan="4" style="padding:18px;color:#ffb2b2;">Failed to load instances for $${activeEnv}.</td></tr>`;
      }
    }

    async function toggleInstance(id, state){
      const action = state.toLowerCase() === "running" ? "stop" : "start";
      try{
        await fetch(`$${API_ENDPOINT}?action=$${action}&instance_id=$${encodeURIComponent(id)}`, {
          headers: { "Authorization": encodedToken }
        });
        setTimeout(fetchInstances, 900);
      }catch(err){
        alert("Action failed: " + (err?.message || err));
      }
    }
  </script>
</body>
</html>
