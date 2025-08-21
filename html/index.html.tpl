<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>EC2 Control Dashboard</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <style>
    :root{
      /* Theme */
      --bg1:#0f172a; --bg2:#0b1222;                    /* dark navy gradient */
      --card:#ffffff; --text:#0f172a; --muted:#64748b;
      --brand:#06b6d4; --brand2:#22d3ee;               /* teal/cyan accents */
      --green:#22c55e; --red:#ef4444;

      --radius:18px;
      --shadow-lg: 0 18px 40px rgba(2,6,23,.35);
      --shadow-md: 0 10px 24px rgba(2,6,23,.20);
      --ring: 0 0 0 4px rgba(34,211,238,.18);
    }

    /* Pleasant, professional background with faint grid */
    body{
      margin:0; min-height:100vh; color:var(--text);
      background:
        radial-gradient(1200px 800px at 20% 0%, rgba(45,92,132,.48) 0%, transparent 60%),
        radial-gradient(900px 700px at 90% 10%, rgba(32,87,128,.40) 0%, transparent 55%),
        linear-gradient(180deg, var(--bg1), var(--bg2));
      font-family: Inter, system-ui, Arial, sans-serif;
    }
    body::before{
      content:""; position:fixed; inset:0; pointer-events:none; opacity:.06;
      background:
        linear-gradient(90deg, #fff 1px, transparent 1px) 0 0/32px 32px,
        linear-gradient(#fff 1px, transparent 1px) 0 0/32px 32px;
      mix-blend-mode:overlay;
    }

    .container{
      width:min(1100px, calc(100% - 40px));
      margin:40px auto;
      display:flex; flex-direction:column; gap:22px; align-items:center;
    }

    .card{
      width:100%;
      background:var(--card);
      border-radius:var(--radius);
      padding:24px 24px 18px;
      box-shadow:var(--shadow-lg);
      border:1px solid rgba(255,255,255,.08);
      position:relative;
    }
    /* subtle gradient frame */
    .card.decor::before{
      content:""; position:absolute; inset:0; border-radius:var(--radius); padding:1px;
      background:linear-gradient(90deg, rgba(6,182,212,.35), rgba(34,211,238,.35));
      -webkit-mask:linear-gradient(#000 0 0) content-box, linear-gradient(#000 0 0);
      -webkit-mask-composite: xor; mask-composite: exclude;
      pointer-events:none;
    }

    .header{ display:flex; align-items:center; gap:10px; margin:4px 0 18px; }
    .title{
      font-size:22px; font-weight:800; margin:0; line-height:1.1;
      background:linear-gradient(90deg, var(--brand), var(--brand2));
      -webkit-background-clip:text; background-clip:text; color:transparent;
      letter-spacing:.2px;
    }
    .icon{ width:22px; height:22px; flex:0 0 22px; color:var(--brand); }

    label{ display:block; margin:10px 0 6px; font-weight:600; color:var(--muted); }

    input, select{
      width:100%; padding:12px 14px; border-radius:12px; border:1px solid #d1d5db;
      background:#fff; outline:0; transition:.18s; font-size:15px;
      box-shadow:var(--shadow-md);
    }
    input:focus, select:focus{ border-color:var(--brand); box-shadow:var(--ring); }

    .login-grid{ display:grid; gap:12px; }

    .actions{ margin-top:14px; display:flex; align-items:center; gap:12px; }

    .hidden{ display:none; }

    table{ width:100%; border-collapse:separate; border-spacing:0; margin-top:14px; }
    thead th{
      text-align:left; font-size:15px; color:#0f172a; background:#f8fafc;
      padding:12px 14px; border-bottom:1px solid #e5e7eb; position:sticky; top:0; z-index:1;
    }
    tbody td{ padding:12px 14px; border-bottom:1px solid #eef2f7; font-size:16px; }
    tbody tr:last-child td{ border-bottom:none; }

    /* Soft 3D buttons */
    .btn{
      display:inline-block; font-weight:700; letter-spacing:.2px;
      padding:10px 18px; border-radius:999px; border:0; cursor:pointer; color:#fff;
      transform:translateY(0);
      box-shadow:0 2px 0 rgba(2,6,23,.18), 0 10px 22px rgba(2,6,23,.22);
      transition:transform .08s ease, box-shadow .12s ease, filter .2s ease;
    }
    .btn:hover{ filter:brightness(1.03); }
    .btn:active{ transform:translateY(2px); box-shadow:0 1px 0 rgba(2,6,23,.22), 0 6px 14px rgba(2,6,23,.26); }

    .btn-primary{ background:linear-gradient(180deg, var(--brand2), var(--brand)); }
    .btn-start{ background:linear-gradient(180deg, #4ade80, var(--green)); }
    .btn-stop{  background:linear-gradient(180deg, #ff8a8a, var(--red)); }
  </style>
</head>
<body>
  <div class="container">

    <!-- Login -->
    <form class="card decor" id="loginForm" onsubmit="login(); return false;">
      <div class="header">
        <svg class="icon" viewBox="0 0 24 24" fill="none">
          <path d="M7 10V8a5 5 0 1 1 10 0v2" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
          <rect x="4" y="10" width="16" height="10" rx="2" stroke="currentColor" stroke-width="2"/>
          <circle cx="12" cy="15" r="1.5" fill="currentColor"/>
        </svg>
        <h2 class="title">EC2 Dashboard Login</h2>
      </div>

      <div class="login-grid">
        <div>
          <label>Username</label>
          <input type="text" id="username" placeholder="Enter username" autocomplete="username" />
        </div>
        <div>
          <label>Password</label>
          <input type="password" id="password" placeholder="Enter password" autocomplete="current-password" />
        </div>
      </div>

      <div class="actions">
        <button class="btn btn-primary" type="submit">Login</button>
        <span id="loginStatus" style="color:#dc2626; font-weight:600;"></span>
      </div>
    </form>

    <!-- Dashboard (hidden until login) -->
    <div id="dashboard" class="card decor hidden">
      <div class="header">
        <svg class="icon" viewBox="0 0 24 24" fill="none">
          <rect x="3" y="4"  width="18" height="6" rx="2" stroke="currentColor" stroke-width="2"/>
          <rect x="3" y="14" width="18" height="6" rx="2" stroke="currentColor" stroke-width="2"/>
          <circle cx="8" cy="7"  r="1" fill="currentColor"/>
          <circle cx="8" cy="17" r="1" fill="currentColor"/>
        </svg>
        <h2 class="title">EC2 Instance Start / Stop</h2>
      </div>

      <label for="env">Select Environment</label>
      <select id="env" onchange="fetchInstances()">
        <option value="">-- Choose --</option>
        <option>PRQA1</option>
        <option>PRQA2</option>
        <option>PRQA3</option>
        <option>PRQA6</option>
        <option>PNQA1</option>
        <option>AVQA1</option>
      </select>

      <table id="instTable">
        <thead>
          <tr>
            <th style="width:38%">Name</th>
            <th style="width:32%">Instance ID</th>
            <th style="width:15%">Status</th>
            <th style="width:15%">Action</th>
          </tr>
        </thead>
        <tbody></tbody>
      </table>
    </div>

  </div>

  <script>
    // Safety: ensure dashboard starts hidden even with caching
    document.addEventListener('DOMContentLoaded', () => {
      const dash = document.getElementById('dashboard');
      if (dash) dash.classList.add('hidden');
    });

    const API_ENDPOINT = "${api_url}/instances";
    let encodedToken = "";

    function login() {
      const user = document.getElementById("username").value.trim();
      const pass = document.getElementById("password").value.trim();

      if (!user || !pass) {
        document.getElementById("loginStatus").innerText = "Enter username and password";
        return;
      }

      encodedToken = btoa(user + ":" + pass);

      // Remove login, show dashboard
      const form = document.getElementById("loginForm");
      if (form) form.remove();

      const dash = document.getElementById("dashboard");
      dash.classList.remove("hidden");

      // Force environment pick after login
      const envSel = document.getElementById("env");
      if (envSel) envSel.value = "";
    }

    async function fetchInstances() {
      const env = document.getElementById("env").value;
      if (!env) return;

      const res = await fetch(API_ENDPOINT + "?action=list&env=" + encodeURIComponent(env), {
        headers: { "Authorization": encodedToken }
      });

      const data = await res.json();
      const tbody = document.querySelector("#instTable tbody");
      tbody.innerHTML = "";

      data.forEach(inst => {
        const row = document.createElement("tr");
        const action = inst.State === "running" ? "Stop" : "Start";
        const btnClass = inst.State === "running" ? "btn btn-stop" : "btn btn-start";

        row.innerHTML =
          "<td>" + inst.Name + "</td>" +
          "<td>" + inst.InstanceId + "</td>" +
          "<td>" + inst.State + "</td>" +
          "<td><button class=\"" + btnClass +
          "\" onclick=\"toggleInstance('" + inst.InstanceId + "', '" + inst.State + "')\">" + action + "</button></td>";

        tbody.appendChild(row);
      });
    }

    async function toggleInstance(id, state) {
      const action = state === "running" ? "stop" : "start";
      await fetch(API_ENDPOINT + "?action=" + action + "&instance_id=" + encodeURIComponent(id), {
        headers: { "Authorization": encodedToken }
      });
      fetchInstances();
    }
  </script>
</body>
</html>
