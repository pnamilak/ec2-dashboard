<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>EC2 Control Dashboard</title>
  <style>
    :root{
      --bg:#0e1420; --panel:#0f172a; --card:#111827; --muted:#94a3b8; --text:#e5e7eb;
      --brand:#60a5fa; --ok:#22c55e; --warn:#f59e0b; --bad:#ef4444; --chip:#1f2937;
      --shadow: 0 10px 30px rgba(0,0,0,.35); --radius: 16px;
    }
    *{box-sizing:border-box}
    body{margin:0; background:radial-gradient(1200px 800px at 20% -10%, #16223a 0%, #0e1420 50%, #0b1020 100%); color:var(--text); font:14px/1.35 system-ui,Segoe UI,Inter,Arial}
    header{position:sticky;top:0;z-index:5; backdrop-filter: blur(6px); background:rgba(17,24,39,.7); border-bottom:1px solid #1f2937}
    .bar{display:flex; align-items:center; gap:14px; padding:14px 18px; max-width:1200px; margin:0 auto}
    .brand{font-weight:700; letter-spacing:.2px}
    .grow{flex:1}
    .btn{cursor:pointer; border:1px solid #273449; background:#0f172a; padding:8px 12px; border-radius:10px; color:#e5e7eb; box-shadow:var(--shadow)}
    .btn[disabled]{opacity:.45; cursor:not-allowed}
    .btn.primary{background-image:linear-gradient(180deg,#1d4ed8,#143aa6); border-color:#23408a}
    .btn.ghost{background:transparent; border-color:#28364c}
    main{max-width:1200px; margin:24px auto; padding:0 18px 60px}
    .filters{display:grid; grid-template-columns:1fr auto; gap:12px; align-items:center; margin:8px 0 18px}
    .tabs{display:flex; gap:8px; flex-wrap:wrap}
    .tab{padding:8px 10px; border-radius:999px; background:var(--chip); border:1px solid #263245; cursor:pointer}
    .tab.active{outline:2px solid var(--brand)}
    .search{width:100%; padding:10px 12px; border-radius:10px; border:1px solid #263245; background:#0b1222; color:#e5e7eb}
    .grid{display:grid; grid-template-columns:repeat(auto-fit,minmax(280px,1fr)); gap:14px}
    .card{background:linear-gradient(180deg,#0e1628,#0b1322); border:1px solid #1f2a3f; border-radius:var(--radius); box-shadow:var(--shadow)}
    .card > header{position:relative; top:auto; background:transparent; border-bottom:1px solid #1d2a40}
    .card .head{display:flex; gap:10px; align-items:center; padding:12px 14px}
    .name{font-weight:600; white-space:nowrap; overflow:hidden; text-overflow:ellipsis}
    .pill{padding:2px 8px; border-radius:999px; border:1px solid #274061; background:#0c1628; font-size:11px; color:#c9dbff}
    .meta{display:grid; grid-template-columns:1fr 1fr; gap:8px; padding:10px 14px; color:#cbd5e1}
    .kv{font-size:12px; opacity:.9}
    .empty, .error{padding:30px; text-align:center; color:#cbd5e1; border:1px dashed #25324a; border-radius:var(--radius)}
    .modal{position:fixed; inset:0; display:flex; align-items:center; justify-content:center; background:rgba(3,6,20,.7); z-index:9999}
    .modal[hidden]{display:none !important;} /* keep modals hidden until JS shows them */
    .card-lg{width:720px; background:#0c1424; border:1px solid #24324c; border-radius:18px; box-shadow:var(--shadow); padding:18px}
    .card-lg h2{margin:6px 0 12px; font-size:18px}
    .field{display:flex; flex-direction:column; gap:6px; margin:8px 0}
    .field input{padding:10px 12px; border:1px solid #293753; border-radius:10px; background:#0a1020; color:#e6eefc}
    .hint{font-size:12px; color:#9fb1d0}
    .err{font-size:12px; color:#ff9aa3; margin-top:6px}
    .right{margin-left:auto}
    .summary{display:grid; grid-template-columns:repeat(3,minmax(160px,1fr)); gap:14px}
    .summary .tile{padding:18px; border-radius:16px; background:#0c1424; border:1px solid #24324c; box-shadow:var(--shadow); text-align:center}
    .big{font-size:28px; font-weight:700}
  </style>
  <link rel="icon" href="data:,"><!-- silence favicon 404 -->
</head>
<body>
  <header>
    <div class="bar">
      <div class="brand">EC2 Control Dashboard</div>
      <div class="pill" id="api-pill">API: <span id="api-base">${api_url}</span></div>
      <div class="pill" id="build-pill">Build: ${js_ver_short}</div>
      <div class="grow"></div>
      <button class="btn ghost" id="refreshBtn">Refresh</button>
      <button class="btn" id="logoutBtn">Logout</button>
    </div>
  </header>

  <main>
    <section class="filters">
      <input id="search" class="search" placeholder="Search by name, id, env, tag, ip…" />
      <div class="tabs" id="envTabs"></div>
    </section>

    <div id="info"></div>
    <section class="grid" id="grid"></section>
  </main>

  <!-- Login Modal -->
  <div class="modal" id="login" hidden>
    <div class="card-lg" style="width:380px">
      <h2>Sign in</h2>
      <div class="hint">Enter the Basic Auth credentials stored in SSM.</div>

      <form id="loginForm" onsubmit="event.preventDefault(); document.getElementById('signinBtn').click();">
        <div class="field">
          <label for="user">Username</label>
          <input id="user" autocomplete="username" />
        </div>
        <div class="field">
          <label for="pass">Password</label>
          <input id="pass" type="password" autocomplete="current-password" />
        </div>
        <div class="err" id="loginErr" hidden></div>
        <div style="display:flex; gap:10px; margin-top:10px; align-items:center">
          <button class="btn primary" id="signinBtn" type="button">Sign In</button>
          <div id="loginSpin" class="spinner" style="display:none"></div>
          <div class="hint right">Token is kept in session only.</div>
        </div>
      </form>
    </div>
  </div>

  <!-- Details Modal -->
  <div class="modal" id="svcModal" hidden>
    <div class="card-lg">
      <h2>Details</h2>
      <div id="svcMeta" class="pill"></div>
      <div style="display:flex; gap:10px; margin-top:10px; align-items:center;">
        <div class="pill" id="osBadge">OS: -</div>
        <div class="pill" id="sqlBadge">SQL: -</div>
        <button class="btn" id="btnIIS" style="display:none">IIS Reset</button>
      </div>
      <div class="hint" style="margin-top:10px">
        Filter services by comma-separated text (matches Name or DisplayName on Windows). Example:
        <code>SQL,SQLServer,SQLSERVERAGENT,ServiceManagement</code>
      </div>
      <div class="field">
        <label for="svcPattern">Patterns</label>
        <input id="svcPattern" placeholder="Type a service keyword…" />
      </div>
      <div id="svcErr" class="err" hidden></div>
      <div id="svcList" style="margin-top:8px"></div>
      <div style="display:flex; gap:10px; margin-top:12px; justify-content:flex-end">
        <button class="btn ghost" id="svcClose">Close</button>
        <button class="btn primary" id="svcRefresh">Refresh</button>
      </div>
    </div>
  </div>

  <!-- Build+token bootstrap -->
  <script>
    window.API_URL='${api_url}'.replace(/\/$/,'');
    window.__APP_READY=false;
    try{
      var K='__ec2dash_build__';
      if (localStorage.getItem(K) !== '${js_ver}') {
        sessionStorage.removeItem('ec2dash.basic'); // force login after each deploy
        localStorage.setItem(K, '${js_ver}');
      }
    }catch(_){}
  </script>
  <!-- Load the versioned JS; browsers cannot reuse an old build -->
  <script src="/app.v3.js?v=${js_ver}" defer onload="window.__APP_READY=true;"></script>
  <!-- Fallback: if JS didn't init, show login + hint -->
  <script>
    setTimeout(function(){
      if (!window.__APP_READY) {
        var m=document.getElementById('login'); if (m) m.hidden=false;
        var e=document.getElementById('loginErr'); if (e){ e.hidden=false; e.textContent='Hard refresh (Ctrl+F5 / Cmd+Shift+R) to load the latest app.'; }
      }
    }, 1200);
  </script>
</body>
</html>
