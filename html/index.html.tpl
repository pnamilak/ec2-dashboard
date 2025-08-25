<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>EC2 Control Dashboard</title>
  <style>
    :root{
      --bg1:#061225; --bg2:#0A2C5E; --bg3:#03203B;
      --panel:#0d1c33; --card:#0f213e; --muted:#9fb6d3; --text:#e8f0ff;
      --brand:#00A1E0; --ok:#22c55e; --warn:#f59e0b; --bad:#ef4444; --chip:#112747;
      --shadow: 0 10px 30px rgba(0,0,0,.35); --radius: 16px;
    }
    *{box-sizing:border-box}
    body{
      margin:0; color:var(--text); font:14px/1.35 system-ui,Segoe UI,Inter,Arial;
      background:
        radial-gradient(1200px 800px at 10% -10%, rgba(0,161,224,.18), transparent 60%),
        radial-gradient(900px 700px at 100% 20%, rgba(11,66,193,.18), transparent 60%),
        linear-gradient(180deg, var(--bg1), var(--bg3) 50%, #020a16);
    }
    header{position:sticky;top:0;z-index:5; backdrop-filter: blur(6px); background:rgba(2,10,22,.55); border-bottom:1px solid #133359}
    .bar{display:flex; align-items:center; gap:14px; padding:14px 18px; max-width:1200px; margin:0 auto}
    .brand{font-weight:700; letter-spacing:.2px}
    .grow{flex:1}
    .btn{cursor:pointer; border:1px solid #1d3b66; background:#0d2140; padding:8px 12px; border-radius:10px; color:#e5f2ff; box-shadow:var(--shadow)}
    .btn[disabled]{opacity:.45; cursor:not-allowed}
    .btn.primary{background-image:linear-gradient(180deg,#0F6CBD,#054d91); border-color:#0e5a9e}
    .btn.ghost{background:transparent; border-color:#20436f}
    main{max-width:1200px; margin:24px auto; padding:0 18px 60px}
    .filters{display:grid; grid-template-columns:1fr auto; gap:12px; align-items:center; margin:8px 0 18px}
    .tabs{display:flex; gap:8px; flex-wrap:wrap}
    .tab{padding:8px 10px; border-radius:999px; background:var(--chip); border:1px solid #284a80; cursor:pointer}
    .tab.active{outline:2px solid var(--brand)}
    .search{width:100%; padding:10px 12px; border-radius:10px; border:1px solid #284a80; background:#071327; color:#e8f0ff}
    .grid{display:grid; grid-template-columns:repeat(auto-fit,minmax(280px,1fr)); gap:14px}
    .card{background:linear-gradient(180deg,#0d213c,#0a1a31); border:1px solid #17365f; border-radius:var(--radius); box-shadow:var(--shadow)}
    .card > header{position:relative; top:auto; background:transparent; border-bottom:1px solid #15345c}
    .card .head{display:flex; gap:10px; align-items:center; padding:12px 14px}
    .name{font-weight:600; white-space:nowrap; overflow:hidden; text-overflow:ellipsis}
    .pill{padding:2px 8px; border-radius:999px; border:1px solid #17426d; background:#0a1a31; font-size:11px; color:#bfe6ff}
    .meta{display:grid; grid-template-columns:1fr 1fr; gap:8px; padding:10px 14px; color:#cde3ff}
    .kv{font-size:12px; opacity:.9}
    .empty, .error{padding:30px; text-align:center; color:#cde3ff; border:1px dashed #244e84; border-radius:var(--radius)}
    .modal{position:fixed; inset:0; display:flex; align-items:center; justify-content:center; background:rgba(3,10,22,.72); z-index:9999}
    .modal[hidden]{display:none !important;}
    .card-lg{width:760px; background:#0b1c33; border:1px solid #1b3c69; border-radius:18px; box-shadow:var(--shadow); padding:18px}
    .card-lg h2{margin:6px 0 12px; font-size:18px}
    .field{display:flex; flex-direction:column; gap:6px; margin:8px 0}
    .field input{padding:10px 12px; border:1px solid #244e84; border-radius:10px; background:#07152a; color:#e6f3ff}
    .hint{font-size:12px; color:#9fc3ec}
    .err{font-size:12px; color:#ff9aa3; margin-top:6px}
    .right{margin-left:auto}
    .summary{display:grid; grid-template-columns:repeat(3,minmax(160px,1fr)); gap:14px}
    .summary .tile{padding:18px; border-radius:16px; background:#0b1c33; border:1px solid #1b3c69; box-shadow:var(--shadow); text-align:center}
    .big{font-size:28px; font-weight:700}
  </style>
  <link rel="icon" href="data:,">
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
  <div class="modal" id="login">
    <div class="card-lg" style="width:380px;background:#0d1f3a;border:1px solid #1b3c69;">
      <h2>Sign in</h2>
      <div class="hint">Enter the Basic Auth credentials stored in SSM.</div>
      <form id="loginForm">
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
          <button class="btn primary" id="signinBtn" type="submit">Sign In</button>
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
        <button class="btn ghost" id="svcClose" type="button">Close</button>
        <button class="btn primary" id="svcRefresh" type="button">Refresh</button>
      </div>
    </div>
  </div>

  <script>
    window.API_URL='${api_url}'.replace(/\/$/,'');
    window.__APP_READY=false;
    try{
      var K='__ec2dash_build__';
      if (localStorage.getItem(K) !== '${js_ver}') {
        sessionStorage.removeItem('ec2dash.basic');
        localStorage.setItem(K, '${js_ver}');
      }
    }catch(_){}
  </script>
  <script src="/app.v3.js?v=${js_ver}" defer onload="window.__APP_READY=true;"></script>
</body>
</html>
