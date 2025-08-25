<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>EC2 Control Dashboard</title>
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin/>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600&display=swap" rel="stylesheet"/>
<style>
  :root{--bg:#0b1220;--card:#111a2b;--ink:#e5e7eb;--muted:#9ca3af;--accent:#60a5fa;--good:#34d399;--bad:#f87171}
  *{box-sizing:border-box} body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.4 Inter,system-ui,-apple-system,Segoe UI,Roboto}
  header.top{display:flex;gap:12px;align-items:center;padding:14px 18px;background:#0e172a;position:sticky;top:0}
  .pill{display:inline-flex;align-items:center;border:1px solid #334155;border-radius:999px;padding:2px 8px;font-size:12px;color:#cbd5e1}
  .btn{border:1px solid #334155;background:#1e293b;color:#e5e7eb;border-radius:10px;padding:8px 12px;cursor:pointer}
  .btn.primary{background:#1d4ed8;border-color:#1d4ed8} .btn.ghost{background:transparent}
  .wrap{padding:18px;max-width:1100px;margin:0 auto}
  .summary{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin:12px 0}
  .tile{background:var(--card);border:1px solid #1f2937;border-radius:16px;padding:16px;text-align:center}
  .tile .big{font-size:36px;font-weight:600}
  .tabs{display:flex;gap:8px;margin:8px 0 16px 0;flex-wrap:wrap}
  .tab{border:1px solid #334155;background:#0b1325;color:#cbd5e1;border-radius:999px;padding:6px 10px;cursor:pointer}
  .tab.active{background:#1d4ed8;border-color:#1d4ed8;color:#fff}
  .grid{display:grid;grid-template-columns:repeat(2,1fr);gap:12px}
  .card{background:var(--card);border:1px solid #1f2937;border-radius:16px;padding:12px}
  .head{display:flex;gap:8px;align-items:center}
  .name{max-width:340px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-weight:600}
  .meta{display:grid;grid-template-columns:repeat(2,1fr);gap:6px;margin-top:10px;color:#cbd5e1}
  .grow{flex:1}
  .empty{color:var(--muted);padding:18px;text-align:center}
  .bar{display:flex;gap:10px;align-items:center;margin:10px 0}
  input[type=text],input[type=email],input[type=password]{background:#0e172a;border:1px solid #243145;border-radius:10px;color:#e5e7eb;padding:8px 10px;width:100%}

  #login{position:fixed;inset:0;background:#0009;display:flex;align-items:center;justify-content:center}
  .modal{width:520px;max-width:92vw;background:#0e172a;border:1px solid #1f2937;border-radius:16px;padding:18px}
  .muted{color:#9ca3af}
  #svcModal{position:fixed;inset:0;background:#0009;display:flex;align-items:center;justify-content:center}
</style>
<script>window.API_URL = "${api_url}";</script>
</head>
<body>
  <header class="top">
    <div style="font-weight:600">EC2 Control Dashboard</div>
    <span class="pill">API: ${api_url}</span>
    <div class="grow"></div>
    <button id="refreshBtn" class="btn">Refresh</button>
    <button id="logoutBtn"  class="btn ghost">Logout</button>
  </header>

  <div class="wrap">
    <div class="bar">
      <input id="search" type="text" placeholder="Search by name, id, env, tag, ip…"/>
      <div class="tabs" id="envTabs"></div>
    </div>

    <div id="info"></div>
    <div id="grid" class="grid"></div>
  </div>

  <!-- BASIC login for API -->
  <section id="login" hidden>
    <div class="modal">
      <h3 style="margin:0 0 10px 0">Enter dashboard credentials</h3>
      <form id="loginForm">
        <label>Username</label>
        <input id="user" type="text" required/>
        <label>Password</label>
        <input id="pass" type="password" required/>
        <div id="loginErr" style="color:#fca5a5;margin:8px 0" hidden></div>
        <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:8px">
          <button id="signinBtn" type="submit" class="btn primary">Sign in</button>
        </div>
      </form>
    </div>
  </section>

  <!-- Details Modal -->
  <section id="svcModal" hidden>
    <div class="modal" style="width:760px">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">
        <div id="svcMeta" style="font-weight:600"></div>
        <span class="pill" id="osBadge">OS: -</span>
        <span class="pill" id="sqlBadge">SQL: -</span>
        <div class="grow"></div>
        <button id="btnIIS" class="btn" style="display:none">IIS Reset</button>
      </div>
      <div class="muted" style="margin-bottom:6px">
        Filter services by comma-separated text (matches Name or DisplayName on Windows).
      </div>
      <input id="svcPattern" type="text" placeholder="SQL,SQLServer,SQLSERVERAGENT,ServiceManagement" />
      <div id="svcErr" class="muted" style="color:#fca5a5;margin:8px 0" hidden></div>
      <div id="svcList" style="margin-top:10px"></div>
      <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:12px">
        <button id="svcClose" class="btn ghost">Close</button>
        <button id="svcRefresh" class="btn">Refresh</button>
      </div>
    </div>
  </section>

  <script defer src="app.v3.js?v=${js_ver_short}"></script>
</body>
</html>
