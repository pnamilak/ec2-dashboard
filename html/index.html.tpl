<!doctype html><html><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>EC2 Control Dashboard</title>
<style>
/* (same styles as before) */
</style>
<script>window.API_URL="${api_url}";</script>
</head><body>
<header class="top">
  <div style="font-weight:600">EC2 Control Dashboard</div>
  <span class="pill">API: ${api_url}</span><div class="grow"></div>
  <button id="refreshBtn" class="btn">Refresh</button>
  <button id="logoutBtn" class="btn ghost">Logout</button>
</header>
<div class="wrap">
  <div class="bar"><input id="search" type="text" placeholder="Search by name, id, env, tag, ip…"/><div class="tabs" id="envTabs"></div></div>
  <div id="info"></div><div id="grid" class="grid"></div>
</div>

<!-- BASIC login for API -->
<section id="login" hidden>
  <div class="modal">
    <h3 style="margin:0 0 10px 0">Enter dashboard credentials</h3>
    <form id="loginForm">
      <label>Username</label><input id="user" type="text" required/>
      <label>Password</label><input id="pass" type="password" required/>
      <div id="loginErr" style="color:#fca5a5;margin:8px 0" hidden></div>
      <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:8px">
        <button id="signinBtn" type="submit" class="btn primary">Sign in</button>
      </div>
    </form>
  </div>
</section>

<!-- Details modal (same as before) -->
<section id="svcModal" hidden> ... </section>

<script defer src="app.v3.js?v=${js_ver_short}"></script>
</body></html>
