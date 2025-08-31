<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>EC2 Dashboard</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    :root{--bg:#0e1624;--panel:#121b2b;--ink:#e6e9ef;--mut:#9aa4b2;--ok:#2e9762;--bad:#b94a4a;--chip:#19243a;--brand:#7b8cff}
    *{box-sizing:border-box}
    body{margin:0;background:var(--bg);color:var(--ink);font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,"Helvetica Neue",sans-serif}
    .wrap{max-width:1100px;margin:28px auto;padding:0 16px}
    .row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
    .tile{background:var(--chip);padding:14px 18px;border-radius:14px;font-weight:700;box-shadow:0 0 0 1px #1c2840 inset}
    .tile.big{font-size:24px}
    .chip{padding:6px 10px;background:#1a2742;border-radius:12px;font-size:12px}
    .btn{padding:8px 14px;border-radius:12px;background:#203252;border:0;color:#dfe7f5;cursor:pointer}
    .btn.small{padding:6px 12px;font-size:12px}
    .btn.ok{background:var(--ok)}
    .btn.bad{background:var(--bad)}
    .tabs .tab{background:var(--chip);padding:8px 14px;border-radius:12px;cursor:pointer}
    .tabs .tab.active{outline:2px solid var(--brand)}
    .box{background:var(--panel);border-radius:14px;padding:14px 16px;margin:12px 0}
    .stack{display:flex;flex-direction:column;gap:10px}
    .rowline{display:flex;align-items:center;gap:10px;justify-content:space-between;background:#0f1a2e;border:1px solid #1c2840;border-radius:12px;padding:10px 12px}
    .mut{color:var(--mut);font-size:12px}
    .state{font-size:12px;color:#cfead9}
    .right{margin-left:auto}

    /* fatal error panel */
    .fatal{position:fixed;inset:16px auto auto 16px;max-width:min(760px,90vw);background:#2b1620;color:#ffd9de;border:1px solid #5a2533;border-radius:12px;padding:12px 14px;box-shadow:0 8px 30px rgba(0,0,0,.35);z-index:9999}
    .fatal b{display:block;margin-bottom:6px}
    .hidden{display:none}
  </style>
</head>
<body>
<div class="wrap" id="app">
  <div class="row" style="margin-bottom:12px">
    <div class="tile big" id="tTotal">Total: 0</div>
    <div class="tile big" id="tRun">Running: 0</div>
    <div class="tile big" id="tStop">Stopped: 0</div>
    <div class="right"></div>
    <div class="chip" id="userBadge" style="display:none"></div>
    <button class="btn small" id="btnSignOut">Sign out</button>
    <button class="btn small" id="btnRefresh">Refresh</button>
  </div>

  <div class="tabs row" id="envTabs"></div>
  <div id="envMount"></div>
</div>

<!-- fatal error panel -->
<div class="fatal hidden" id="fatal">
  <b>Something went wrong while loading the dashboard.</b>
  <div id="fatalMsg"></div>
</div>

<script>
(function(){
  // ----- CONFIG injected by Terraform -----
  const API_BASE = "${api_base_url}";
  // safer JSON parse for env names
  const ENV_NAMES = (function(raw){
    try{
      // Allow old "A,B,C" or JSON array. We prefer JSON array when available.
      if (raw.trim().startsWith("[")) return JSON.parse(raw);
      if (!raw) return [];
      return raw.split(",").map(s=>s.trim()).filter(Boolean);
    }catch(e){ return []; }
  })("${env_names}");
  const ALLOWED_DOMAIN = "${allowed_email_domain}";
  const VERSION = "${timestamp()}" // forces a new copy into caches each apply
  // ---------------------------------------

  // Helpers
  const $  = (id)=>document.getElementById(id);
  const showFatal = (msg)=>{
    $('fatalMsg').textContent = msg;
    $('fatal').classList.remove('hidden');
  };
  const http = (path, method, obj, bearer)=>{
    const h = {"content-type":"application/json"};
    if (bearer) h.authorization = "Bearer " + bearer;
    return fetch(API_BASE + path, {
      method,
      headers: h,
      body: obj ? JSON.stringify(obj) : undefined,
    }).then(async r=>{
      const data = await r.json().catch(()=> ({}));
      if (!r.ok) {
        const msg = (data && (data.error || data.message)) || ("http " + r.status);
        throw new Error(msg);
      }
      return data;
    });
  };

  // Show user badge if present
  const renderUser = ()=>{
    const u = localStorage.getItem("user");
    if (u) {
      try {
        const o = JSON.parse(u);
        $('userBadge').textContent = (o.name || o.username || "") + " • " + (o.role || "");
        $('userBadge').style.display = 'inline-block';
      } catch {}
    } else {
      $('userBadge').style.display = 'none';
    }
  };

  // Build tabs eagerly so page never looks empty
  const renderTabs = (envs)=>{
    const tabs = $('envTabs'); tabs.innerHTML = '';
    (ENV_NAMES.length ? ENV_NAMES : ['Default']).forEach((name, idx)=>{
      const b = document.createElement('div');
      b.className = 'tab';
      b.textContent = name;
      b.onclick = ()=>{ drawEnv(envs[name] || {DM:[],EA:[]}); setActive(idx); };
      tabs.appendChild(b);
    });
    function setActive(i){
      tabs.querySelectorAll('.tab').forEach((n,k)=>n.classList.toggle('active', k===i));
    }
    // initial draw
    const first = ENV_NAMES[0] || 'Default';
    setActive(0);
    drawEnv(envs[first] || {DM:[],EA:[]});
  };

  const btn = (txt, css, fn)=>{
    const b = document.createElement('button');
    b.textContent = txt; b.className = 'btn small ' + (css||''); b.onclick = fn;
    return b;
  };

  const drawEnv = (env)=>{
    const mount = $('envMount'); mount.innerHTML = '';
    [
      ['Dream Mapper','DM'],
      ['Encore Anywhere','EA']
    ].forEach(([title,key])=>{
      const box = document.createElement('div'); box.className='box';
      const head = document.createElement('div'); head.style.fontWeight='700'; head.style.marginBottom='8px';
      head.textContent = title; box.appendChild(head);
      const wrap = document.createElement('div'); wrap.className='stack';
      (env[key] || []).forEach(it=>{
        const line = document.createElement('div'); line.className='rowline';
        const left = document.createElement('div');
        left.innerHTML = "<b>"+(it.name||'')+"</b> <span class='mut'>("+(it.id||'')+")</span>";
        line.appendChild(left);
        const state = document.createElement('div'); state.className='state'; state.textContent = it.state||'';
        line.appendChild(state);
        const start = btn('Start','ok', ()=> act(it.id,'start'));
        const stop  = btn('Stop','bad', ()=> act(it.id,'stop'));
        if ((it.state||'').toLowerCase()==='running'){ start.disabled=true; } else { stop.disabled=true; }
        line.appendChild(start); line.appendChild(stop);
        // services button (modal from older version can be re-added if needed)
        line.appendChild(btn('Services','',()=> openServices(it)));
        wrap.appendChild(line);
      });
      box.appendChild(wrap); mount.appendChild(box);
    });
  };

  // Placeholder; you already have a services modal in your earlier copy.
  function openServices(it){
    alert('Services panel for ' + (it.name||it.id));
  }

  function act(id,what){
    http('/instance-action','POST',{id,action:what}, localStorage.getItem('jwt'))
      .then(()=> setTimeout(refresh, 1500))
      .catch(e=> alert(e.message||'action failed'));
  }

  function refresh(){
    const jwt = localStorage.getItem('jwt');
    if (!jwt){ location.href = 'login.html?v=' + VERSION; return; }
    http('/instances','GET',null,jwt).then(data=>{
      $('tTotal').textContent = "Total: "   + (data.summary?.total   ?? 0);
      $('tRun').textContent   = "Running: " + (data.summary?.running ?? 0);
      $('tStop').textContent  = "Stopped: " + (data.summary?.stopped ?? 0);
      renderTabs(data.envs || {});
    }).catch(err=>{
      // Token expired etc.
      if (String(err.message || '').toLowerCase().includes('unauthorized')){
        localStorage.removeItem('jwt');
        location.href = 'login.html?v=' + VERSION;
      } else {
        showFatal('Failed to load instances: ' + err.message);
      }
    });
  }

  // global error trap -> show panel instead of a blank page
  window.addEventListener('error', function(e){
    try { showFatal((e.error && e.error.message) ? e.error.message : (e.message || 'Unknown error')); }
    catch {}
  });

  // wire buttons
  $('btnRefresh').onclick = refresh;
  $('btnSignOut').onclick = ()=>{
    localStorage.removeItem('jwt');
    localStorage.removeItem('role');
    localStorage.removeItem('user');
    localStorage.removeItem('otp_verified');
    localStorage.removeItem('otp_email');
    location.href = 'login.html?v=' + VERSION;
  };

  // boot
  renderUser();
  refresh();
})();
</script>
</body>
</html>
