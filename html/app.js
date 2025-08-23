(() => {
  const API = (window.API_URL || '').replace(/\/$/, '');
  const LS_KEY = 'ec2dash.basic';
  const qs = sel => document.querySelector(sel);
  const qsa = sel => Array.from(document.querySelectorAll(sel));

  const state = { raw: [], view: [], filters: { env:'All', svc:'All', st:'All', q:'' }, envs: new Set(), svcs: new Set() };

  function encodeBasic(u,p){ return 'Basic ' + btoa(`${u}:${p}`); }
  function authHeader(){ return { 'Authorization': sessionStorage.getItem(LS_KEY) || '' }; }

  async function api(path, opts={}){
    const res = await fetch(API + path, { ...opts, headers: { 'Content-Type':'application/json', ...(opts.headers||{}), ...authHeader() }});
    if (res.status === 401 || res.status === 403){ throw new Error('AUTH'); }
    if (!res.ok){ const text = await res.text(); throw new Error(text||res.statusText); }
    return res.json();
  }

  function renderTabs(){
    const envTabs = qs('#envTabs'); const svcTabs = qs('#svcTabs'); const stTabs = qs('#stateTabs');
    envTabs.innerHTML = ''; svcTabs.innerHTML = ''; stTabs.innerHTML = '';
    const envs = ['All', ...Array.from(state.envs).sort()];
    const svcs = ['All', ...Array.from(state.svcs).sort()];
    const sts  = ['All','running','stopped','pending','stopping'];
    for (const [arr,root,key] of [[envs,envTabs,'env'],[svcs,svcTabs,'svc'],[sts,stTabs,'st']]){
      arr.forEach(v=>{
        const b = document.createElement('button'); b.className='tab' + (state.filters[key]===v?' active':''); b.textContent=v; b.onclick=()=>{state.filters[key]=v; filter();}; root.appendChild(b);
      })
    }
  }

  function filter(){
    const q = state.filters.q.toLowerCase();
    const env = state.filters.env; const svc = state.filters.svc; const st = state.filters.st;
    state.view = state.raw.filter(x =>
      (env==='All'||x.env===env) && (svc==='All'||x.service===svc) && (st==='All'||x.state===st) &&
      (!q || `${x.name} ${x.id} ${x.env} ${x.service} ${x.ip} ${x.az}`.toLowerCase().includes(q))
    );
    draw();
  }

  function cardHtml(x){
    const cls = x.state;
    return `<article class="card ${cls}">
      <header class="head">
        <div class="dot"></div>
        <div class="name" title="${x.name}">${x.name||'(no-name)'}</div>
        <div class="pill right">${x.env||'—'}</div>
      </header>
      <div class="meta">
        <div class="kv">ID<br><b>${x.id}</b></div>
        <div class="kv">State<br><b>${x.state}</b></div>
        <div class="kv">Svc<br><b>${x.service||'—'}</b></div>
        <div class="kv">AZ<br><b>${x.az||'—'}</b></div>
        <div class="kv">IP<br><b>${x.ip||'—'}</b></div>
        <div class="kv">SSM<br><b>${x.ping||'—'}</b></div>
      </div>
      <div class="status">${x.desc||''}</div>
      <div class="actions">
        <button class="chip-btn" data-action="start"  data-id="${x.id}" ${x.state!=='stopped'?'disabled':''}>Start</button>
        <button class="chip-btn" data-action="stop"   data-id="${x.id}" ${x.state!=='running'?'disabled':''}>Stop</button>
        <button class="chip-btn" data-action="reboot" data-id="${x.id}" ${x.state!=='running'?'disabled':''}>Reboot</button>
        <button class="chip-btn" data-action="services" data-id="${x.id}" data-name="${x.name}">Services</button>
      </div>
    </article>`;
  }

  function draw(){
    const grid = qs('#grid'); const info = qs('#info');
    if (!state.view.length){ grid.innerHTML=''; info.innerHTML='<div class="empty">No instances found. Try different filters.</div>'; return; }
    info.innerHTML = `<div class="pill">Showing ${state.view.length} of ${state.raw.length}</div>`;
    grid.innerHTML = state.view.map(cardHtml).join('');
    qsa('[data-action]').forEach(el=> el.onclick = onAction);
  }

  function inferSets(list){
    state.envs.clear(); state.svcs.clear();
    list.forEach(x=>{ if (x.env) state.envs.add(x.env); if (x.service) state.svcs.add(x.service); });
  }

  async function load(){
    qs('#info').innerHTML = '<div class="pill">Loading…</div>';
    try{
      const data = await api('/instances');
      state.raw = data.instances || [];
      inferSets(state.raw);
      renderTabs();
      filter();
    }catch(err){
      if (err.message==='AUTH'){ showLogin('Session expired or invalid credentials.'); }
      else qs('#info').innerHTML = `<div class="error">${err.message||'Failed loading'}</div>`;
    }
  }

  // ---- login handling ----
  function showLogin(msg){
    qs('#login').hidden=false; qs('#loginErr').hidden=!msg; qs('#loginErr').textContent=msg||'';
  }
  function hideLogin(){ qs('#login').hidden=true; }

  qs('#signinBtn').onclick = async ()=>{
    const u = qs('#user').value.trim(); const p = qs('#pass').value;
    if(!u||!p){ qs('#loginErr').hidden=false; qs('#loginErr').textContent='Please enter username and password.'; return; }
    qs('#loginSpin').style.display='inline-block'; qs('#loginErr').hidden=true;
    try{
      const token = 'Basic ' + btoa(`${u}:${p}`); sessionStorage.setItem(LS_KEY, token);
      await load(); hideLogin();
    }catch(err){
      sessionStorage.removeItem(LS_KEY);
      qs('#loginErr').hidden=false; qs('#loginErr').textContent = (err.message==='AUTH')? 'Invalid username or password.' : (err.message||'Login failed');
    }finally{ qs('#loginSpin').style.display='none'; }
  };

  qs('#logoutBtn').onclick = ()=>{ sessionStorage.removeItem(LS_KEY); showLogin(); };
  qs('#refreshBtn').onclick = ()=> load();
  qs('#search').oninput = (e)=>{ state.filters.q = e.target.value; filter(); };

  // ---- instance actions + service explorer ----
  async function onAction(e){
    const id = e.currentTarget.dataset.id; const act = e.currentTarget.dataset.action; const name = e.currentTarget.dataset.name || '';
    if (act === 'services') { return openServices(id, name); }
    const btns = qsa(`[data-id="${id}"]`);
    btns.forEach(b=>b.disabled=true);
    try{
      await api('/instances', {method:'POST', body:JSON.stringify({ action:act, instance_id:id })});
      await load();
    }catch(err){ alert(err.message||String(err)); }
    finally{ btns.forEach(b=>b.disabled=false); }
  }

  let svcCtx = { id:'', name:'' };

  async function openServices(instanceId, name){
    svcCtx = { id: instanceId, name: name };
    qs('#svcMeta').textContent = `Instance: ${name||instanceId}`;
    qs('#svcErr').hidden = true; qs('#svcList').innerHTML = '';
    qs('#svcModal').hidden = false;
    await refreshServices();
  }

  async function refreshServices(){
    const patt = qs('#svcPattern').value.trim();
    try{
      const res = await api('/instances', { method:'POST', body: JSON.stringify({ action:'services_query', instance_id: svcCtx.id, pattern: patt }) });
      renderSvcList(res.Services || []);
    }catch(err){
      qs('#svcErr').hidden = false; qs('#svcErr').textContent = err.message||'Failed to load services';
    }
  }

  function renderSvcList(items){
    if(!items.length){ qs('#svcList').innerHTML = '<div class="empty">No matching services.</div>'; return; }
    const rows = items.map(s=>{
      const running = (s.status||'').toLowerCase()==='running' || (s.status||'').toLowerCase()==='active';
      const btn = running
        ? `<button class="chip-btn" data-svc-act="stop" data-svc-name="${s.name}">Stop</button>`
        : `<button class="chip-btn" data-svc-act="start" data-svc-name="${s.name}">Start</button>`;
      return `<tr>
        <td style="padding:8px 10px; border-bottom:1px solid #23314a"><code>${s.name}</code></td>
        <td style="padding:8px 10px; border-bottom:1px solid #23314a">${s.displayName||''}</td>
        <td style="padding:8px 10px; border-bottom:1px solid #23314a">${s.status}</td>
        <td style="padding:8px 10px; border-bottom:1px solid #23314a">${btn}</td>
      </tr>`;
    }).join('');
    qs('#svcList').innerHTML = `<table style="width:100%; border-collapse:collapse; font-size:13px"><thead><tr>
      <th style="text-align:left; padding:8px 10px; border-bottom:1px solid #23314a">Name</th>
      <th style="text-align:left; padding:8px 10px; border-bottom:1px solid #23314a">Display Name</th>
      <th style="text-align:left; padding:8px 10px; border-bottom:1px solid #23314a">Status</th>
      <th style="text-align:left; padding:8px 10px; border-bottom:1px solid #23314a">Action</th>
    </tr></thead><tbody>${rows}</tbody></table>`;
    qsa('[data-svc-act]').forEach(el=> el.onclick = onSvcToggle);
  }

  async function onSvcToggle(e){
    const act = e.currentTarget.dataset.svcAct; const svc = e.currentTarget.dataset.svcName;
    e.currentTarget.disabled = true;
    try{
      await api('/instances', { method:'POST', body: JSON.stringify({ action: act==='start'?'service_start':'service_stop', instance_id: svcCtx.id, service: svc }) });
      await refreshServices();
    }catch(err){ alert(err.message||'Action failed'); }
    finally{ e.currentTarget.disabled = false; }
  }

  qs('#svcClose').onclick = ()=>{ qs('#svcModal').hidden = true; };
  qs('#svcRefresh').onclick = ()=>{ refreshServices(); };

  // boot
  (async function(){
    if (!sessionStorage.getItem(LS_KEY)) showLogin();
    await load();
  })();
})();
