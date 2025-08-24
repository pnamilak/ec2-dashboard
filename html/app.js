(() => {
  const API = (window.API_URL || '').replace(/\/$/, '');
  const LS_KEY = 'ec2dash.basic';
  const qs = sel => document.querySelector(sel);
  const qsa = sel => Array.from(document.querySelectorAll(sel));

  const state = {
    raw: [],
    summary: { total: 0, running: 0, stopped: 0 },
    selectedEnv: 'Summary',
    filters: { q: '' },
    envs: new Set()
  };

  function authHeader(){ return { 'Authorization': sessionStorage.getItem(LS_KEY) || '' }; }

  async function api(path, opts={}){
    const res = await fetch(API + path, { ...opts, headers: { 'Content-Type':'application/json', ...(opts.headers||{}), ...authHeader() }});
    if (res.status === 401 || res.status === 403){
      // force re-login on any auth failure
      sessionStorage.removeItem(LS_KEY);
      throw new Error('AUTH');
    }
    if (!res.ok){ const text = await res.text(); throw new Error(text||res.statusText); }
    return res.json();
  }

  // --------- tabs & render ----------
  function renderEnvTabs(){
    const envTabs = qs('#envTabs');
    const envs = ['Summary', ...Array.from(state.envs).sort()];
    envTabs.innerHTML = '';
    envs.forEach(v=>{
      const b = document.createElement('button');
      b.className = 'tab' + (state.selectedEnv===v?' active':'');
      b.textContent = v;
      b.onclick = ()=>{ state.selectedEnv = v; draw(); };
      envTabs.appendChild(b);
    });
  }

  function draw(){
    const grid = qs('#grid'); const info = qs('#info');
    const q = state.filters.q.toLowerCase();

    if (state.selectedEnv === 'Summary'){
      info.innerHTML = '';
      grid.innerHTML = `
        <div class="summary">
          <div class="tile"><div>Total</div><div class="big">${state.summary.total}</div></div>
          <div class="tile"><div>Running</div><div class="big">${state.summary.running}</div></div>
          <div class="tile"><div>Stopped</div><div class="big">${state.summary.stopped}</div></div>
        </div>`;
      return;
    }

    const env = state.selectedEnv;
    const list = state.raw.filter(x =>
      (x.env===env) && (!q || `${x.name} ${x.id} ${x.env} ${x.service} ${x.ip} ${x.az} ${x.os}`.toLowerCase().includes(q))
    );

    if (!list.length){
      info.innerHTML = `<div class="empty">No instances in <b>${env}</b>.</div>`;
      grid.innerHTML = '';
      return;
    }
    info.innerHTML = `<div class="pill">Showing ${list.length} in ${env}</div>`;
    grid.innerHTML = list.map(cardHtml).join('');
    qsa('[data-action]').forEach(el=> el.onclick = onAction);
  }

  function cardHtml(x){
    const startDisabled = x.state!=='stopped';
    const stopDisabled  = x.state!=='running';
    return `<article class="card ${x.state}">
      <header class="head">
        <div class="dot"></div>
        <div class="name" title="${x.name}">${x.name||'(no-name)'}</div>
        <div class="pill right">${x.env||'—'}</div>
      </header>
      <div class="meta">
        <div class="kv">ID<br><b>${x.id}</b></div>
        <div class="kv">State<br><b>${x.state}</b></div>
        <div class="kv">OS<br><b>${x.os||'-'}</b></div>
        <div class="kv">Type<br><b>${x.type||'-'}</b></div>
        <div class="kv">AZ<br><b>${x.az||'—'}</b></div>
        <div class="kv">IP<br><b>${x.ip||'—'}</b></div>
      </div>
      <div class="actions">
        <button class="chip-btn" data-action="start"  data-id="${x.id}" ${startDisabled?'disabled':''}>Start</button>
        <button class="chip-btn" data-action="stop"   data-id="${x.id}" ${stopDisabled?'disabled':''}>Stop</button>
        <button class="chip-btn" data-action="reboot" data-id="${x.id}" ${stopDisabled?'':'disabled'}>Reboot</button>
        <button class="chip-btn" data-action="details" data-id="${x.id}" data-name="${x.name}">Details</button>
      </div>
    </article>`;
  }

  // --------- data load & login ----------
  async function load(){
    qs('#info').innerHTML = '<div class="pill">Loading…</div>';
    const token = sessionStorage.getItem(LS_KEY);
    if (!token){ showLogin(); qs('#info').innerHTML=''; return; } // <- do NOT call API before login
    try{
      const data = await api('/instances');
      state.raw = data.instances || [];
      state.summary = data.summary || { total: 0, running: 0, stopped: 0 };
      state.envs = new Set();
      state.raw.forEach(x=>{ if (x.env) state.envs.add(x.env); });
      if (state.selectedEnv !== 'Summary' && !state.envs.has(state.selectedEnv)) state.selectedEnv = 'Summary';
      renderEnvTabs();
      draw();
    }catch(err){
      if (err.message === 'AUTH'){ showLogin('Please sign in.'); }
      else qs('#info').innerHTML = `<div class="error">${err.message||'Failed loading'}</div>`;
    }
  }

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
  qs('#search').oninput = (e)=>{ state.filters.q = e.target.value; draw(); };

  // --------- actions & details ----------
  async function onAction(e){
    const id = e.currentTarget.dataset.id; const act = e.currentTarget.dataset.action; const name = e.currentTarget.dataset.name || '';
    if (act === 'details') return openDetails(id, name);
    const btns = qsa(`[data-id="${id}"]`);
    btns.forEach(b=>b.disabled=true);
    try{
      await api('/instances', {method:'POST', body:JSON.stringify({ action:act, instance_id:id })});
      await load();
    }catch(err){
      if (err.message==='AUTH'){ showLogin('Session expired. Please sign in.'); }
      else alert(err.message||String(err));
    }finally{ btns.forEach(b=>b.disabled=false); }
  }

  function byId(id){ return state.raw.find(x=>x.id===id); }

  let svcCtx = { id:'', name:'', role:'', lastOS:'', isWindows:false };

  function defaultPatternsFor(inst){
    const key = (inst.service || inst.name || '').toLowerCase();
    if (key.includes('sql')) return 'MSSQL,SQLServer,SQLSERVERAGENT,SQLAgent';
    if (key.includes('web') || key.includes('svc') || key.includes('iis')) return 'W3SVC,AppHostSvc,was,IIS';
    if (key.includes('redis')) return 'redis';
    return '';
  }

  async function openDetails(instanceId, name){
    const inst = byId(instanceId) || { service: '', os:'' };
    svcCtx = { id: instanceId, name: name, role: (inst.service||'').toLowerCase(), lastOS: inst.os||'', isWindows:false };
    qs('#svcMeta').textContent = `Instance: ${name||instanceId}`;
    const def = defaultPatternsFor(inst);
    qs('#svcPattern').value = def;
    qs('#svcErr').hidden = true; qs('#svcList').innerHTML = '';
    qs('#btnIIS').style.display = 'none';
    qs('#svcModal').hidden = false;
    await refreshDetails();
  }

  async function refreshDetails(){
    const patt = qs('#svcPattern').value.trim();
    try{
      const res = await api('/instances', { method:'POST', body: JSON.stringify({ action:'details', instance_id: svcCtx.id, pattern: patt }) });
      // badges
      qs('#osBadge').textContent = 'OS: ' + (res.OS || '-');
      qs('#sqlBadge').textContent = 'SQL: ' + (res.SQL || '-');
      svcCtx.isWindows = !!res.isWindows;
      // IIS Reset button visibility: Windows + role indicates web/SVC/IIS
      const showIIS = svcCtx.isWindows && (svcCtx.role.includes('web') || svcCtx.role.includes('svc') || svcCtx.role.includes('iis'));
      qs('#btnIIS').style.display = showIIS ? 'inline-block' : 'none';
      renderSvcList(res.Services || []);
    }catch(err){
      if (err.message==='AUTH'){ showLogin('Please sign in.'); qs('#svcModal').hidden=false; return; }
      qs('#svcErr').hidden = false; qs('#svcErr').textContent = err.message||'Failed to load details';
    }
  }

  function renderSvcList(items){
    if(!items.length){ qs('#svcList').innerHTML = '<div class="empty">No matching services.</div>'; return; }
    const rows = items.map(s=>{
      const st = (s.status||'').toLowerCase();
      const running = (st==='running' || st==='active');
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
      await refreshDetails();
    }catch(err){
      if (err.message==='AUTH'){ showLogin('Please sign in.'); }
      else alert(err.message||'Action failed');
    }finally{ e.currentTarget.disabled = false; }
  }

  // IIS Reset
  qs('#btnIIS').onclick = async ()=>{
    try{
      await api('/instances', { method:'POST', body: JSON.stringify({ action:'iis_reset', instance_id: svcCtx.id }) });
      alert('IIS reset command sent.');
    }catch(err){
      if (err.message==='AUTH'){ showLogin('Please sign in.'); }
      else alert(err.message||'IIS reset failed');
    }
  };

  qs('#svcClose').onclick = ()=>{ qs('#svcModal').hidden = true; };
  qs('#svcRefresh').onclick = ()=>{ refreshDetails(); };

  // boot: do not touch API until we have a token
  (async function(){
    if (!sessionStorage.getItem(LS_KEY)) { showLogin(); return; }
    await load();
  })();
})();
