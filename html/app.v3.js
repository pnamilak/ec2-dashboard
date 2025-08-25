(function(){
  const $ = (id)=>document.getElementById(id);
  const API = window.API_URL;
  const LS_KEY='ec2dash.basic';
  const state={all:[],envs:[],activeEnv:'ALL',filterText:''};

  function token(){return sessionStorage.getItem(LS_KEY)||''}
  function setToken(t){sessionStorage.setItem(LS_KEY,t)}
  function clearToken(){sessionStorage.removeItem(LS_KEY)}

  function ui_login(show,msg){$('login').hidden=!show;if(msg){$('loginErr').hidden=false;$('loginErr').textContent=msg;} if(show){$('user').focus();}}
  async function signIn(ev){ if(ev) ev.preventDefault(); const u=$('user').value.trim(), p=$('pass').value;
    const t='Basic '+btoa(u+':'+p); setToken(t);
    try{ await loadInstances(true); ui_login(false);}catch(e){ clearToken(); ui_login(true,'Invalid credentials.');}}
  $('loginForm').addEventListener('submit',signIn); $('signinBtn').addEventListener('click',signIn);
  $('logoutBtn').addEventListener('click',()=>{clearToken(); ui_login(true);});
  $('refreshBtn').addEventListener('click',()=>loadInstances(false));
  $('search').addEventListener('input',(e)=>{state.filterText=e.target.value.trim().toLowerCase();render();});

  async function api(path,opts={}){
    const headers=Object.assign({'Authorization':token(),'Content-Type':'application/json'},opts.headers||{});
    const r=await fetch(API+path,Object.assign({},opts,{headers}));
    if(r.status===401||r.status===403) throw new Error('unauthorized');
    if(!r.ok) throw new Error(await r.text()||`HTTP ${r.status}`);
    return r.json();
  }

  function envFromName(n){n=(n||'').trim(); if(!n) return 'other'; const first=n.split('-',1)[0];
    let m=first.match(/^[a-z]{2,3}qa\d+/i); if(m) return m[0].toLowerCase();
    m=n.match(/[a-z]{2,3}qa\d+/i); if(m) return m[0].toLowerCase();
    m=n.toLowerCase().match(/prod|prd|ppe|stage|stg|uat|sit|qa|dev|test|dr/); if(m) return m[0]; return 'other'; }

  async function loadInstances(isProbe){
    $('info').innerHTML=`<div class="empty">Loading...</div>`;
    try{
      const data=await api('/instances');
      state.all=(data.items||[]).map(x=>({...x,env:envFromName(x.name)}));
      state.envs=['ALL',...Array.from(new Set(state.all.map(x=>x.env))).sort((a,b)=>a.localeCompare(b))];
      if(!isProbe){ summary(data.summary||{}); tabs(); render(); }
    }catch(e){ $('info').innerHTML=''; ui_login(true, e.message.includes('unauthorized')?'':('Error: '+e.message)); throw e; }
  }

  function summary(s){const {total=0,running=0,stopped=0}=s;
    $('info').innerHTML=`<div class="summary">
      <div class="tile"><div class="big">${total}</div><div>Total</div></div>
      <div class="tile"><div class="big">${running}</div><div>Running</div></div>
      <div class="tile"><div class="big">${stopped}</div><div>Stopped</div></div></div>`;}

  function tabs(){const box=$('envTabs'); box.innerHTML=''; state.envs.forEach(e=>{const b=document.createElement('button');
    b.className='tab'+(state.activeEnv===e?' active':''); b.textContent=e; b.onclick=()=>{state.activeEnv=e;render();}; box.appendChild(b);});}

  function render(){
    const grid=$('grid'); let list=state.all.slice();
    if(state.activeEnv!=='ALL') list=list.filter(x=>x.env===state.activeEnv);
    if(state.filterText){const t=state.filterText; list=list.filter(x=>(x.name||'').toLowerCase().includes(t)||(x.id||'').toLowerCase().includes(t));}
    if(!list.length){grid.innerHTML=`<div class="empty" style="grid-column:1/-1">No instances match.</div>`; return;}
    grid.innerHTML=list.map(x=>card(x)).join('');
    list.forEach(x=>{
      const s=$('start-'+x.id), t=$('stop-'+x.id), d=$('det-'+x.id);
      if(s) s.onclick=()=>instAction(x.id,'start');
      if(t) t.onclick=()=>instAction(x.id,'stop');
      if(d) d.onclick=()=>openDetails(x);
    });
  }

  function pill(st){
    const c=st==='running'?'style="border-color:#14532d;background:#0a1f12;color:#a7f3d0"':
              st==='stopped'?'style="border-color:#4b1d1d;background:#1a0b0b;color:#fecaca"':'';
    return `<span class="pill" ${c}>${st}</span>`;
  }

  function card(x){
    const canStart=x.state==='stopped', canStop=x.state==='running';
    return `<article class="card">
      <header class="head">
        <div class="name" title="${x.name}">${x.name}</div>
        <span class="pill">${x.env}</span>
        ${pill(x.state)}
        <div class="grow"></div>
        <button class="btn ghost" id="det-${x.id}">Details</button>
        ${canStart?`<button class="btn primary" id="start-${x.id}">Start</button>`:''}
        ${canStop?`<button class="btn" id="stop-${x.id}">Stop</button>`:''}
      </header>
      <div class="meta">
        <div class="kv">ID: ${x.id}</div>
        <div class="kv">Platform: ${x.platform}</div>
        <div class="kv">Private IP: ${x.privateIp||'-'}</div>
        <div class="kv">Public IP: ${x.publicIp||'-'}</div>
      </div>
    </article>`;
  }

  async function instAction(id, action){
    try{
      await api('/instances',{method:'POST',body:JSON.stringify({action,instanceId:id})});
      await loadInstances(false);
    }catch(e){ alert('Action failed: '+e.message); }
  }

  // ---------- Details modal ----------
  let current=null;

  function defaultPatternsFor(name){
    const n=(name||'').toLowerCase();
    if(n.includes('sql')) return 'SQL,SQLServer,SQLSERVERAGENT,MsDtsServer';
    if(n.includes('web')||n.includes('svc')||n.includes('iis')) return 'W3SVC,World Wide Web Publishing,AppHostSvc';
    if(n.includes('redis')) return 'redis';
    if(n.includes('rabbit')) return 'rabbit';
    return 'ServiceManagement';
  }

  function cssId(s){ return (s||'').replace(/[^a-z0-9]/ig,'_'); }

  function svcCard(s){
    const canStart=(''+s.Status).toLowerCase()==='stopped';
    const canStop =(''+s.Status).toLowerCase()==='running';
    const sid=cssId(s.Name);
    return `
      <article class="card">
        <header class="head">
          <div class="name" title="${s.DisplayName||s.Name}">${s.DisplayName||s.Name}</div>
          <span class="pill">${s.Name}</span>
          <span class="pill">${s.Status}</span>
          <div class="grow"></div>
          ${canStart?`<button class="btn primary" id="svc-start-${sid}">Start</button>`:''}
          ${canStop?`<button class="btn" id="svc-stop-${sid}">Stop</button>`:''}
        </header>
      </article>`;
  }

  async function svcAction(name, action){
    if(!current) return;
    try{
      await api('/instances',{method:'POST',body:JSON.stringify({action,instanceId:current.id,name})});
      await refreshServices();
    }catch(e){ alert('Service action failed: '+e.message); }
  }

  async function refreshServices(){
    if(!current) return;
    const pats=$('svcPattern').value.split(',').map(s=>s.trim()).filter(Boolean);
    $('svcErr').hidden=true;
    $('svcList').innerHTML=`<div class="muted">Querying services…</div>`;
    try{
      const res=await api('/instances',{method:'POST',body:JSON.stringify({action:'services_query',instanceId:current.id,patterns:pats})});
      const data=res.data||{};
      $('osBadge').textContent='OS: '+(data.os||'-');
      $('sqlBadge').textContent='SQL: '+(data.sql||'-');

      const svcs=data.services||[];
      if(!svcs.length){ $('svcList').innerHTML=`<div class="empty">No matching services.</div>`; }
      else{
        $('svcList').innerHTML=`<div class="grid">`+svcs.map(svc=>svcCard(svc)).join('')+`</div>`;
        svcs.forEach(s=>{
          const sid=cssId(s.Name);
          const start=$('svc-start-'+sid), stop=$('svc-stop-'+sid);
          if(start) start.onclick=()=>svcAction(s.Name,'service_start');
          if(stop)  stop.onclick =()=>svcAction(s.Name,'service_stop');
        });
      }
    }catch(e){
      $('svcErr').hidden=false;
      $('svcErr').textContent=e.message;
      $('svcList').innerHTML='';
    }
  }

  function openDetails(x){
    current=x;
    $('svcMeta').textContent=`${x.name} (${x.id})`;
    $('svcPattern').value=defaultPatternsFor(x.name);
    $('btnIIS').style.display=/web|svc|iis/i.test(x.name)?'inline-block':'none';
    $('osBadge').textContent='OS: -';
    $('sqlBadge').textContent='SQL: -';
    $('svcList').innerHTML='';
    $('svcErr').hidden=true;
    $('svcModal').hidden=false;
    refreshServices();
  }

  $('svcClose').onclick = ()=>{ $('svcModal').hidden=true; current=null; };
  $('svcRefresh').onclick = refreshServices;
  $('btnIIS').onclick = async ()=>{
    if(!current) return;
    try{
      const r=await api('/instances',{method:'POST',body:JSON.stringify({action:'iis_reset',instanceId:current.id})});
      alert(r.ok?'IIS Reset sent.':('IIS reset failed: '+(r.stderr||'unknown')));
    }catch(e){ alert('IIS reset error: '+e.message); }
  };

  (async function boot(){ if(token()){ try{await loadInstances(false); $('login').hidden=true;} catch{ui_login(true);} } else { ui_login(true); }})();
})();
