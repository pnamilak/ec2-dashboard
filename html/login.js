// html/login.js
// Fixed: API base resolution, JWT header, /services contract (instanceId), displayName fallback,
// and safer StartAll/StopAll bindings.  (Minimal changes; UI/flow unchanged.)

(() => {
  const API =
    (window.__API_BASE__ || window.API_BASE || localStorage.getItem("api_base_url") || "").replace(/\/+$/,"");
  const jwt = () => localStorage.getItem("jwt"); // token set at login page

  const hdrs = () => ({
    "Content-Type": "application/json",
    ...(jwt() ? { "Authorization": "Bearer " + jwt() } : {}),
  });

  // ========= ADDITIVE: Profile UI (compact CSS + modal + helpers) =========
  (function injectProfileUI(){
    try {
      const css = `
        .btn.xs { padding: 4px 8px !important; font-size: 11px !important; border-radius: 8px !important; }
        .profile-modal {
          position: fixed; inset: 0; display:none; align-items:center; justify-content:center;
          background: rgba(0,0,0,.45); z-index: 9999;
        }
        .profile-modal.show { display:flex; }
        .profile-card {
          width: 360px; max-width: 90vw; background: #121b2b; color: #e6e9ef;
          border-radius: 16px; padding: 18px; box-shadow: 0 12px 50px rgba(0,0,0,.5);
        }
        .profile-card h3 { margin: 0 0 10px 0; font-size: 18px; }
        .profile-row { display:flex; gap:8px; margin: 6px 0; font-size: 14px; }
        .profile-row .k { width: 80px; color:#9aa4b2; }
        .profile-actions { display:flex; justify-content:flex-end; gap:8px; margin-top:14px; }
      `;
      const s = document.createElement('style'); s.textContent = css; document.head.appendChild(s);

      const tpl = document.createElement('div');
      tpl.id = "profileModal";
      tpl.className = "profile-modal";
      tpl.innerHTML = `
        <div class="profile-card">
          <h3>Profile</h3>
          <div class="profile-row"><div class="k">Name</div><div id="pfName">—</div></div>
          <div class="profile-row"><div class="k">Email</div><div id="pfEmail">—</div></div>
          <div class="profile-row"><div class="k">Access</div><div id="pfRole">—</div></div>
          <div class="profile-actions">
            <button class="btn" id="pfClose" type="button">Close</button>
            <button class="btn danger" id="pfLogout" type="button">Logout</button>
          </div>
        </div>
      `;
      document.body.appendChild(tpl);
    } catch {}
  })();

  function pf_decodeJwtPayload(t){
    try {
      const parts = (t||"").split(".");
      if (parts.length < 2) return {};
      const json = atob(parts[1].replace(/-/g,"+").replace(/_/g,"/"));
      return JSON.parse(json)||{};
    } catch { return {}; }
  }

  function pf_getProfile(){
    const tok = localStorage.getItem("jwt") || "";
    const role = (localStorage.getItem("role") || "").toLowerCase();
    const payload = pf_decodeJwtPayload(tok);
    let rawUser = localStorage.getItem("user") || payload.sub || "";
    try {
      if (rawUser && rawUser.startsWith("{")) {
        rawUser = (JSON.parse(rawUser)||{}).username || payload.sub || "";
      }
    } catch {}

    const isEmail = /@/.test(rawUser);
    const email = isEmail ? rawUser : (/@/.test(payload.sub||"") ? (payload.sub||"") : "");
    let name = "";
    if (isEmail) name = rawUser.split("@")[0];
    else if (rawUser.includes("\\")) name = rawUser.split("\\").pop();
    else name = rawUser || (email ? email.split("@")[0] : "");
    if (name) name = name.charAt(0).toUpperCase() + name.slice(1);
    return { name: name || "—", email: email || "—", role: role || payload.role || "user" };
  }

  function pf_showProfile(){
    const m = document.getElementById("profileModal");
    if (!m) return;
    const {name, email, role} = pf_getProfile();
    const n = document.getElementById("pfName");
    const e = document.getElementById("pfEmail");
    const r = document.getElementById("pfRole");
    if (n) n.textContent = name;
    if (e) e.textContent = email;
    if (r) r.textContent = role;
    m.classList.add("show");
  }
  function pf_closeProfile(){ const m = document.getElementById("profileModal"); if (m) m.classList.remove("show"); }
  function pf_logout(){
    localStorage.removeItem("jwt");
    localStorage.removeItem("role");
    localStorage.removeItem("user");
    window.location.href = "./";
  }

  document.addEventListener("click", (e)=>{
    if (e.target && e.target.id === "pfClose")  { e.preventDefault(); pf_closeProfile(); }
    if (e.target && e.target.id === "pfLogout") { e.preventDefault(); pf_logout(); }
    if (e.target && e.target.id === "profileBtn"){ e.preventDefault(); pf_showProfile(); }
  });

  // Robust repurposing of an existing "Logout" button to "Profile"
  function pf_tryRepurposeLogout(){
    try {
      // 1) common selectors
      const selList = [
        '#logout', '.logout', 'button#logout', 'a#logout',
        'button[data-action="logout"]', 'a[data-action="logout"]'
      ];
      for (const sel of selList) {
        const el = document.querySelector(sel);
        if (el) { pf_rewireToProfile(el); return true; }
      }
      // 2) find by visible text content "Logout"
      const allBtns = Array.from(document.querySelectorAll('button, a'));
      for (const el of allBtns) {
        const txt = (el.textContent || '').trim().toLowerCase();
        if (txt === 'logout') { pf_rewireToProfile(el); return true; }
      }
      return false;
    } catch { return false; }
  }

  function pf_rewireToProfile(btn){
    try {
      btn.id = "profileBtn";
      btn.textContent = "Profile";
      btn.classList.add("xs");
      btn.removeAttribute('href'); // avoid navigation if it was an <a>
      btn.onclick = (e)=>{ e.preventDefault(); pf_showProfile(); };
    } catch {}
  }

  function pf_initProfileButton(){
    // First attempt immediately (in case button is already present)
    if (pf_tryRepurposeLogout()) return;

    // Fallback: if no Logout found, create a floating Profile button (non-destructive)
    const floating = document.getElementById("profileBtn");
    if (!floating) {
      const b = document.createElement("button");
      b.id = "profileBtn";
      b.className = "btn xs";
      b.textContent = "Profile";
      b.style.position = "fixed";
      b.style.top = "10px";
      b.style.right = "10px";
      b.style.zIndex = "9999";
      b.onclick = (e)=>{ e.preventDefault(); pf_showProfile(); };
      document.body.appendChild(b);
    }

    // Also observe DOM mutations (handles SPA loads / late renders)
    const obs = new MutationObserver((_muts)=>{
      pf_tryRepurposeLogout();
    });
    obs.observe(document.documentElement || document.body, { childList: true, subtree: true });
    // Give it a few periodic retries too (defensive)
    let tries = 0;
    const t = setInterval(()=>{
      if (pf_tryRepurposeLogout() || (++tries > 10)) clearInterval(t);
    }, 500);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", pf_initProfileButton);
  } else {
    pf_initProfileButton();
  }
  // ========= /ADDITIVE: Profile UI =========

  // ------------ Helpers ------------
  const q = (sel, el=document) => el.querySelector(sel);
  const qq = (sel, el=document) => Array.from(el.querySelectorAll(sel));

  function toast(msg) {
    console.log(msg);
    const el = q("#toast");
    if (!el) return;
    el.textContent = msg;
    el.classList.add("show");
    setTimeout(() => el.classList.remove("show"), 1800);
  }

  // Prevent accidental navigation to /services (e.g., <a href="/services">)
  document.addEventListener("click", (e) => {
    const a = e.target.closest('a[href="/services"]');
    if (a) { e.preventDefault(); e.stopPropagation(); }
  }, true);

  // ------------ Instances ------------
  let STATE = { envOrder: [], envs: {}, flat: [] };

  async function fetchInstances() {
    const r = await fetch(`${API}/instances`, { method:"GET", headers: hdrs() });
    const j = await r.json();
    if (!j.ok) throw new Error(j.error || "instances_failed");
    STATE.envs = j.envs || {};
    STATE.flat = j.instances || [];
    STATE.envOrder = Object.keys(STATE.envs).sort();

    renderTabs();
    renderEnv(STATE.envOrder[0] || "ALL");
  }

  // ------------ Render Tabs / Panels ------------
  function renderTabs() {
    const tabs = q("#tabs");
    if (!tabs) return;
    tabs.innerHTML = "";

    const add = (label) => {
      const b = document.createElement("button");
      b.className = "pill";
      b.textContent = label;
      b.onclick = () => renderEnv(label);
      tabs.appendChild(b);
    };

    if (STATE.envOrder.length === 0) add("Summary");
    else {
      add("Summary");
      STATE.envOrder.forEach(add);
    }
  }

  function instancesInEnv(env) {
    if (env === "Summary" || !STATE.envs || !STATE.envs[env]) return { DM: [], EA: [] };
    return STATE.envs[env];
  }

  function renderEnv(env) {
    const header = q("#envHeader");
    if (header) {
      header.textContent = `Env: ${env} • Total: ${STATE.flat.length} • `
        + `Running: ${STATE.flat.filter(x=>x.state==='running').length} • `
        + `Stopped: ${STATE.flat.filter(x=>x.state==='stopped').length}`;
    }

    const dm = q("#dmList"); const ea = q("#eaList");
    if (dm) dm.innerHTML = "";
    if (ea) ea.innerHTML = "";

    const groups = instancesInEnv(env);
    [ ["DM", dm], ["EA", ea] ].forEach(([role, mount]) => {
      if (!mount) return;
      (groups[role] || []).forEach(inst => mount.appendChild(instanceRow(inst)));
    });

    // wire group buttons safely
    const dmStart = q("#dm-start-all");
    const dmStop  = q("#dm-stop-all");
    const eaStart = q("#ea-start-all");
    const eaStop  = q("#ea-stop-all");
    if (dmStart) dmStart.onclick = () => startAll(env, "DM");
    if (dmStop)  dmStop.onclick  = () => stopAll(env, "DM");
    if (eaStart) eaStart.onclick = () => startAll(env, "EA");
    if (eaStop)  eaStop.onclick  = () => stopAll(env, "EA");
  }

  function instanceRow(inst) {
    const row = document.createElement("div");
    row.className = "inst-row";
    row.innerHTML = `
      <div class="inst-name">${inst.name || inst.id}</div>
      <span class="badge ${inst.state}">${inst.state}</span>
      <div class="actions">
        <button class="btn danger" data-op="stop" type="button">Stop</button>
        <button class="btn ok"     data-op="start" type="button">Start</button>
        <button class="btn warn"   data-svc="1"    type="button">Services</button>
      </div>
    `;
    const [btnStop, btnStart, btnSvc] = qq("button", row);

    if (btnStart) btnStart.onclick = () => doAction(inst.id, "start");
    if (btnStop)  btnStop.onclick  = () => doAction(inst.id, "stop");
    if (btnSvc)   btnSvc.addEventListener("click", (e) => { e.preventDefault(); e.stopPropagation(); openServices(inst); });

    if (btnStart && (inst.state || "").toLowerCase() === "running") btnStart.disabled = true;
    if (btnStop && (inst.state || "").toLowerCase() === "stopped") btnStop.disabled = true;

    return row;
  }

  async function doAction(id, op) {
    const r = await fetch(`${API}/instance-action`, {
      method:"POST", headers: hdrs(),
      body: JSON.stringify({ id, op })
    });
    const j = await r.json();
    if (!j.ok) { toast(j.error || "action_failed"); return; }
    toast(`${op} requested`);
    await fetchInstances();
  }

  async function startAll(env, role) {
    const ids = (instancesInEnv(env)[role] || []).map(x => x.id);
    if (!ids.length) return;
    await bulk("start", ids);
  }
  async function stopAll(env, role) {
    const ids = (instancesInEnv(env)[role] || []).map(x => x.id);
    if (!ids.length) return;
    await bulk("stop", ids);
  }
  async function bulk(op, ids) {
    const r = await fetch(`${API}/bulk-action`, {
      method:"POST", headers: hdrs(),
      body: JSON.stringify({ op, instanceIds: ids })
    });
    const j = await r.json();
    if (!j.ok) { toast(j.error || "bulk_failed"); return; }
    toast(`${op} all requested`);
    await fetchInstances();
  }

  // ------------ Services Modal ------------
  function decideMode(name) {
    const n = (name || "").toLowerCase();
    if (n.includes("sql")) return "sql";
    if (n.includes("redis")) return "redis";
    return "filter";
  }

  function openServices(inst) {
    const modal = q("#svcModal");
    if (!modal) return;
    // Always store instanceId (API contract)
    modal.dataset.iid = inst.instanceId || inst.id;
    modal.dataset.iname = inst.name || "";
    

    // NEW: hide IIS reset on SQL/Redis instances
    const modeForButtons = decideMode(modal.dataset.iname);
    const iisBtn = q("#svcIIS"); if (iisBtn) iisBtn.style.display = (modeForButtons === "filter") ? "" : "none";

    const title = q("#svcTitle");
    if (title) title.textContent = `Services – ${inst.name || inst.id} (${modal.dataset.iid})`;
    const rows = q("#svcRows");
    if (rows) rows.innerHTML = "";
    const inp = q("#svcQuery");
    if (inp) inp.value = "";
    modal.classList.add("show");
    listServices();
  }

  function closeServices() {
    const modal = q("#svcModal");
    if (modal) modal.classList.remove("show");
  }

async function listServices() {
  const modal = q("#svcModal");
  if (!modal) return;
  const iid   = modal.dataset.iid;
  const iname = modal.dataset.iname;
  const queryEl = q("#svcQuery");
  const query = (queryEl && queryEl.value ? queryEl.value.trim() : "");
  const mode  = decideMode(iname);

  // Hide IIS Reset for SQL/Redis
  const iisBtn = q("#svcIIS");
  if (iisBtn) iisBtn.style.display = (mode === "filter") ? "" : "none";

  const r = await fetch(`${API}/services`, {
    method: "POST",
    headers: hdrs(),
    body: JSON.stringify({ instanceId: iid, op: "list", mode, query })
  });
  const j = await r.json();

  const tbody = q("#svcRows");
  if (tbody) tbody.innerHTML = "";

  if (!j.ok) {
    if (tbody) {
      const tr = document.createElement("tr");
      tr.innerHTML = `<td colspan="4">${j.error || "error"}</td>`;
      tbody.appendChild(tr);
    }
    return;
  }

  // One-time delegated handler (survives re-renders)
  if (tbody && !tbody._bound) {
    tbody.addEventListener("click", (e) => {
      // FIX: only match the button itself (or its ancestors), not a descendant selector
      const b = e.target.closest("button[data-op]");
      if (!b) return;
      e.preventDefault();
      e.stopPropagation();

      const tr = b.closest("tr");
      const svcName = tr?.dataset.name || tr?.querySelector("td")?.textContent?.trim();
      const m = q("#svcModal");
      const iidNow   = m?.dataset.iid;
      const inameNow = m?.dataset.iname || "";

      if (!svcName) { toast("service name missing"); return; }
      changeService(iidNow, svcName, b.dataset.op, inameNow);
    });
    tbody._bound = true;
  }

  // Normalize to {name, display, status}
  const rows = (j.services || []).map(raw => {
    if (typeof raw === "string") {
      const [n = "", d = "", s = ""] = raw.split("|");
      return { name: n, display: d, status: (s || "unknown").toLowerCase() };
    }
    const name =
      raw.name ?? raw.Name ?? raw.service ?? raw.Service ?? raw.ServiceName ?? "";
    const display =
      raw.display ?? raw.displayName ?? raw.Display ?? raw.DisplayName ?? name;
    const status =
      (raw.status ?? raw.Status ?? raw.state ?? raw.State ?? "unknown").toLowerCase();
    return { name, display, status };
  });

  // Render
  rows.forEach((svc) => {
    const tr = document.createElement("tr");

    const name    = svc.name || "-";
    const display = svc.display || svc.displayName || "-";

    // Store for delegated click handler
    tr.dataset.name = name;

    const norm = (v) => {
      if (typeof v === "number") return ({ 1: "stopped", 4: "running" }[v]) || "unknown";
      return String(v || "unknown").toLowerCase();
    };
    const statusStr  = norm(svc.status);
    const showStatus = statusStr.charAt(0).toUpperCase() + statusStr.slice(1);

    let btns = "";
    if (statusStr === "running") {
      btns = `<button class="btn danger" data-op="stop"  type="button">Stop</button>`;
    } else if (statusStr === "stopped") {
      btns = `<button class="btn ok"     data-op="start" type="button">Start</button>`;
    } else {
      btns = `<button class="btn ok"     data-op="start" type="button">Start</button>
              <button class="btn danger" data-op="stop"  type="button">Stop</button>`;
    }

    tr.innerHTML = `
      <td>${name}</td>
      <td>${display}</td>
      <td><span class="badge ${statusStr}">${showStatus}</span></td>
      <td>${btns}</td>
    `;

    // Keep your existing per-row handlers (defensive; OK to leave)
    const btnStart = tr.querySelector('button[data-op="start"]');
    const btnStop  = tr.querySelector('button[data-op="stop"]');
    if (btnStart) btnStart.onclick = () => changeService(iid, name, "start", iname);
    if (btnStop ) btnStop .onclick = () => changeService(iid, name, "stop",  iname);

    if (btnStart && statusStr === "running") btnStart.disabled = true;
    if (btnStop  && statusStr === "stopped") btnStop.disabled  = true;

    tbody && tbody.appendChild(tr);
  });
}




async function changeService(iid, name, op, iname) {
  if (!name) { toast("service name missing"); return; }

  // Send op=start/stop (as proved by your PowerShell test).
  const payload = {
    instanceId: iid,
    id: iid,                    // legacy, harmless
    op,                         // <-- KEY: start/stop goes in `op`
    serviceName: name,
    service: name,              // legacy, harmless
    instanceName: iname || ""
  };

  const r = await fetch(`${API}/services`, {
    method: "POST",
    headers: hdrs(),
    body: JSON.stringify(payload)
  });
  const j = await r.json();
  if (!j.ok) {
    console.error("Service action failed:", j);
    toast(j.error || "svc_failed");
    return;
  }
  await listServices();
}



  // wire modal buttons
  document.addEventListener("click", (e) => {
    if (e.target.id === "svcClose") { e.preventDefault(); closeServices(); }
    if (e.target.id === "svcList")  { e.preventDefault(); listServices(); }
    if (e.target.id === "svcIIS")   { e.preventDefault(); iisReset(); }
  });

  async function iisReset() {
    const modal = q("#svcModal");
    if (!modal) return;
    const iid = modal.dataset.iid;
    const r = await fetch(`${API}/services`, {
      method:"POST", headers: hdrs(),
      body: JSON.stringify({ instanceId: iid, op:"iisreset" })
    });
    const j = await r.json();
    if (!j.ok) { toast(j.error || "iis_failed"); return; }
    toast("IIS restarted");
    await listServices();
  }

  // ------------ Init ------------
  window.DASH = { fetchInstances };

  fetchInstances().catch(err => {
    console.error(err);
    toast("Failed to load instances");
  });
})();
