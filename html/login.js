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

    const r = await fetch(`${API}/services`, {
      method:"POST", headers: hdrs(),
      body: JSON.stringify({ instanceId: iid, op:"list", mode, query })
    });
    const j = await r.json();

    const tbody = q("#svcRows");
    if (tbody) tbody.innerHTML = "";

    if (j && j.note === "not_connected") {
      const tr = document.createElement("tr");
      tr.innerHTML = `<td colspan="4">No services (SSM not connected)</td>`;
      if (tbody) tbody.appendChild(tr);
      return;
    }

    if (!j.ok) {
      const tr = document.createElement("tr");
      tr.innerHTML = `<td colspan="4">${j.error || "error"}</td>`;
      if (tbody) tbody.appendChild(tr);
      return;
    }

    (j.services || []).forEach(svc => {
      const name   = svc.name || svc.Name || "";
      const disp   = svc.display || svc.displayName || svc.DisplayName || "";
      const status = (svc.status || svc.Status || "unknown").toLowerCase();
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${name}</td>
        <td>${disp}</td>
        <td><span class="badge ${status}">${status}</span></td>
        <td>
          <button class="btn ok"     data-op="start" type="button">Start</button>
          <button class="btn danger" data-op="stop"  type="button">Stop</button>
        </td>
      `;
      const [btnStart, btnStop] = qq("button", tr);
      if (btnStart) btnStart.onclick = () => changeService(iid, name, "start");
      if (btnStop)  btnStop.onclick  = () => changeService(iid, name, "stop");
      if (btnStart && status === "running") btnStart.disabled = true;
      if (btnStop  && status === "stopped") btnStop.disabled = true;
      if (tbody) tbody.appendChild(tr);
    });
  }

  async function changeService(iid, name, op) {
    if (!name) { toast("service name missing"); return; }
    const r = await fetch(`${API}/services`, {
      method:"POST", headers: hdrs(),
      body: JSON.stringify({ instanceId: iid, op, serviceName: name })
    });
    const j = await r.json();
    if (!j.ok) { toast(j.error || "svc_failed"); return; }
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
