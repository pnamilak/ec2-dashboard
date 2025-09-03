// html/login.js
// Minimal, UI-compatible fixes for env/grouping, bulk actions, and services.

(() => {
  const API = window.API_BASE || "";                 // from index.html template
  const token = () => localStorage.getItem("token"); // set at login

  const hdrs = () => ({
    "Content-Type": "application/json",
    "Authorization": "Bearer " + token()
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

  // ------------ Instances ------------
  let STATE = {
    envOrder: [],
    envs: {},       // same shape as API: { ENV: {DM:[], EA:[]} }
    flat: []        // all instances
  };

  async function fetchInstances() {
    const r = await fetch(`${API}/instances`, { method:"GET", headers: hdrs() });
    const j = await r.json();
    if (!j.ok) throw new Error(j.error || "instances_failed");
    STATE.envs = j.envs || {};
    STATE.flat = j.instances || [];

    // Keep tab order using keys; normalize to what API sends (already uppercased)
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
    if (env === "Summary" || !STATE.envs || !STATE.envs[env]) {
      return { DM: [], EA: [] };
    }
    return STATE.envs[env];
  }

  function renderEnv(env) {
    const header = q("#envHeader");
    header.textContent = `Env: ${env} • Total: ${STATE.flat.length} • `
      + `Running: ${STATE.flat.filter(x=>x.state==='running').length} • `
      + `Stopped: ${STATE.flat.filter(x=>x.state==='stopped').length}`;

    const dm = q("#dmList"); const ea = q("#eaList");
    dm.innerHTML = ""; ea.innerHTML = "";

    const groups = instancesInEnv(env);
    [ ["DM", dm], ["EA", ea] ].forEach(([role, mount]) => {
      (groups[role] || []).forEach(inst => mount.appendChild(instanceRow(inst)));
    });

    // wire group buttons
    q("#dm-start-all").onclick = () => startAll(env, "DM");
    q("#dm-stop-all").onclick  = () => stopAll(env, "DM");
    q("#ea-start-all").onclick = () => startAll(env, "EA");
    q("#ea-stop-all").onclick  = () => stopAll(env, "EA");
  }

  function instanceRow(inst) {
    const row = document.createElement("div");
    row.className = "inst-row";
    row.innerHTML = `
      <div class="inst-name">${inst.name || inst.id}</div>
      <span class="badge ${inst.state}">${inst.state}</span>
      <div class="actions">
        <button class="btn danger" data-op="stop">Stop</button>
        <button class="btn ok"     data-op="start">Start</button>
        <button class="btn warn"   data-svc="1">Services</button>
      </div>
    `;
    const [btnStop, btnStart, btnSvc] = qq("button", row);

    btnStart.onclick = () => doAction(inst.id, "start");
    btnStop.onclick  = () => doAction(inst.id, "stop");
    btnSvc.onclick   = () => openServices(inst);

    // disable inconsistent button by state
    if ((inst.state || "").toLowerCase() === "running") btnStart.disabled = true;
    if ((inst.state || "").toLowerCase() === "stopped") btnStop.disabled = true;

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
    await fetchInstances();   // refresh
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
  function openServices(inst) {
    const modal = q("#svcModal");
    modal.dataset.iid = inst.id;
    modal.dataset.iname = inst.name || "";
    q("#svcTitle").textContent = `Services – ${inst.name || inst.id} (${inst.id})`;
    q("#svcRows").innerHTML = "";
    q("#svcQuery").value = "";       // leave empty to auto-detect mode
    modal.classList.add("show");
    listServices();                  // initial list
  }

  function closeServices() {
    q("#svcModal").classList.remove("show");
  }

  async function listServices() {
    const iid   = q("#svcModal").dataset.iid;
    const iname = q("#svcModal").dataset.iname;
    const query = q("#svcQuery").value.trim();

    const r = await fetch(`${API}/services`, {
      method:"POST", headers: hdrs(),
      body: JSON.stringify({ id: iid, instanceName: iname, op:"list", query })
    });
    const j = await r.json();

    const tbody = q("#svcRows");
    tbody.innerHTML = "";

    if (!j.ok) {
      const tr = document.createElement("tr");
      tr.innerHTML = `<td colspan="4">${j.error || "error"}</td>`;
      tbody.appendChild(tr);
      return;
    }

    (j.services || []).forEach(svc => {
      const tr = document.createElement("tr");
      const status = (svc.status || "Unknown").toLowerCase();
      tr.innerHTML = `
        <td>${svc.name || ""}</td>
        <td>${svc.displayName || ""}</td>
        <td><span class="badge ${status}">${svc.status || "Unknown"}</span></td>
        <td>
          <button class="btn ok"   data-op="start">Start</button>
          <button class="btn danger" data-op="stop">Stop</button>
        </td>
      `;
      const [btnStart, btnStop] = qq("button", tr);
      btnStart.onclick = () => changeService(iid, svc.name, "start");
      btnStop.onclick  = () => changeService(iid, svc.name, "stop");
      if (status === "running") btnStart.disabled = true;
      if (status === "stopped") btnStop.disabled = true;
      tbody.appendChild(tr);
    });
  }

  async function changeService(iid, name, op) {
    const r = await fetch(`${API}/services`, {
      method:"POST", headers: hdrs(),
      body: JSON.stringify({ id: iid, op, serviceName: name })
    });
    const j = await r.json();
    if (!j.ok) { toast(j.error || "svc_failed"); return; }
    await listServices();
  }

  // wire modal buttons
  document.addEventListener("click", (e) => {
    if (e.target.id === "svcClose") closeServices();
    if (e.target.id === "svcList")  listServices();
    if (e.target.id === "svcIIS")   iisReset();
  });

  async function iisReset() {
    const iid = q("#svcModal").dataset.iid;
    const r = await fetch(`${API}/services`, {
      method:"POST", headers: hdrs(),
      body: JSON.stringify({ id: iid, op:"iisreset" })
    });
    const j = await r.json();
    if (!j.ok) { toast(j.error || "iis_failed"); return; }
    toast("IIS restarted");
    await listServices();
  }

  // ------------ Init ------------
  window.DASH = { fetchInstances }; // tiny hook if you need it in console

  // start immediately after login page sets token
  fetchInstances().catch(err => {
    console.error(err);
    toast("Failed to load instances");
  });
})();
