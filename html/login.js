/* html/login.js — 2025-09-02
   Fixes:
   - Start all / Stop all (per card) wired to /bulk-action
   - Services modal shows Name/DisplayName/Status, Start/Stop works
   - No UI layout change; selectors are built from the same card markup
*/

(() => {
  const API_BASE = window.API_BASE || ""; // leave as in your HTML
  const LS = window.localStorage;
  let JWT = LS.getItem("jwt") || "";
  let STATE = {
    activeEnv: null,      // e.g. "NAQA6"
    all: [],              // flat instances from /instances
    envs: {},             // grouped { ENV: { DM:[], EA:[] } }
  };

  // ---------- helpers ----------
  function authHeaders() {
    const h = { "Content-Type": "application/json" };
    if (JWT) h["Authorization"] = "Bearer " + JWT;
    return h;
  }
  async function api(path, method = "GET", body) {
    const res = await fetch(API_BASE + path, {
      method,
      headers: authHeaders(),
      body: body ? JSON.stringify(body) : undefined,
    });
    if (!res.ok) throw new Error(res.status + " " + res.statusText);
    return await res.json();
  }
  const $$ = (sel, el=document) => Array.from(el.querySelectorAll(sel));
  const $ = (sel, el=document) => el.querySelector(sel);
  const byText = (btn, txt) => btn && btn.textContent.trim().toLowerCase() === txt;

  function pill(status) {
    const s = (status||"").toLowerCase();
    const cls = s === "running" ? "ok" : (s === "stopped" ? "warn" : "");
    return `<span class="pill ${cls}">${s}</span>`;
  }

  // ---------- render ----------
  function renderSummaryBar(sum, envKey) {
    const el = $("#env-summary");
    if (!el) return;
    const t = envKey || STATE.activeEnv || "ALL";
    el.innerHTML = `Env: ${t} • Total: ${sum.total} • Running: ${sum.running} • Stopped: ${sum.stopped}`;
  }

  function envOrder(envs) {
    // keep deterministic order; Summary first is handled by HTML/tabs
    return Object.keys(envs).sort((a,b) => a.localeCompare(b, undefined, {numeric:true}));
  }

  function setActiveEnv(k) {
    STATE.activeEnv = k;
    render();
  }

  function renderTabs() {
    const tabs = $("#tabs");
    if (!tabs) return;
    const envKeys = envOrder(STATE.envs);
    // keep existing "Summary" tab; rebuild other env tabs
    const container = $("#env-tabs");
    if (!container) return;

    container.innerHTML = "";
    for (const k of envKeys) {
      const b = document.createElement("button");
      b.className = "tab";
      b.dataset.env = k;
      b.textContent = k;
      if (k === STATE.activeEnv) b.classList.add("active");
      container.appendChild(b);
    }
  }

  function sectionHtml(title, items) {
    // items = [{id,name,state,...}]
    const ids = items.map(x=>x.id).join(",");
    const rows = items.map(x => `
      <div class="inst">
        <div class="inst-name">${x.name || x.id}</div>
        <div class="inst-state">${pill(x.state)}</div>
        <div class="inst-actions">
          ${x.state === "running"
            ? `<button class="btn btn-stop" data-act="stop" data-id="${x.id}">Stop</button>`
            : `<button class="btn btn-start" data-act="start" data-id="${x.id}">Start</button>`}
          <button class="btn btn-svc" data-svcs="open" data-id="${x.id}" data-name="${x.name || ""}">Services</button>
        </div>
      </div>
    `).join("");

    return `
      <div class="card" data-ids="${ids}">
        <div class="card-head">
          <div class="card-title">${title}</div>
          <div class="card-tools">
            <button class="btn" data-bulk="start">Start all</button>
            <button class="btn" data-bulk="stop">Stop all</button>
          </div>
        </div>
        <div class="card-body">${rows || `<div class="empty">No instances</div>`}</div>
      </div>
    `;
  }

  function renderEnv(envKey) {
    const root = $("#cards");
    if (!root) return;
    const env = STATE.envs[envKey] || {DM:[], EA:[]};
    root.innerHTML = `
      ${sectionHtml("Dream Mapper", env.DM)}
      ${sectionHtml("Encore Anywhere", env.EA)}
    `;
    // summary for this env only
    const all = [...env.DM, ...env.EA];
    renderSummaryBar({
      total: all.length,
      running: all.filter(x=>x.state==="running").length,
      stopped: all.filter(x=>x.state==="stopped").length
    }, envKey);
  }

  function render() {
    if (!STATE.activeEnv) {
      // pick first non-empty, else first key
      const keys = envOrder(STATE.envs);
      STATE.activeEnv = keys.find(k => (STATE.envs[k].DM.length+STATE.envs[k].EA.length) > 0) || keys[0] || "ALL";
    }
    renderTabs();
    renderEnv(STATE.activeEnv);
  }

  // ---------- data ----------
  async function refreshInstances() {
    const res = await api("/instances", "GET");
    if (!res.ok) throw new Error(res.error || "instances failed");
    STATE.all = res.instances || [];
    STATE.envs = res.envs || { ALL: {DM:[],EA:[]} };
    renderSummaryBar(res.summary || {total:0,running:0,stopped:0}, STATE.activeEnv);
    render();
  }

  // ---------- actions ----------
  async function doAction(id, op) {
    const res = await api("/instance-action", "POST", { instanceId: id, op });
    if (!res.ok) throw new Error(res.error || "instance-action failed");
    await refreshInstances();
  }
  async function doBulk(ids, op) {
    if (!ids.length) return;
    const res = await api("/bulk-action", "POST", { instanceIds: ids, op });
    if (!res.ok) throw new Error(res.error || "bulk-action failed");
    await refreshInstances();
  }

  // ---------- services modal ----------
  const svcModal = {
    root: null,
    tbody: null,
    q: null,
    iid: null,
    iname: null
  };

  function ensureSvcModal() {
    if (svcModal.root) return;
    const el = document.createElement("div");
    el.className = "modal";
    el.innerHTML = `
      <div class="modal-box">
        <div class="modal-head">
          <div class="modal-title" id="svc-title">Services</div>
          <div class="modal-tools">
            <input id="svc-q" placeholder="filter (regex)" />
            <button class="btn" id="svc-list">List</button>
            <button class="btn" id="svc-iis">IIS reset</button>
          </div>
        </div>
        <div class="modal-body">
          <table class="table">
            <thead><tr><th>Name</th><th>Display Name</th><th>Status</th><th>Action</th></tr></thead>
            <tbody id="svc-tbody"></tbody>
          </table>
          <div class="modal-note" id="svc-note"></div>
        </div>
        <div class="modal-foot">
          <button class="btn" id="svc-close">Close</button>
        </div>
      </div>`;
    document.body.appendChild(el);
    svcModal.root  = el;
    svcModal.tbody = $("#svc-tbody", el);
    svcModal.q     = $("#svc-q", el);
  }
  function openSvc(iid, name) {
    ensureSvcModal();
    svcModal.iid = iid;
    svcModal.iname = name || "";
    $("#svc-title").textContent = `Services – ${(name||iid)} (${iid})`;
    svcModal.tbody.innerHTML = "";
    $("#svc-note").textContent = "Loading…";
    svcModal.root.classList.add("show");
    listServices(); // initial list
  }
  function closeSvc() { if (svcModal.root) svcModal.root.classList.remove("show"); }

  function note(msg) { $("#svc-note").textContent = msg || ""; }

  async function listServices() {
    try {
      const body = { instanceId: svcModal.iid, op: "list", instanceName: svcModal.iname };
      const q = (svcModal.q.value || "").trim();
      if (q) body.query = q;
      const res = await api("/services", "POST", body);
      if (!res.ok) { note(res.error || "Error"); return; }
      const items = res.services || [];
      if (!items.length) { note("No matching services."); svcModal.tbody.innerHTML=""; return; }
      note("");
      svcModal.tbody.innerHTML = items.map(s => {
        const status = (s.status||"").toLowerCase();
        const run = status === "running";
        return `<tr>
          <td>${s.name||""}</td>
          <td>${s.displayName||""}</td>
          <td>${pill(status)}</td>
          <td>
            <button class="btn ${run?"btn-stop":"btn-start"}" data-svcs="${run?"stop":"start"}" data-svcname="${s.name||""}">${run?"Stop":"Start"}</button>
          </td>
        </tr>`;
      }).join("");
    } catch (e) {
      note(e.message || "Failed");
    }
  }
  async function svcStartStop(op, name) {
    note("Working…");
    try {
      const res = await api("/services", "POST", {
        instanceId: svcModal.iid, instanceName: svcModal.iname, op, serviceName: name
      });
      if (!res.ok) { note(res.error || "Error"); return; }
      await listServices();
    } catch (e) {
      note(e.message || "Failed");
    }
  }

  // ---------- event wiring ----------
  document.addEventListener("click", async (e) => {
    const b = e.target.closest("button");
    if (!b) return;

    // env tab
    if (b.dataset.env) {
      setActiveEnv(b.dataset.env);
      return;
    }

    // Per-instance Start/Stop
    if (b.dataset.act && b.dataset.id) {
      try { await doAction(b.dataset.id, b.dataset.act); } catch (_) {}
      return;
    }

    // Card Start all / Stop all
    if (b.dataset.bulk) {
      const card = b.closest(".card");
      if (!card) return;
      const ids = (card.dataset.ids || "").split(",").filter(Boolean);
      try { await doBulk(ids, b.dataset.bulk); } catch (_) {}
      return;
    }

    // Services open
    if (b.dataset.svcs === "open") {
      openSvc(b.dataset.id, b.dataset.name || "");
      return;
    }

    // Services modal controls
    if (b.id === "svc-close") { closeSvc(); return; }
    if (b.id === "svc-list")  { listServices(); return; }
    if (b.id === "svc-iis")   { try { await api("/services","POST",{instanceId:svcModal.iid,op:"iisreset"}); await listServices(); } catch(_){} return; }
    if (b.dataset.svcs === "start" && b.dataset.svcname) { await svcStartStop("start", b.dataset.svcname); return; }
    if (b.dataset.svcs === "stop"  && b.dataset.svcname) { await svcStartStop("stop",  b.dataset.svcname); return; }

    // top refresh
    if (byText(b, "refresh")) { try { await refreshInstances(); } catch(_){} return; }
  });

  // ---------- init ----------
  (async function init() {
    try { await refreshInstances(); } catch (e) { /* stays on Loading… */ }
  })();
})();
