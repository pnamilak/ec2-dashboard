/* html/login.js
 * No visual redesign; fixes:
 *  - case-insensitive env tabs (driven by backend)
 *  - Start all / Stop all wired to /bulk-action
 *  - Services modal lists name/displayName/status + Start/Stop works
 *  - Clear error text when SSM is not connected
 */

/* ---------- API helpers ---------- */
const API_BASE =
  window.API_BASE ||
  (document.querySelector('meta[name="api-base"]')?.content || "").trim() ||
  ""; // if your index.html injects this, it will be used

function apiUrl(p) {
  if (/^https?:\/\//i.test(p)) return p;
  if (API_BASE) return API_BASE.replace(/\/+$/, "") + p;
  return p; // same origin
}

function bearer() {
  const t = localStorage.getItem("jwt") || "";
  return t ? { Authorization: `Bearer ${t}` } : {};
}

async function api(path, method = "GET", body) {
  const opt = {
    method,
    headers: {
      "Content-Type": "application/json",
      ...bearer(),
    },
  };
  if (body) opt.body = JSON.stringify(body);
  const r = await fetch(apiUrl(path), opt);
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j?.error || r.statusText);
  return j;
}

/* ---------- elements ---------- */
const app = document.getElementById("app") || document.body;
const statusBar = document.getElementById("status-text");

function setStatus(text, show = true) {
  if (!statusBar) return;
  statusBar.textContent = text || "";
  statusBar.style.display = show && text ? "" : "none";
}

/* ---------- tiny helpers ---------- */
const esc = (s) => (s == null ? "" : String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c])));

function chip(state) {
  const s = (state || "").toLowerCase();
  const color = s === "running" ? "chip-running" : s === "stopped" ? "chip-stopped" : "chip-other";
  return `<span class="chip ${color}">${esc(s || "-")}</span>`;
}

/* ---------- state ---------- */
let lastData = null;
let currentEnv = null;

/* ---------- render ---------- */
function renderTabs(envs, summary) {
  const keys = Object.keys(envs || {}).sort();
  if (!currentEnv) currentEnv = keys[0] || "Summary";

  const tabBtns =
    `<button class="tab-btn ${currentEnv === "Summary" ? "active" : ""}" data-tab="Summary">Summary</button>` +
    keys
      .map((k) => `<button class="tab-btn ${currentEnv === k ? "active" : ""}" data-tab="${esc(k)}">${esc(k)}</button>`)
      .join("");

  const summaryLine = currentEnv === "Summary"
    ? `All • Total: ${summary.total} • Running: ${summary.running} • Stopped: ${summary.stopped}`
    : `Env: ${esc(currentEnv)} • Total: ${(envs[currentEnv]?.DM?.length || 0) + (envs[currentEnv]?.EA?.length || 0)} • Running: ${
        (envs[currentEnv]?.DM || []).filter((x) => (x.state || "").toLowerCase() === "running").length +
        (envs[currentEnv]?.EA || []).filter((x) => (x.state || "").toLowerCase() === "running").length
      } • Stopped: ${
        (envs[currentEnv]?.DM || []).filter((x) => (x.state || "").toLowerCase() === "stopped").length +
        (envs[currentEnv]?.EA || []).filter((x) => (x.state || "").toLowerCase() === "stopped").length
      }`;

  return `
    <div class="topbar">
      <div id="summary-text">${summaryLine}</div>
      <button class="btn btn-refresh" id="btn-refresh-all">Refresh</button>
    </div>
    <div class="tabs">${tabBtns}</div>
  `;
}

function renderGroup(title, list, groupId) {
  const rows = (list || [])
    .map(
      (x) => `
      <div class="row" data-id="${esc(x.id)}" data-name="${esc(x.name || "")}">
        <div class="row-name">${esc(x.name || "-")} ${chip(x.state)}</div>
        <div class="row-actions">
          ${
            (x.state || "").toLowerCase() === "running"
              ? `<button class="btn btn-stop" data-op="stop" data-id="${esc(x.id)}">Stop</button>`
              : `<button class="btn btn-start" data-op="start" data-id="${esc(x.id)}">Start</button>`
          }
          <button class="btn btn-svc" data-id="${esc(x.id)}" data-name="${esc(x.name || "")}">Services</button>
        </div>
      </div>`
    )
    .join("");

  return `
    <div class="card" data-group="${groupId}">
      <div class="card-head">
        <div class="card-title">${esc(title)}</div>
        <div class="card-head-actions">
          <button class="btn btn-refresh-group">Refresh</button>
          <button class="btn btn-start-all">Start all</button>
          <button class="btn btn-stop-all">Stop all</button>
        </div>
      </div>
      <div class="card-body">${rows || `<div class="empty">No instances</div>`}</div>
    </div>
  `;
}

function renderEnv(envs, summary) {
  const tabs = renderTabs(envs, summary);

  if (currentEnv === "Summary") {
    const flat = Object.values(envs || {}).flatMap((g) => [...(g.DM || []), ...(g.EA || [])]);
    const block = renderGroup("All instances", flat, "ALL");
    return `${tabs}<div class="grid">${block}</div>`;
  }

  const g = envs[currentEnv] || { DM: [], EA: [] };
  return `${tabs}
    <div class="grid">
      ${renderGroup("Dream Mapper", g.DM, "DM")}
      ${renderGroup("Encore Anywhere", g.EA, "EA")}
    </div>
  `;
}

function paint(data) {
  lastData = data;
  const { envs = {}, summary = { total: 0, running: 0, stopped: 0 } } = data || {};
  app.querySelector("#main")?.remove();
  const wrap = document.createElement("div");
  wrap.id = "main";
  wrap.innerHTML = renderEnv(envs, summary);
  app.appendChild(wrap);
}

/* ---------- services modal ---------- */
let modalEl = null;

function closeModal() {
  modalEl?.remove();
  modalEl = null;
}

function openServicesModal(instanceId, instanceName) {
  closeModal();
  modalEl = document.createElement("div");
  modalEl.className = "modal";
  modalEl.innerHTML = `
    <div class="modal-body" data-iid="${esc(instanceId)}" data-iname="${esc(instanceName || "")}">
      <div class="modal-title">Services – ${esc(instanceName)} (${esc(instanceId)})</div>
      <div class="svc-controls">
        <input id="svc-pattern" placeholder="filter (e.g. MSSQL|SQLSERVERAGENT|Redis|W3SVC)" />
        <button class="btn btn-svc-list">List</button>
        <button class="btn btn-iisreset">IIS reset</button>
      </div>
      <div class="svc-table">
        <div class="svc-head"><div>Name</div><div>Display Name</div><div>Status</div><div>Action</div></div>
        <div class="svc-rows" id="svc-rows"><div class="empty">No services</div></div>
      </div>
      <div class="modal-actions"><button class="btn btn-close">Close</button></div>
    </div>
  `;
  document.body.appendChild(modalEl);
}

function renderSvcRows(arr) {
  const box = document.getElementById("svc-rows");
  if (!box) return;
  if (!arr || !arr.length) {
    box.innerHTML = `<div class="empty">No services</div>`;
    return;
  }
  box.innerHTML = arr
    .map((s) => {
      const run = (s.status || "").toLowerCase() === "running";
      return `<div class="svc-row" data-svc="${esc(s.name || "")}">
        <div>${esc(s.name || "")}</div>
        <div>${esc(s.displayName || "")}</div>
        <div>${chip(s.status)}</div>
        <div>
          <button class="btn ${run ? "btn-stop" : "btn-start"} btn-svc-op" data-op="${run ? "stop" : "start"}">${run ? "Stop" : "Start"}</button>
        </div>
      </div>`;
    })
    .join("");
}

/* ---------- actions ---------- */
async function refreshAll() {
  setStatus("Loading summary...", true);
  try {
    const r = await api("/instances", "GET");
    paint(r);
    setStatus("", false);
  } catch (e) {
    setStatus(`Failed to load: ${e.message}`, true);
  }
}

async function actInstance(id, op) {
  await api("/instance-action", "POST", { id, op });
}

async function actBulk(ids, op) {
  await api("/bulk-action", "POST", { ids, op });
}

async function listServices(iid, pattern = "", nameHint = "") {
  try {
    const mode = pattern ? "filter" : (nameHint.toLowerCase().includes("sql") ? "sql" :
                  nameHint.toLowerCase().includes("redis") ? "redis" : "filter");
    const r = await api("/services", "POST", { id: iid, op: "list", mode, query: pattern });
    if (r?.services) renderSvcRows(r.services);
    else if (r?.error === "ssm_not_connected") {
      renderSvcRows([]);
      document.getElementById("svc-rows").innerHTML =
        `<div class="empty">SSM not connected (agent/role/network). </div>`;
    } else {
      renderSvcRows([]);
    }
  } catch (e) {
    renderSvcRows([]);
    document.getElementById("svc-rows").innerHTML =
      `<div class="empty">Error: ${esc(e.message)}</div>`;
  }
}

async function opService(iid, svcName, op) {
  const r = await api("/services", "POST", { id: iid, op, serviceName: svcName });
  if (r?.service) {
    // update that row only
    const row = document.querySelector(`.svc-row[data-svc="${CSS.escape(svcName)}"]`);
    if (row) {
      const run = (r.service.status || "").toLowerCase() === "running";
      row.querySelector(":scope > div:nth-child(3)").innerHTML = chip(r.service.status);
      row.querySelector(".btn-svc-op").textContent = run ? "Stop" : "Start";
      row.querySelector(".btn-svc-op").dataset.op = run ? "stop" : "start";
      row.querySelector(".btn-svc-op").classList.toggle("btn-start", !run);
      row.querySelector(".btn-svc-op").classList.toggle("btn-stop", run);
    }
  }
}

/* ---------- events ---------- */
document.addEventListener("click", async (e) => {
  const btn = e.target.closest("button");
  if (!btn) return;

  // tabs
  if (btn.classList.contains("tab-btn")) {
    currentEnv = btn.dataset.tab;
    paint(lastData);
    return;
  }

  // global refresh
  if (btn.id === "btn-refresh-all") {
    refreshAll();
    return;
  }

  // per-instance start/stop
  if (btn.classList.contains("btn-start") || btn.classList.contains("btn-stop")) {
    const id = btn.dataset.id || btn.closest(".row")?.dataset.id;
    const op = btn.dataset.op || (btn.classList.contains("btn-start") ? "start" : "stop");
    if (!id) return;
    btn.disabled = true;
    try {
      await actInstance(id, op);
      await refreshAll();
    } catch (err) {
      alert(`Failed: ${err.message}`);
    } finally {
      btn.disabled = false;
    }
    return;
  }

  // group Start all/Stop all
  if (btn.classList.contains("btn-start-all") || btn.classList.contains("btn-stop-all")) {
    const group = btn.closest(".card");
    const ids = [...group.querySelectorAll(".row")].map((x) => x.dataset.id).filter(Boolean);
    if (!ids.length) return;
    const op = btn.classList.contains("btn-start-all") ? "start" : "stop";
    btn.disabled = true;
    try {
      await actBulk(ids, op);
      await refreshAll();
    } catch (err) {
      alert(`Failed: ${err.message}`);
    } finally {
      btn.disabled = false;
    }
    return;
  }

  // group refresh
  if (btn.classList.contains("btn-refresh-group")) {
    refreshAll();
    return;
  }

  // services open
  if (btn.classList.contains("btn-svc")) {
    const id = btn.dataset.id || btn.closest(".row")?.dataset.id;
    const name = btn.dataset.name || btn.closest(".row")?.dataset.name || "";
    openServicesModal(id, name);
    // initial list guess based on instance name
    const hint = name.toLowerCase();
    const pat = hint.includes("sql") ? "MSSQL|SQLSERVERAGENT" : hint.includes("redis") ? "Redis" : "";
    document.getElementById("svc-pattern").value = pat;
    await listServices(id, pat, name);
    return;
  }

  // services modal actions
  if (btn.classList.contains("btn-close")) {
    closeModal();
    return;
  }

  if (btn.classList.contains("btn-svc-list")) {
    const box = btn.closest(".modal-body");
    const iid = box.dataset.iid;
    const pat = document.getElementById("svc-pattern").value || "";
    await listServices(iid, pat, box.dataset.iname || "");
    return;
  }

  if (btn.classList.contains("btn-iisreset")) {
    const box = btn.closest(".modal-body");
    const iid = box.dataset.iid;
    btn.disabled = true;
    try {
      await api("/services", "POST", { id: iid, op: "iisreset" });
      alert("IIS reset kicked off.");
    } catch (err) {
      alert(`IIS reset failed: ${err.message}`);
    } finally {
      btn.disabled = false;
    }
    return;
  }

  if (btn.classList.contains("btn-svc-op")) {
    const box = btn.closest(".modal-body");
    const iid = box.dataset.iid;
    const svcRow = btn.closest(".svc-row");
    const svcName = svcRow?.dataset.svc || "";
    const op = btn.dataset.op || "";
    if (!iid || !svcName || !op) return;
    btn.disabled = true;
    try {
      await opService(iid, svcName, op);
    } catch (err) {
      alert(`Failed: ${err.message}`);
    } finally {
      btn.disabled = false;
    }
    return;
  }
});

/* ---------- init ---------- */
(async function init() {
  // require JWT
  const t = localStorage.getItem("jwt");
  if (!t) {
    location.href = "/login.html";
    return;
  }
  await refreshAll();
})();
