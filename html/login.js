/* login.js — API + OTP + instances + services (complete) */

const API_BASE = window.__API_BASE__;         // set by index.html.tpl
let   jwt      = localStorage.getItem("jwt") || "";

/* ---------------- API helper (Bearer + JSON) ---------------- */
async function api(path, method = "GET", body) {
  const headers = { "Content-Type": "application/json" };
  if (jwt) headers["Authorization"] = "Bearer " + jwt;

  const res  = await fetch(API_BASE + path, {
    method,
    headers,
    body: body == null ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  let data   = {};
  try { data = text ? JSON.parse(text) : {}; } catch { data = { raw: text }; }

  if (!res.ok || data.ok === false) {
    const msg = data.error || data.message || ("HTTP " + res.status);
    throw new Error(msg);
  }
  return data;
}

/* ---------------- OTP / Login (works on the verify/sign-in pages) ---------------- */
const elEmail   = document.querySelector("#email");
const elOtp     = document.querySelector("#otp");
const btnReq    = document.querySelector("#btn-request-otp");
const btnVerify = document.querySelector("#btn-verify-otp");
const btnLogin  = document.querySelector("#btn-login");

btnReq?.addEventListener("click", async () => {
  const email = (elEmail?.value || "").trim();
  if (!email) return alert("Enter email");
  try {
    const r = await api("/request-otp", "POST", { email });
    // show dev OTP when SES is sandboxed:
    if (r.code) alert(`OTP sent. Dev code: ${r.code}`);
  } catch (e) { alert(e.message || "Failed to request OTP"); }
});

btnVerify?.addEventListener("click", async () => {
  const email = (elEmail?.value || "").trim();
  const code  = (elOtp?.value   || "").trim();
  if (!email || !code) return alert("Enter email and OTP");
  try { await api("/verify-otp", "POST", { email, code }); alert("OTP verified"); }
  catch (e) { alert(e.message || "OTP verify failed"); }
});

btnLogin?.addEventListener("click", async () => {
  const email = (elEmail?.value || "").trim();
  const code  = (elOtp?.value   || "").trim();
  if (!email || !code) return alert("Enter email and OTP");
  try {
    const r = await api("/login", "POST", { email, code });
    jwt = r.token || "";
    localStorage.setItem("jwt", jwt);
    // if we’re already on the dashboard, refresh; otherwise the page can redirect.
    await refreshInstances();
  } catch (e) { alert("Login failed: " + (e.message || "unknown")); }
});

/* ---------------- Dashboard: summary + instances table ---------------- */
const statusEl   = document.querySelector("#summary-status"); // <div id="summary-status">Loading summary…</div>
const tableEl    = document.querySelector("#instances");      // <table id="instances"><tbody>…</tbody></table>
const tbodyEl    = tableEl?.querySelector("tbody");
const btnRefresh = document.querySelector("#btn-refresh");

function setStatus(text, show = true) {
  if (!statusEl) return;
  statusEl.textContent   = text || "";
  statusEl.style.display = show ? "" : "none";
}

function renderInstances(list) {
  if (!tbodyEl) return;
  if (!list || !list.length) {
    tbodyEl.innerHTML = `<tr><td colspan="4">No instances</td></tr>`;
    return;
  }
  tbodyEl.innerHTML = list.map(x => `
    <tr>
      <td>${x.name || "-"}</td>
      <td>${x.id}</td>
      <td>${(x.state || "").toLowerCase()}</td>
      <td class="actions">
        <button class="btn-svc"    data-id="${x.id}" data-name="${x.name || ""}">Services</button>
        <button class="btn-start"  data-id="${x.id}">Start</button>
        <button class="btn-stop"   data-id="${x.id}">Stop</button>
        <button class="btn-reboot" data-id="${x.id}">Reboot</button>
      </td>
    </tr>
  `).join("");
}

async function refreshInstances() {
  if (!tableEl) return;          // not on the dashboard page
  setStatus("Loading summary...", true);
  try {
    const r = await api("/instances", "GET");

    // Support both shapes: new (summary/envs) and old (instances)
    const list = Array.isArray(r.instances)
      ? r.instances
      : Object.values(r.envs || {}).flatMap(g => [...(g.DM || []), ...(g.EA || [])]);

    renderInstances(list);
    setStatus("", false);
  } catch (e) {
    console.error(e);
    setStatus(e.message || "Failed to load instances", true);
  }
}

btnRefresh?.addEventListener("click", refreshInstances);

tableEl?.addEventListener("click", async (ev) => {
  const b = ev.target.closest("button");
  if (!b) return;
  const id = b.dataset.id;
  try {
    if (b.classList.contains("btn-start"))  await api("/instance-action", "POST", { instanceId: id, op: "start"  });
    if (b.classList.contains("btn-stop"))   await api("/instance-action", "POST", { instanceId: id, op: "stop"   });
    if (b.classList.contains("btn-reboot")) await api("/instance-action", "POST", { instanceId: id, op: "reboot" });
    if (b.classList.contains("btn-svc"))    return openServicesModal({ id, name: b.dataset.name || "" });
    await refreshInstances();
  } catch (e) { alert(e.message || "Action failed"); }
});

// Auto-run on dashboard
if (tableEl) refreshInstances();

/* ---------------- Services Modal (your code, kept & completed) ---------------- */

const svcModal = {
  el: null, tbody: null, titleEl: null,
  filterWrap: null, filterInput: null, listBtn: null, iisBtn: null,
  instanceId: null, mode: "filter" // 'sql' | 'redis' | 'filter'
};

function ensureModal() {
  if (svcModal.el) return;
  const modal = document.createElement("div");
  modal.id = "svc-modal";
  modal.innerHTML = `
    <div class="modal-backdrop"></div>
    <div class="modal">
      <div class="modal-header">
        <h3 id="svc-title">Services</h3>
        <button id="svc-close" class="btn btn-ghost">Close</button>
      </div>
      <div class="modal-body">
        <div id="svc-filter-wrap" class="row" style="display:none;gap:8px;margin-bottom:10px;">
          <input id="svc-filter" type="text" placeholder="Type 2-5 letters (SVC/WEB)" class="input" />
          <button id="svc-list" class="btn btn-primary">List</button>
          <button id="svc-iis" class="btn btn-soft">IIS reset</button>
        </div>
        <table class="table">
          <thead><tr><th>Name</th><th>Display Name</th><th>Status</th><th>Action</th></tr></thead>
          <tbody id="svc-body"></tbody>
        </table>
        <div id="svc-note" class="muted" style="margin-top:8px;"></div>
      </div>
    </div>`;
  document.body.appendChild(modal);

  svcModal.el         = modal;
  svcModal.tbody      = modal.querySelector("#svc-body");
  svcModal.titleEl    = modal.querySelector("#svc-title");
  svcModal.filterWrap = modal.querySelector("#svc-filter-wrap");
  svcModal.filterInput= modal.querySelector("#svc-filter");
  svcModal.listBtn    = modal.querySelector("#svc-list");
  svcModal.iisBtn     = modal.querySelector("#svc-iis");

  modal.querySelector("#svc-close").onclick = () => modal.classList.remove("open");
  svcModal.listBtn.onclick = () => doList();
  svcModal.iisBtn.onclick  = () => doIisReset();
}

function openServicesModal(instance) {
  ensureModal();
  svcModal.instanceId = instance.id;
  svcModal.titleEl.textContent = `Services – ${instance.name || ""} (${instance.id})`;

  const n = (instance.name || "").toLowerCase();
  if (n.includes("sql")) {
    svcModal.mode = "sql";    svcModal.filterWrap.style.display = "none";  doList();
  } else if (n.includes("redis")) {
    svcModal.mode = "redis";  svcModal.filterWrap.style.display = "none";  doList();
  } else {
    svcModal.mode = "filter"; svcModal.filterWrap.style.display = "flex";
    svcModal.filterInput.value = ""; svcModal.tbody.innerHTML = ""; modalNote("Type 2-5 letters and click List.");
  }
  svcModal.el.classList.add("open");
}
window.openServicesModal = openServicesModal;

function modalNote(t){ svcModal.el.querySelector("#svc-note").textContent = t || ""; }

function doList() {
  modalNote("Listing...");
  const payload = { instanceId: svcModal.instanceId, op: "list", mode: svcModal.mode };
  if (svcModal.mode === "filter") payload.query = (svcModal.filterInput.value || "").trim();

  api("/services", "POST", payload)
    .then((res) => {
      svcModal.tbody.innerHTML = "";
      if (!res.ok) return modalNote(res.error || "Error");
      const items = res.services || [];
      if (!items.length) return modalNote("No matching services.");
      modalNote("");
      for (const s of items) {
        const status = (s.status || "").toLowerCase();
        const run    = status === "running";
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td>${s.name || ""}</td>
          <td>${s.displayName || s.display || ""}</td>
          <td><span class="pill ${run ? "ok" : "warn"}">${status}</span></td>
          <td><button class="btn ${run ? "btn-stop" : "btn-start"}" data-svc="${s.name}" data-op="${run ? "stop":"start"}">${run ? "Stop":"Start"}</button></td>`;
        svcModal.tbody.appendChild(tr);
      }
      svcModal.tbody.querySelectorAll("button[data-svc]").forEach(b =>
        b.onclick = () => doControl(b.dataset.svc, b.dataset.op));
    })
    .catch(e => modalNote(`Error: ${e.message}`));
}

function doControl(serviceName, op) {
  modalNote(`${op} ${serviceName}...`);
  api("/services", "POST", { instanceId: svcModal.instanceId, op, serviceName })
    .then((r) => r.ok ? doList() : modalNote(r.error || "Error"))
    .catch(e => modalNote(`Error: ${e.message}`));
}

function doIisReset() {
  modalNote("Issuing IIS reset...");
  api("/services", "POST", { instanceId: svcModal.instanceId, op: "iisreset" })
    .then((r) => modalNote(r.ok ? (r.message || "IIS reset sent.") : (r.error || "IIS reset failed")))
    .catch(e => modalNote(`Error: ${e.message}`));
}
