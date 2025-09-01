/* login.js – dashboard interactions (services fixed) */

const API_BASE = window.__API_BASE__; // set by index.html.tpl from Terraform output
let jwt = localStorage.getItem("jwt") || "";

function api(path, method = "GET", body) {
  const headers = { "Content-Type": "application/json" };
  if (jwt) headers["Authorization"] = `Bearer ${jwt}`;
  return fetch(`${API_BASE}${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  }).then(async (r) => {
    const txt = await r.text();
    let data = {};
    try { data = txt ? JSON.parse(txt) : {}; } catch { data = { raw: txt }; }
    if (!r.ok) throw new Error(data.error || r.statusText);
    return data;
  });
}

/* ---------- Services Modal ---------- */

const svcModal = {
  el: null,
  tbody: null,
  titleEl: null,
  filterWrap: null,
  filterInput: null,
  listBtn: null,
  iisBtn: null,
  instanceId: null,
  mode: "filter", // 'sql' | 'redis' | 'filter'
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
          <thead>
            <tr><th>Name</th><th>Display Name</th><th>Status</th><th>Action</th></tr>
          </thead>
          <tbody id="svc-body"></tbody>
        </table>
        <div id="svc-note" class="muted" style="margin-top:8px;"></div>
      </div>
    </div>`;
  document.body.appendChild(modal);

  svcModal.el = modal;
  svcModal.tbody = modal.querySelector("#svc-body");
  svcModal.titleEl = modal.querySelector("#svc-title");
  svcModal.filterWrap = modal.querySelector("#svc-filter-wrap");
  svcModal.filterInput = modal.querySelector("#svc-filter");
  svcModal.listBtn = modal.querySelector("#svc-list");
  svcModal.iisBtn = modal.querySelector("#svc-iis");

  modal.querySelector("#svc-close").onclick = () => modal.classList.remove("open");
  svcModal.listBtn.onclick = () => doList();
  svcModal.iisBtn.onclick = () => doIisReset();
}

function openServicesModal(instance) {
  ensureModal();
  svcModal.instanceId = instance.id;
  svcModal.titleEl.textContent = `Services – ${instance.name} (${instance.id})`;

  // decide mode by instance name
  const n = (instance.name || "").toLowerCase();
  if (n.includes("sql")) {
    svcModal.mode = "sql";
    svcModal.filterWrap.style.display = "none";
    doList();
  } else if (n.includes("redis")) {
    svcModal.mode = "redis";
    svcModal.filterWrap.style.display = "none";
    doList();
  } else if (n.includes("svc") || n.includes("web")) {
    svcModal.mode = "filter";
    svcModal.filterWrap.style.display = "flex";
    svcModal.filterInput.value = "";
    svcModal.tbody.innerHTML = "";
    modalNote("Type 2-5 letters and click List.");
  } else {
    // default to filter mode
    svcModal.mode = "filter";
    svcModal.filterWrap.style.display = "flex";
    svcModal.filterInput.value = "";
    svcModal.tbody.innerHTML = "";
    modalNote("Type 2-5 letters and click List.");
  }

  svcModal.el.classList.add("open");
}

function modalNote(text) {
  const el = svcModal.el.querySelector("#svc-note");
  el.textContent = text || "";
}

function doList() {
  modalNote("Listing...");
  const payload = {
    instanceId: svcModal.instanceId,
    op: "list",
    mode: svcModal.mode
  };
  if (svcModal.mode === "filter") {
    payload.query = (svcModal.filterInput.value || "").trim();
  }
  api("/services", "POST", payload)
    .then((res) => {
      svcModal.tbody.innerHTML = "";
      if (res.note === "not_connected") {
        modalNote("No services (SSM: not connected).");
        return;
      }
      if (!res.ok) {
        modalNote(res.error || "Error");
        return;
      }
      const items = res.services || [];
      if (!items.length) {
        modalNote("No matching services.");
        return;
      }
      modalNote("");
      for (const s of items) {
        const tr = document.createElement("tr");
        const status = (s.status || "").toLowerCase();
        const isRunning = status === "running";
        tr.innerHTML = `
          <td>${s.name || ""}</td>
          <td>${s.display || ""}</td>
          <td><span class="pill ${isRunning ? "ok" : "warn"}">${status}</span></td>
          <td>
            <button class="btn ${isRunning ? "btn-stop" : "btn-start"}"
                    data-svc="${s.name}"
                    data-op="${isRunning ? "stop" : "start"}">
              ${isRunning ? "Stop" : "Start"}
            </button>
          </td>`;
        svcModal.tbody.appendChild(tr);
      }
      // wire actions
      svcModal.tbody.querySelectorAll("button[data-svc]").forEach((b) => {
        b.onclick = () => doControl(b.dataset.svc, b.dataset.op);
      });
    })
    .catch((e) => modalNote(`Error: ${e.message}`));
}

function doControl(serviceName, op) {
  modalNote(`${op} ${serviceName}...`);
  api("/services", "POST", {
    instanceId: svcModal.instanceId,
    op,
    serviceName
  })
    .then((res) => {
      if (res.note === "not_connected") {
        modalNote("SSM: not connected.");
        return;
      }
      if (!res.ok) {
        modalNote(res.error || "Error");
        return;
      }
      doList(); // refresh list
    })
    .catch((e) => modalNote(`Error: ${e.message}`));
}

function doIisReset() {
  modalNote("Issuing IIS reset...");
  api("/services", "POST", {
    instanceId: svcModal.instanceId,
    op: "iisreset",
  })
    .then((res) => {
      modalNote(res.ok ? (res.message || "IIS reset sent.") : (res.error || "IIS reset failed"));
    })
    .catch((e) => modalNote(`Error: ${e.message}`));
}

/* ---------- existing dashboard wiring ---------- */
/* Your existing code should call openServicesModal(instance)
   when the per-instance “Services” button is clicked. */
window.openServicesModal = openServicesModal;
