// login.js — attach JWT to all API calls and stop the spinner reliably.

(function () {
  // Hard-code your API base for clarity
  const API_BASE = "https://9c36fvxj24.execute-api.us-east-2.amazonaws.com";

  const $  = (s) => document.querySelector(s);
  const $$ = (s) => Array.from(document.querySelectorAll(s));

  // Centralized API helper with JWT + 401 handling
  async function api(path, method = "GET", body) {
    const headers = { "Content-Type": "application/json" };
    const tok = localStorage.getItem("jwt");
    if (tok) headers["Authorization"] = "Bearer " + tok;

    const opt = { method, headers };
    if (body !== undefined && body !== null) opt.body = JSON.stringify(body);

    const res = await fetch(API_BASE + path, opt);

    // 401 -> clear token so the UI forces re-verify/login
    if (res.status === 401) {
      try { localStorage.removeItem("jwt"); } catch {}
      throw new Error("Unauthorized (401) — please verify email & sign in again.");
    }

    let json = {};
    try { json = await res.json(); } catch {}
    if (!res.ok || json.ok === false) {
      const msg = json.error || json.message || `HTTP ${res.status}`;
      throw new Error(msg);
    }
    return json;
  }

  // ---------------- OTP / Email screens (unchanged behavior) ----------------
  const emailInput = $("#email");
  const otpInput   = $("#otp");
  const btnReq     = $("#btn-request-otp");
  const btnVerify  = $("#btn-verify-otp");
  const btnLogin   = $("#btn-login");
  const tokenSpan  = $("#token");

  btnReq?.addEventListener("click", async () => {
    const email = emailInput.value.trim();
    if (!email) return alert("Enter email");
    try {
      const res = await api("/request-otp", "POST", { email });
      alert(res.ok ? `OTP sent. Dev: ${res.code || ""}` : `Failed: ${res.error}`);
    } catch (e) { alert(e.message || "Failed to request OTP"); }
  });

  btnVerify?.addEventListener("click", async () => {
    const email = emailInput.value.trim();
    const code  = otpInput.value.trim();
    if (!email || !code) return alert("Enter email and OTP");
    try { await api("/verify-otp", "POST", { email, code }); alert("OTP verified"); }
    catch (e) { alert(e.message || "OTP verify failed"); }
  });

  btnLogin?.addEventListener("click", async () => {
    const email = emailInput?.value?.trim();
    const code  = otpInput?.value?.trim();
    if (!email || !code) return alert("Enter email and OTP");
    try {
      const res = await api("/login", "POST", { email, code });
      localStorage.setItem("jwt", res.token);
      if (tokenSpan) tokenSpan.textContent = res.token.slice(0, 24) + "…";
      await refreshInstances();
    } catch (e) { alert("Login failed: " + (e.message || "unknown")); }
  });

  // ---------------- Instances table ----------------
  const panel        = $("#summary-panel");   // container that shows "Loading summary..."
  const statusEl     = $("#summary-status");  // <div id="summary-status">Loading summary…</div>
  const tbl          = $("#instances");
  const btnRefresh   = $("#btn-refresh");
  const btnStartAll  = $("#btn-start-all");
  const btnStopAll   = $("#btn-stop-all");
  const btnRebootAll = $("#btn-reboot-all");

  function setStatus(text, show) {
    if (!statusEl) return;
    statusEl.textContent = text || "";
    statusEl.style.display = show ? "" : "none";
  }

  async function refreshInstances() {
    setStatus("Loading summary...", true);
    try {
      const res = await api("/instances", "GET");
      renderInstances(res.instances || []);
      setStatus("", false); // hide spinner/status no matter what the list contains
    } catch (e) {
      console.error(e);
      setStatus(e.message || "Failed to load instances", true);
    }
  }

  function renderInstances(list) {
    if (!tbl) return;
    const rows = (list || []).map(x => `
      <tr>
        <td>${x.name || "-"}</td>
        <td>${x.id}</td>
        <td>${(x.state||"").toLowerCase()}</td>
        <td class="actions">
          <button class="btn-svc" data-id="${x.id}" data-name="${x.name || ""}">Services</button>
          <button class="btn-start"  data-id="${x.id}">Start</button>
          <button class="btn-stop"   data-id="${x.id}">Stop</button>
          <button class="btn-reboot" data-id="${x.id}">Reboot</button>
        </td>
      </tr>`).join("");
    tbl.querySelector("tbody").innerHTML = rows || `<tr><td colspan="4">No instances</td></tr>`;
  }

  btnRefresh?.addEventListener("click", refreshInstances);

  tbl?.addEventListener("click", async (e) => {
    const b = e.target.closest("button");
    if (!b) return;
    const id = b.dataset.id;
    try {
      if (b.classList.contains("btn-start"))  await api("/instance-action", "POST", { instanceId: id, op: "start" });
      else if (b.classList.contains("btn-stop"))   await api("/instance-action", "POST", { instanceId: id, op: "stop" });
      else if (b.classList.contains("btn-reboot")) await api("/instance-action", "POST", { instanceId: id, op: "reboot" });
      else if (b.classList.contains("btn-svc")) { openServicesModal({ instanceId: id, instanceName: b.dataset.name || "" }); return; }
      await refreshInstances();
    } catch (e2) { alert(e2.message || "Action failed"); }
  });

  // ---------------- Services modal (unchanged) ----------------
  const modal           = $("#svc-modal");
  const svcList         = $("#svc-list");
  const svcSearch       = $("#svc-search");
  const btnSvcList      = $("#btn-svc-list");
  const btnSvcStart     = $("#btn-svc-start");
  const btnSvcStop      = $("#btn-svc-stop");
  const btnIISReset     = $("#btn-iis-reset");
  let currentSvcContext = null;

  function openServicesModal(ctx) {
    currentSvcContext = ctx;
    modal?.classList.add("open");
    svcList.innerHTML = "";
    svcSearch.value = "";
    listServices();
  }

  function guessModeFromName(name) {
    const n = (name || "").toLowerCase();
    if (n.includes("sql"))   return "sql";
    if (n.includes("redis")) return "redis";
    if (n.includes("svc") || n.includes("web")) return "filter";
    return "filter";
  }

  async function listServices() {
    if (!currentSvcContext) return;
    const query = svcSearch.value.trim();
    const mode  = query ? "filter" : guessModeFromName(currentSvcContext.instanceName);
    try {
      const res = await api("/services", "POST", {
        instanceId: currentSvcContext.instanceId, op: "list", mode, query
      });
      const arr = res.services || [];
      svcList.innerHTML = arr.map(s =>
        `<li data-name="${s.name}"><span>${s.displayName || s.name}</span><em>${s.status}</em></li>`
      ).join("") || `<li class="empty">No services</li>`;
    } catch (e) { alert(e.message || "Failed to list services"); }
  }

  btnSvcList?.addEventListener("click", listServices);

  btnSvcStart?.addEventListener("click", async () => {
    const sel = svcList.querySelector("li.selected");
    if (!sel || !currentSvcContext) return alert("Pick a service");
    try {
      await api("/services", "POST", {
        instanceId: currentSvcContext.instanceId, op: "start", mode: "filter", serviceName: sel.dataset.name
      });
      await listServices();
    } catch (e) { alert(e.message || "Service start failed"); }
  });

  btnSvcStop?.addEventListener("click", async () => {
    const sel = svcList.querySelector("li.selected");
    if (!sel || !currentSvcContext) return alert("Pick a service");
    try {
      await api("/services", "POST", {
        instanceId: currentSvcContext.instanceId, op: "stop", mode: "filter", serviceName: sel.dataset.name
      });
      await listServices();
    } catch (e) { alert(e.message || "Service stop failed"); }
  });

  btnIISReset?.addEventListener("click", async () => {
    if (!currentSvcContext) return;
    try {
      await api("/services", "POST", { instanceId: currentSvcContext.instanceId, op: "iisreset", mode: "filter" });
      alert("IIS reset sent");
    } catch (e) { alert(e.message || "IIS reset failed"); }
  });

  // Auto load if the table is on the page
  if ($("#instances")) refreshInstances();
})();
