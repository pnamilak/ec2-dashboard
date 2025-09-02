// website/login.js
// -----------------------------------------------------------------------------
// OTP/Sign-in flow + Instances + Services, with JWT attached automatically.
// -----------------------------------------------------------------------------

(function () {
  const API_BASE =
    window.__API_BASE__ ||
    (document.querySelector("meta[name=api-base]")?.content || "").trim() ||
    ""; // e.g., "https://9c36fvxj24.execute-api.us-east-2.amazonaws.com"

  if (!API_BASE) {
    console.warn("API base not configured; set window.__API_BASE__ or <meta name='api-base'>");
  }

  // ---------- tiny helpers ----------
  const $  = (sel) => document.querySelector(sel);
  const $$ = (sel) => Array.from(document.querySelectorAll(sel));

  // Centralized API helper – attaches JWT and handles 401s
  async function api(path, method = "GET", body) {
    const headers = { "Content-Type": "application/json" };
    const tok = localStorage.getItem("jwt");
    if (tok) headers["Authorization"] = "Bearer " + tok;

    const opt = { method, headers };
    if (body !== undefined && body !== null) opt.body = JSON.stringify(body);

    const res = await fetch(API_BASE + path, opt);

    if (res.status === 401) {
      // token missing/expired → clear and send user back to verify/login
      try { localStorage.removeItem("jwt"); } catch (_) {}
      throw new Error("Unauthorized (401) — please verify email & sign in again.");
    }

    // backend always returns JSON
    let json = {};
    try { json = await res.json(); } catch (_) { json = {}; }

    if (!res.ok || json.ok === false) {
      const msg = json.error || json.message || `HTTP ${res.status}`;
      throw new Error(msg);
    }

    return json;
  }

  // ---------- OTP flow ----------
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
    } catch (e) {
      alert(e.message || "Failed to request OTP");
    }
  });

  btnVerify?.addEventListener("click", async () => {
    const email = emailInput.value.trim();
    const code  = otpInput.value.trim();
    if (!email || !code) return alert("Enter email and OTP");
    try {
      const res = await api("/verify-otp", "POST", { email, code });
      alert(res.ok ? "OTP verified" : "Invalid OTP");
    } catch (e) {
      alert(e.message || "OTP verify failed");
    }
  });

  // Simple OTP login (email + code) used by your login.html
  btnLogin?.addEventListener("click", async () => {
    const email = emailInput?.value?.trim();
    const code  = otpInput?.value?.trim();
    if (!email || !code) return alert("Enter email and OTP");
    try {
      const res = await api("/login", "POST", { email, code });
      localStorage.setItem("jwt", res.token);
      if (tokenSpan) tokenSpan.textContent = res.token.slice(0, 24) + "…";
      await refreshInstances();
    } catch (e) {
      alert("Login failed: " + (e.message || "unknown error"));
    }
  });

  // ---------- Instances ----------
  const tbl        = $("#instances");
  const btnRefresh = $("#btn-refresh");
  const btnStartAll  = $("#btn-start-all");
  const btnStopAll   = $("#btn-stop-all");
  const btnRebootAll = $("#btn-reboot-all");

  async function refreshInstances() {
    const panel = $("#summary-panel");
    try {
      const res = await api("/instances", "GET");
      renderInstances(res.instances || []);
      if (panel) panel.dataset.state = "ready";
    } catch (e) {
      if (panel) panel.dataset.state = "error";
      console.error(e);
      alert(e.message || "Failed to load instances");
    }
  }

  function renderInstances(list) {
    if (!tbl) return;
    const rows = (list || [])
      .map((x) => {
        const state = (x.state || "").toLowerCase();
        return `
        <tr>
          <td>${x.name || "-"}</td>
          <td>${x.id}</td>
          <td>${state}</td>
          <td class="actions">
            <button class="btn-svc"    data-id="${x.id}" data-name="${x.name || ""}">Services</button>
            <button class="btn-start"  data-id="${x.id}">Start</button>
            <button class="btn-stop"   data-id="${x.id}">Stop</button>
            <button class="btn-reboot" data-id="${x.id}">Reboot</button>
          </td>
        </tr>`;
      })
      .join("");
    tbl.querySelector("tbody").innerHTML = rows || `<tr><td colspan="4">No instances</td></tr>`;
  }

  btnRefresh?.addEventListener("click", refreshInstances);

  tbl?.addEventListener("click", async (e) => {
    const b = e.target.closest("button");
    if (!b) return;
    const id = b.dataset.id;
    try {
      if (b.classList.contains("btn-start")) {
        await api("/instance-action", "POST", { instanceId: id, op: "start" });
      } else if (b.classList.contains("btn-stop")) {
        await api("/instance-action", "POST", { instanceId: id, op: "stop" });
      } else if (b.classList.contains("btn-reboot")) {
        await api("/instance-action", "POST", { instanceId: id, op: "reboot" });
      } else if (b.classList.contains("btn-svc")) {
        openServicesModal({ instanceId: id, instanceName: b.dataset.name || "" });
        return;
      }
      await refreshInstances();
    } catch (e2) {
      alert(e2.message || "Action failed");
    }
  });

  btnStartAll?.addEventListener("click", async () => {
    const ids = $$("tbody tr [data-id]").map((b) => b.dataset.id);
    if (!ids.length) return;
    await api("/bulk-action", "POST", { instanceIds: ids, op: "start" });
    await refreshInstances();
  });
  btnStopAll?.addEventListener("click", async () => {
    const ids = $$("tbody tr [data-id]").map((b) => b.dataset.id);
    if (!ids.length) return;
    await api("/bulk-action", "POST", { instanceIds: ids, op: "stop" });
    await refreshInstances();
  });
  btnRebootAll?.addEventListener("click", async () => {
    const ids = $$("tbody tr [data-id]").map((b) => b.dataset.id);
    if (!ids.length) return;
    await api("/bulk-action", "POST", { instanceIds: ids, op: "reboot" });
    await refreshInstances();
  });

  // ---------- Services modal (unchanged behavior; tolerant payload) ----------
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
    listServices();  // initial load
  }

  async function listServices() {
    if (!currentSvcContext) return;
    const query = svcSearch.value.trim();
    const mode  = query ? "filter" : guessModeFromName(currentSvcContext.instanceName);
    try {
      const res = await api("/services", "POST", {
        instanceId: currentSvcContext.instanceId,
        op: "list",
        mode,
        query
      });
      const arr = res.services || [];
      svcList.innerHTML = arr.map(s =>
        `<li data-name="${s.name}"><span>${s.displayName || s.name}</span><em>${s.status}</em></li>`
      ).join("") || `<li class="empty">No services</li>`;
    } catch (e) {
      alert(e.message || "Failed to list services");
    }
  }

  btnSvcList?.addEventListener("click", listServices);

  btnSvcStart?.addEventListener("click", async () => {
    const sel = svcList.querySelector("li.selected");
    if (!sel || !currentSvcContext) return alert("Pick a service");
    const name = sel.dataset.name;
    try {
      const res = await api("/services", "POST", {
        instanceId: currentSvcContext.instanceId,
        op: "start",
        mode: "filter",
        serviceName: name
      });
      alert(res.ok ? "Service started" : ("Service action failed: " + (res.error || "")));
      await listServices();
    } catch (e) {
      alert(e.message || "Service start failed");
    }
  });

  btnSvcStop?.addEventListener("click", async () => {
    const sel = svcList.querySelector("li.selected");
    if (!sel || !currentSvcContext) return alert("Pick a service");
    const name = sel.dataset.name;
    try {
      const res = await api("/services", "POST", {
        instanceId: currentSvcContext.instanceId,
        op: "stop",
        mode: "filter",
        serviceName: name
      });
      alert(res.ok ? "Service stopped" : ("Service action failed: " + (res.error || "")));
      await listServices();
    } catch (e) {
      alert(e.message || "Service stop failed");
    }
  });

  btnIISReset?.addEventListener("click", async () => {
    if (!currentSvcContext) return;
    try {
      const res = await api("/services", "POST", {
        instanceId: currentSvcContext.instanceId,
        op: "iisreset",
        mode: "filter"
      });
      alert(res.ok ? "IIS reset sent" : ("IIS reset failed: " + (res.error || "")));
    } catch (e) {
      alert(e.message || "IIS reset failed");
    }
  });

  function guessModeFromName(name) {
    const n = (name || "").toLowerCase();
    if (n.includes("sql"))   return "sql";
    if (n.includes("redis")) return "redis";
    if (n.includes("svc") || n.includes("web")) return "filter";
    return "filter";
  }

  // Auto-load instances if table exists on page
  if ($("#instances")) refreshInstances();
})();
