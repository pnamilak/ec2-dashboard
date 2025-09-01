// website/login.js
// -----------------------------------------------------------------------------
// Front-end glue for OTP login + instance list + actions + Services modal.
// Works with the Lambda above. Sends the new payload shape, but the backend
// also supports legacy shapes for safety.
// -----------------------------------------------------------------------------

(function () {
  const API_BASE =
    window.__API_BASE__ ||
    (document.querySelector("meta[name=api-base]")?.content || "").trim() ||
    ""; // e.g., "https://u5gyqkfkc3.execute-api.us-east-2.amazonaws.com"

  if (!API_BASE) {
    console.warn("API base not configured; set window.__API_BASE__ or <meta name='api-base'>");
  }

  // ------------- tiny helpers -------------
  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => Array.from(document.querySelectorAll(sel));

  async function api(path, method = "GET", body) {
    const opt = { method, headers: { "Content-Type": "application/json" } };
    if (body) opt.body = JSON.stringify(body);
    const r = await fetch(API_BASE + path, opt);
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return j;
  }

  // ------------- OTP flow -------------
  const emailInput = $("#email");
  const otpInput = $("#otp");
  const btnReq = $("#btn-request-otp");
  const btnVerify = $("#btn-verify-otp");
  const btnLogin = $("#btn-login");
  const tokenSpan = $("#token");

  btnReq?.addEventListener("click", async () => {
    const email = emailInput.value.trim();
    if (!email) return alert("Enter email");
    const res = await api("/request-otp", "POST", { email });
    alert(res.ok ? "OTP sent (check email). Dev: " + (res.code || "") : "Failed: " + res.error);
  });

  btnVerify?.addEventListener("click", async () => {
    const email = emailInput.value.trim();
    const code = otpInput.value.trim();
    const res = await api("/verify-otp", "POST", { email, code });
    alert(res.ok ? "OTP is valid" : "Invalid OTP");
  });

  btnLogin?.addEventListener("click", async () => {
    const email = emailInput.value.trim();
    const code = otpInput.value.trim();
    const res = await api("/login", "POST", { email, code });
    if (!res.ok) return alert("Login failed: " + res.error);
    localStorage.setItem("jwt", res.token);
    tokenSpan.textContent = res.token.slice(0, 24) + "…";
    await refreshInstances();
  });

  // ------------- Instances -------------
  const tbl = $("#instances");
  const btnRefresh = $("#btn-refresh");
  const btnStartAll = $("#btn-start-all");
  const btnStopAll = $("#btn-stop-all");

  async function refreshInstances() {
    const res = await api("/instances", "GET");
    if (!res.ok) return alert("Failed to list instances");
    renderInstances(res.instances || []);
  }

  function renderInstances(items) {
    const rows = items
      .map((x) => {
        const id = x.id, name = x.name || id, state = x.state || "";
        const svcBtn = `<button class="btn btn-svc" data-id="${id}" data-name="${name}">Services</button>`;
        const startBtn = `<button class="btn btn-start" data-id="${id}">Start</button>`;
        const stopBtn = `<button class="btn btn-stop" data-id="${id}">Stop</button>`;
        const rebootBtn = `<button class="btn btn-reboot" data-id="${id}">Reboot</button>`;
        return `<tr>
          <td>${name}</td>
          <td>${id}</td>
          <td>${state}</td>
          <td>${startBtn} ${stopBtn} ${rebootBtn} ${svcBtn}</td>
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
    if (b.classList.contains("btn-start")) {
      await api("/instance-action", "POST", { instanceId: id, op: "start" });
      return refreshInstances();
    }
    if (b.classList.contains("btn-stop")) {
      await api("/instance-action", "POST", { instanceId: id, op: "stop" });
      return refreshInstances();
    }
    if (b.classList.contains("btn-reboot")) {
      await api("/instance-action", "POST", { instanceId: id, op: "reboot" });
      return refreshInstances();
    }
    if (b.classList.contains("btn-svc")) {
      openServicesModal({ instanceId: id, instanceName: b.dataset.name || "" });
    }
  });

  btnStartAll?.addEventListener("click", async () => {
    const ids = $$("tbody tr td:nth-child(2)").map((td) => td.textContent.trim()).filter(Boolean);
    if (!ids.length) return;
    await api("/bulk-action", "POST", { instanceIds: ids, op: "start" });
    refreshInstances();
  });

  btnStopAll?.addEventListener("click", async () => {
    const ids = $$("tbody tr td:nth-child(2)").map((td) => td.textContent.trim()).filter(Boolean);
    if (!ids.length) return;
    await api("/bulk-action", "POST", { instanceIds: ids, op: "stop" });
    refreshInstances();
  });

  // ------------- Services Modal -------------
  const modal = $("#svc-modal");
  const modalTitle = $("#svc-title");
  const listBody = $("#svc-list");
  const selMode = $("#svc-mode");
  const inpFilter = $("#svc-filter");
  const btnList = $("#svc-list-btn");
  const btnIISReset = $("#svc-iisreset");
  let currentSvcContext = null;

  function openServicesModal(ctx) {
    currentSvcContext = { ...ctx, mode: guessModeFromName(ctx.instanceName) };
    selMode.value = currentSvcContext.mode;
    modalTitle.textContent = `Services — ${ctx.instanceName} (${ctx.instanceId})`;
    listBody.innerHTML = `<tr><td colspan="4">Click "List"</td></tr>`;
    modal.style.display = "block";
  }

  $("#svc-close")?.addEventListener("click", () => (modal.style.display = "none"));

  selMode?.addEventListener("change", () => {
    if (currentSvcContext) currentSvcContext.mode = selMode.value;
  });

  btnList?.addEventListener("click", async () => {
    if (!currentSvcContext) return;
    const mode = selMode.value;
    const query = inpFilter.value.trim();
    const payload = { instanceId: currentSvcContext.instanceId, op: "list", mode };
    if (mode === "filter" && query) payload.query = query;

    const res = await api("/services", "POST", payload);
    if (!res.ok) {
      const msg = res.error === "ssm_not_connected" ? "SSM: not connected" :
                  res.error === "unsupported" ? "Unsupported mode" :
                  "Error: " + res.error;
      listBody.innerHTML = `<tr><td colspan="4">${msg}</td></tr>`;
      return;
    }
    const rows = (res.services || []).map(s => {
      const n = s.name || "", d = s.displayName || "", st = s.status || "";
      const startBtn = `<button class="svc-start" data-name="${n}">Start</button>`;
      const stopBtn  = `<button class="svc-stop" data-name="${n}">Stop</button>`;
      return `<tr><td>${n}</td><td>${d}</td><td>${st}</td><td>${startBtn} ${stopBtn}</td></tr>`;
    }).join("");
    listBody.innerHTML = rows || `<tr><td colspan="4">No services</td></tr>`;
  });

  listBody?.addEventListener("click", async (e) => {
    const b = e.target.closest("button");
    if (!b || !currentSvcContext) return;
    const serviceName = b.dataset.name;
    const op = b.classList.contains("svc-start") ? "start" : "stop";
    const res = await api("/services", "POST", {
      instanceId: currentSvcContext.instanceId,
      op,
      mode: selMode.value,
      serviceName
    });
    if (res.ok) {
      // Update row status
      await btnList.click();
    } else {
      alert("Service action failed: " + res.error);
    }
  });

  btnIISReset?.addEventListener("click", async () => {
    if (!currentSvcContext) return;
    const res = await api("/services", "POST", {
      instanceId: currentSvcContext.instanceId,
      op: "iisreset",
      mode: "filter"
    });
    alert(res.ok ? "IIS reset sent" : "IIS reset failed: " + res.error);
  });

  function guessModeFromName(name) {
    const n = (name || "").toLowerCase();
    if (n.includes("sql")) return "sql";
    if (n.includes("redis")) return "redis";
    if (n.includes("svc") || n.includes("web")) return "filter";
    return "filter";
  }

  // Auto-load instances if table exists on page
  if (tbl) refreshInstances();
})();
