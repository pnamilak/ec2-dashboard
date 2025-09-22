// html/login.js
// Fixed: API base, JWT header, displayName (from JWT.name), "readonly" UI rules.
// Readonly rules:
//   • Per instance: ONLY "Services" shown (Start/Stop hidden)
//   • Bulk bar: "Start all" / "Stop all" hidden
//   • Services modal: service Start/Stop disabled/faded; IIS button disabled
// Other flows/markup untouched.

(() => {
  // ------------ Core config ------------
  const API =
    (window.__API_BASE__ || window.API_BASE || localStorage.getItem("api_base_url") || "").replace(/\/+$/, "");

  const jwt = () => {
    const t = localStorage.getItem("jwt");
    return (t && t !== "undefined" && t !== "null") ? t : "";
  };

  const hdrs = () => ({
    "Content-Type": "application/json",
    ...(jwt() ? { "Authorization": "Bearer " + jwt() } : {}),
  });

  // ------------ Mini helpers ------------
  const q  = (sel, el = document) => el.querySelector(sel);
  const qq = (sel, el = document) => Array.from(el.querySelectorAll(sel));

  // Basic toast (kept)
  function toast(msg) {
    try { console.log(msg); } catch {}
    const el = q("#toast");
    if (!el) {
      if (window.toast) { window.toast(msg); }
      else {
        let t = document.getElementById("__dash_toast");
        if (!t) {
          t = document.createElement("div");
          t.id = "__dash_toast";
          Object.assign(t.style, {
            position: "fixed", left: "50%", bottom: "28px", transform: "translateX(-50%)",
            background: "rgba(0,0,0,.8)", color: "#fff", padding: "10px 14px",
            borderRadius: "10px", fontSize: "14px", zIndex: "9999",
            boxShadow: "0 8px 24px rgba(0,0,0,.35)", maxWidth: "70vw", textAlign: "center",
            pointerEvents: "none"
          });
          document.body.appendChild(t);
        }
        t.textContent = String(msg || "");
        t.style.opacity = "1";
        setTimeout(() => { t.style.transition = "opacity .35s"; t.style.opacity = "0"; }, 1600);
      }
      return;
    }
    el.textContent = msg;
    el.classList.add("show");
    setTimeout(() => el.classList.remove("show"), 1800);
  }

  // Dedicated readonly popup (modal)
  function roNotice(message) {
    const msg = String(message || "This action is not allowed for Readonly users.");
    let m = document.getElementById("__ro_notice");
    if (!m) {
      m = document.createElement("div");
      m.id = "__ro_notice";
      Object.assign(m.style, {
        position: "fixed", inset: "0", display: "flex", alignItems: "center", justifyContent: "center",
        background: "rgba(0,0,0,.45)", zIndex: 99999
      });
      m.innerHTML = `
        <div style="background:#162338;color:#fff;min-width:320px;max-width:90vw;padding:18px 16px;border-radius:12px;border:1px solid rgba(255,255,255,.15);box-shadow:0 12px 32px rgba(0,0,0,.45)">
          <div style="font-weight:800;font-size:16px;margin-bottom:8px">Action not allowed</div>
          <div id="__ro_msg" style="opacity:.9"></div>
          <div style="text-align:right;margin-top:14px">
            <button id="__ro_ok" class="btn ok" type="button">OK</button>
          </div>
        </div>`;
      document.body.appendChild(m);
      const ok = document.getElementById("__ro_ok");
      ok && ok.addEventListener("click", () => m.remove());
      m.addEventListener("click", (e) => { if (e.target === m) m.remove(); });
    }
    const box = m.querySelector("#__ro_msg");
    if (box) box.textContent = msg;
    m.style.display = "flex";
  }

  // Decode base64url JSON safely (no exceptions)
  function decodeJwtPayloadSafe(t) {
    try {
      const p = t.split(".")[1]; if (!p) return {};
      const b = p.replace(/-/g, "+").replace(/_/g, "/");
      const json = decodeURIComponent(atob(b).split("").map(c => "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2)).join(""));
      return JSON.parse(json || "{}");
    } catch { return {}; }
  }

  function titleCaseWords(s) { return String(s || "").replace(/\b([a-z])/g, m => m.toUpperCase()); }

  function escapeHtml(s) {
    return String(s)
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");
  }

  // ------------ Role / Read-only detection (now dynamic) ------------
  let claims = {};
  try { const t = jwt(); if (t && t.includes(".")) claims = decodeJwtPayloadSafe(t); } catch {}

  function currentRole() {
    try {
      const t = jwt();
      let p = claims;
      if (t && t.includes(".")) p = decodeJwtPayloadSafe(t);

      const fromJwt =
        String(
          p.access ?? 
          p.role ?? 
          p["custom:access"] ?? 
          (Array.isArray(p["cognito:groups"]) ? p["cognito:groups"][0] : "") ?? 
          ""
        ).toLowerCase();

      const fromLS =
        String(localStorage.getItem("role") ||
               localStorage.getItem("access") ||
               "").toLowerCase();

      return (fromJwt || fromLS || "user");
    } catch { return "user"; }
  }

  const isRO = () => ["readonly", "read", "viewer", "ro"].includes(currentRole());

  function markReadonlyDataAttr() {
    try {
      if (isRO()) document.documentElement.setAttribute("data-access", "readonly");
      else document.documentElement.removeAttribute("data-access");
    } catch {}
  }
  markReadonlyDataAttr();
  setTimeout(markReadonlyDataAttr, 250);
  setTimeout(markReadonlyDataAttr, 1000);

  (function ensureDisabledStyle(){
    if (document.getElementById("global-disabled-style")) return;
    const s = document.createElement("style");
    s.id = "global-disabled-style";
    s.textContent = `
      .btn-disabled, .btn[disabled], .pill[disabled]{
        opacity:.45!important; cursor:not-allowed!important;
        pointer-events:none!important; filter:grayscale(18%)!important;
      }
      /* CSS guard */
      [data-access="readonly"] #dm-start-all,
      [data-access="readonly"] #dm-stop-all,
      [data-access="readonly"] #ea-start-all,
      [data-access="readonly"] #ea-stop-all { display:none !important; }
      [data-access="readonly"] .inst-row .actions .btn[data-op="start"],
      [data-access="readonly"] .inst-row .actions .btn[data-op="stop"] { display:none !important; }
      [data-access="readonly"] #svcRows button[data-op]{
        pointer-events:none !important; opacity:.45 !important; cursor:not-allowed !important; filter:grayscale(18%) !important;
      }
      [data-access="readonly"] #svcIIS{
        pointer-events:none !important; opacity:.45 !important; cursor:not-allowed !important; filter:grayscale(18%) !important;
      }
    `;
    (document.head || document.documentElement).appendChild(s);
  })();

  // --- UNIVERSAL READ-ONLY GUARD (UI level) ---
  (function readonlyGuard(){
    function hardReadonlySweep(root = document) {
      if (!isRO()) return;
      const all = root.querySelectorAll('button, [role="button"]');
      all.forEach(b => {
        try {
          const isStart = (b.dataset && b.dataset.op === "start");
          const isStop  = (b.dataset && b.dataset.op === "stop");
          const text = (b.textContent || b.innerText || "").trim().toLowerCase();
          if (isStart || isStop || text === "start" || text === "stop" || text === "start all" || text === "stop all") {
            b.disabled = true;
            b.classList && b.classList.add("btn-disabled");
            b.title = "Read-only user";
            b.style.display = "none"; // hide only start/stop (Services stays)
          }
        } catch {}
      });
    }

    hardReadonlySweep();
    const mo = new MutationObserver(muts => {
      muts.forEach(m => {
        m.addedNodes && m.addedNodes.forEach(n => { if (n.nodeType === 1) hardReadonlySweep(n); });
      });
    });
    try { mo.observe(document.body, { childList: true, subtree: true }); } catch {}

    function isDangerBtn(target) {
      const el = target && (target.closest && target.closest('button, [role="button"]'));
      if (!el) return false;
      const text = (el.textContent || el.innerText || "").trim().toLowerCase();
      const dop  = (el.dataset && el.dataset.op) || "";
      return (dop === "start" || dop === "stop" ||
              text === "start" || text === "stop" ||
              text === "start all" || text === "stop all");
    }
    const block = (e) => {
      if (!isRO()) return;
      if (!isDangerBtn(e.target)) return;
      e.preventDefault(); e.stopPropagation(); e.stopImmediatePropagation && e.stopImmediatePropagation();
      roNotice("Start/Stop is not permitted for Readonly users.");
      return false;
    };
    document.addEventListener("click", block, true);
    document.addEventListener("mousedown", block, true);
    document.addEventListener("pointerdown", block, true);
    document.addEventListener("keydown", (e) => {
      if (!isRO()) return;
      if ((e.key === "Enter" || e.key === " ") && isDangerBtn(e.target)) {
        e.preventDefault(); e.stopPropagation(); e.stopImmediatePropagation && e.stopImmediatePropagation();
        roNotice("Start/Stop is not permitted for Readonly users.");
      }
    }, true);

    let ticks = 0;
    const iv = setInterval(() => {
      try { markReadonlyDataAttr(); hardReadonlySweep(); } catch {}
      if (++ticks > 24) clearInterval(iv);
    }, 250);
  })();

  // --- NETWORK-LEVEL READONLY GUARD (final backstop) ---
  (function readonlyNetworkGuard(){
    if (typeof window.fetch !== "function") return;
    const nativeFetch = window.fetch.bind(window);

    window.fetch = async function(input, init = {}) {
      try {
        const url = (typeof input === "string") ? input : (input && input.url) || "";
        const method = String((init && init.method) || "GET").toUpperCase();

        if (isRO() && method === "POST" && /\/(instance-action|bulk-action|services)\b/.test(url)) {
          let op = "";
          try {
            const body = init && init.body;
            if (typeof body === "string") {
              const j = JSON.parse(body);
              op = String(j.op || j.serviceOp || "").toLowerCase();
            }
          } catch {}

          const hittingInstance = url.includes("/instance-action");
          const hittingBulk     = url.includes("/bulk-action");
          const hittingSvcCtl   = url.includes("/services") && (op === "start" || op === "stop" || op === "iisreset");

          if (hittingInstance || hittingBulk || hittingSvcCtl) {
            let msg = "This action is not allowed for Readonly users.";
            if (hittingBulk)        msg = "Bulk actions (Start/Stop all) are not allowed for Readonly users.";
            else if (hittingSvcCtl) msg = `Service ${op || "control"} is not allowed for Readonly users.`;
            else if (hittingInstance && op) msg = `${op[0]?.toUpperCase()}${op.slice(1)} is not allowed for Readonly users.`;
            roNotice(msg);

            return new Response(
              JSON.stringify({ ok: false, error: "forbidden (readonly user)" }),
              { status: 403, headers: { "Content-Type": "application/json" } }
            );
          }
        }
      } catch {}
      return nativeFetch(input, init);
    };
  })();

  document.addEventListener("click", (e) => {
    const a = e.target.closest && e.target.closest('a[href="/services"]');
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
    renderEnv(STATE.envOrder[0] || "Summary");
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
    add("Summary");
    STATE.envOrder.forEach(add);
  }

  function instancesInEnv(env) {
    if (env === "Summary" || !STATE.envs || !STATE.envs[env]) return { DM: [], EA: [] };
    return STATE.envs[env];
  }

  // ---------- POST-RENDER SWEEP ----------
  function applyReadonlyUI() {
    if (!isRO()) return;

    const blockSelectors = [
      "#dm-start-all", "#dm-stop-all",
      "#ea-start-all", "#ea-stop-all",
      "#dm-iis-svc", "#dm-iis-web",
      "#ea-iis-svc", "#ea-iis-web"
    ];

    blockSelectors.forEach(sel => {
      const b = q(sel);
      if (b) {
        b.disabled = false;
        b.classList.add("btn-disabled");
        b.onclick = () => roNotice("This action is not permitted for Readonly users.");
      }
    });

    qq('.inst-row .actions .btn[data-op="start"], .inst-row .actions .btn[data-op="stop"]').forEach(b => {
      if (b) {
        b.disabled = false;
        b.classList.add("btn-disabled");
        b.onclick = () => roNotice("Start/Stop is not permitted for Readonly users.");
      }
    });

    qq('#svcRows button[data-op="start"], #svcRows button[data-op="stop"]').forEach(b => {
      if (b) {
        b.disabled = false;
        b.classList.add("btn-disabled");
        b.onclick = () => roNotice("Service Start/Stop is not permitted for Readonly users.");
      }
    });

    const iisBtn = q("#svcIIS");
    if (iisBtn) {
      iisBtn.disabled = false;
      iisBtn.classList.add("btn-disabled");
      iisBtn.onclick = () => roNotice("IIS reset is not permitted for Readonly users.");
    }
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
    [["DM", dm], ["EA", ea]].forEach(([team, mount]) => {
      if (!mount) return;
      (groups[team] || []).forEach(inst => mount.appendChild(instanceRow(inst)));
    });

    const dmStart = q("#dm-start-all");
    const dmStop  = q("#dm-stop-all");
    const eaStart = q("#ea-start-all");
    const eaStop  = q("#ea-stop-all");
    if (dmStart) dmStart.onclick = () => startAll(env, "DM");
    if (dmStop)  dmStop.onclick  = () => stopAll(env, "DM");
    if (eaStart) eaStart.onclick = () => startAll(env, "EA");
    if (eaStop)  eaStop.onclick  = () => stopAll(env, "EA");

    const dmIisSvc = q("#dm-iis-svc");
    const dmIisWeb = q("#dm-iis-web");
    const eaIisSvc = q("#ea-iis-svc");
    const eaIisWeb = q("#ea-iis-web");

    if (dmIisSvc) dmIisSvc.onclick = () => __iisResetGroup(env, "DM", "svc", dmIisSvc);
    if (dmIisWeb) dmIisWeb.onclick = () => __iisResetGroup(env, "DM", "web", dmIisWeb);
    if (eaIisSvc) eaIisSvc.onclick = () => __iisResetGroup(env, "EA", "svc", eaIisSvc);
    if (eaIisWeb) eaIisWeb.onclick = () => __iisResetGroup(env, "EA", "web", eaIisWeb);

    if (isRO()) { [dmStart, dmStop, eaStart, eaStop].forEach(b => { if (b) b.style.display = "none"; }); }

    applyReadonlyUI();
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

    if (btnStart) btnStart.onclick = (e) => { e.preventDefault(); e.stopPropagation(); doAction(inst.id, "start"); };
    if (btnStop)  btnStop.onclick  = (e) => { e.preventDefault(); e.stopPropagation(); doAction(inst.id, "stop");  };
    if (btnSvc)   btnSvc.addEventListener("click", (e) => { e.preventDefault(); e.stopPropagation(); openServices(inst); });

    if (btnStart && (inst.state || "").toLowerCase() === "running") btnStart.disabled = true;
    if (btnStop  && (inst.state || "").toLowerCase() === "stopped") btnStop.disabled  = true;

    if (isRO()) {
      if (btnStart) { btnStart.disabled = true; btnStart.classList.add("btn-disabled"); btnStart.style.display = "none"; }
      if (btnStop)  { btnStop.disabled  = true; btnStop.classList.add("btn-disabled");  btnStop.style.display  = "none"; }
    }

    // dataset used by Services modal
    row.dataset.instanceId   = inst.id;
    row.dataset.instanceName = inst.name || inst.id;
    row.dataset.platform     = (inst.platform || "").toLowerCase();

    return row;
  }

  async function doAction(id, op) {
    if (isRO()) { roNotice(`${op[0].toUpperCase()+op.slice(1)} is not permitted for Readonly users.`); return; }
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
    const list = (instancesInEnv(env)[role] || []);

    const isSql = (name) => {
      const n = String(name||"").toLowerCase();
      return n.includes("sql") || n.includes("mssql") || n.includes("postgres") || n.includes("mysql");
    };
    const isRedis = (name) => {
      const n = String(name||"").toLowerCase();
      return n.includes("redis") || n.includes("cache");
    };
    const isRabbit = (name) => {
      const n = String(name||"").toLowerCase();
      return n.includes("rabbit") || n.includes("rabbitmq") || (n.includes("mq") && !n.includes("sqs"));
    };

    const sql    = [];
    const redis  = [];
    const rabbit = [];
    const svc    = [];
    const web    = [];
    const other  = [];

    for (const it of list){
      const nm = it.name || it.instanceName || it.id || "";
      if      (isSql(nm))    sql.push(it);
      else if (isRedis(nm))  redis.push(it);
      else if (isRabbit(nm)) rabbit.push(it);
      else if (__isSvcName(nm)) svc.push(it);
      else if (__isWebName(nm)) web.push(it);
      else other.push(it);
    }

    const order = [sql, redis, rabbit, svc, web, other];
    for (const bucket of order){
      for (const it of bucket){
        try { await doAction(it.id, "start"); } catch(e){ /* continue */ }
      }
    }
  }

  async function stopAll(env, role) {
    const ids = (instancesInEnv(env)[role] || []).map(x => x.id);
    if (!ids.length) return;
    await bulk("stop", ids);
  }
  async function bulk(op, ids) {
    if (isRO()) { roNotice(`Bulk ${op} is not permitted for Readonly users.`); return; }
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

  // Decide quick mode from instance name + query
  function decideMode(instanceName, query) {
    const s = ((instanceName || "") + " " + (query || "")).toLowerCase();
    if (s.includes("rabbitmq") || /\brabbit\b/.test(s)) return "rabbit";
    if (s.includes("redis")) return "redis";
    return "filter";
  }

  // Open modal: do NOT fetch yet; wait for click on "List"
  function openServices(inst) {
    const modal = q("#svcModal");
    if (!modal) return;
    const title = q("#svcTitle");
    const input = q("#svcQuery");
    const rows  = q("#svcRows");

    modal.dataset.iid   = inst.id;
    modal.dataset.iname = inst.name || inst.id;
    modal.dataset.os    = (inst.platform || "").toLowerCase();

    if (title) title.textContent = `Services – ${inst.name || inst.id}`;
    if (input) input.value = "";
    if (rows)  rows.innerHTML = "";

    // show IIS only when Windows + generic filter mode
    const iisBtn = q("#svcIIS");
    if (iisBtn) {
      const isLinux = modal.dataset.os === "linux";
      iisBtn.style.display = isLinux ? "none" : "";
      if (isRO()) { iisBtn.disabled = true; iisBtn.classList.add("btn-disabled"); }
    }

    modal.classList.add("show");
  }

  function closeServices() {
    const modal = q("#svcModal");
    if (modal) modal.classList.remove("show");
  }

  // Main “List” action (bound to the existing #svcList button)
  async function listServices() {
    const modal = q("#svcModal");
    if (!modal) return;
    const iid    = modal.dataset.iid;
    const iname  = modal.dataset.iname || "";
    const os     = (modal.dataset.os || "").toLowerCase();
    const input  = q("#svcQuery");
    const rowsEl = q("#svcRows");
    const query  = (input && input.value ? input.value.trim() : "");

    const mode = decideMode(iname, query);

    // Windows requires 2+ chars for generic filter. Linux: same rule to prevent noisy empty runs.
    if (mode === "filter" && (!query || query.length < 2)) {
      if (rowsEl) rowsEl.innerHTML = `<tr><td colspan="4" class="muted">Type 2+ letters (SVC/WEB). Linux won’t auto-list.</td></tr>`;
      return;
    }

    if (rowsEl) rowsEl.innerHTML = `<tr><td colspan="4" class="muted">Listing…</td></tr>`;

    const r = await fetch(`${API}/services`, {
      method: "POST",
      headers: hdrs(),
      body: JSON.stringify({ instanceId: iid, op: "list", mode, query })
    });
    const j = await r.json();

    if (rowsEl) rowsEl.innerHTML = "";

    if (!j.ok) {
      if (rowsEl) rowsEl.innerHTML = `<tr><td colspan="4" class="muted">No services (${j.error || "failed"})</td></tr>`;
      applyReadonlyUI();
      return;
    }

    const list = j.services || [];
    if (!list.length) {
      if (rowsEl) rowsEl.innerHTML = `<tr><td colspan="4" class="muted">No matching services.</td></tr>`;
      applyReadonlyUI();
      return;
    }

    const norm = (v) => {
      const s = String(v || "unknown").toLowerCase();
      if (["running","started","startpending","active","activating"].includes(s)) return "running";
      if (["stopped","stoppped","stoppending","inactive","failed","deactivating"].includes(s)) return "stopped";
      return s || "unknown";
    };

    rowsEl.innerHTML = list.map(svc => {
      const name  = svc.name || svc.Name || svc.service || svc.Service || svc.ServiceName || "";
      const disp  = svc.display || svc.displayName || svc.Display || svc.DisplayName || svc.Description || name || "—";
      const stat  = norm(svc.status || svc.Status || svc.state || svc.State || svc.ActiveState);
      const act   = name ? ((stat === "running")
        ? `<button class="btn danger" data-op="stop">Stop</button>`
        : `<button class="btn ok" data-op="start">Start</button>`) : "";
      return `<tr data-name="${name || ""}">
        <td>${name || "—"}</td>
        <td>${disp}</td>
        <td><span class="badge ${stat}">${stat[0].toUpperCase()+stat.slice(1)}</span></td>
        <td>${act}</td>
      </tr>`;
    }).join("");

    if (!rowsEl._bound) {
      rowsEl.addEventListener("click", (e) => {
        const b = e.target.closest && e.target.closest("button[data-op]");
        if (!b) return;
        e.preventDefault(); e.stopPropagation();
        if (isRO()) { roNotice("Service control is not permitted for Readonly users."); return; }
        const tr  = b.closest("tr");
        const svc = tr ? (tr.dataset.name || tr.querySelector("td")?.textContent?.trim()) : "";
        if (!svc) { toast("service name missing"); return; }
        changeService(iid, svc, b.dataset.op, iname);
      }, true);
      rowsEl._bound = true;
    }

    applyReadonlyUI();
  }

  async function changeService(iid, name, op, iname) {
    if (!name) { toast("service name missing"); return; }
    if (isRO()) { roNotice("Service control is not permitted for Readonly users."); return; }

    const payload = {
      instanceId: iid,
      id: iid,
      op,
      serviceName: name,
      service: name,
      instanceName: iname || ""
    };

    const r = await fetch(`${API}/services`, {
      method: "POST",
      headers: hdrs(),
      body: JSON.stringify(payload)
    });
    const j = await r.json();
    if (!j.ok) { try { console.error("Service action failed:", j); } catch {} toast(j.error || "svc_failed"); return; }
    await listServices();
  }

  // wire modal buttons (IDs already in your HTML)
  document.addEventListener("click", (e) => {
    if (e.target.id === "svcClose") { e.preventDefault(); closeServices(); }
    if (e.target.id === "svcList")  { e.preventDefault(); listServices(); }
    if (e.target.id === "svcIIS")   { e.preventDefault(); iisReset(); }
  });

  async function iisReset() {
    if (isRO()) { roNotice("IIS reset is not permitted for Readonly users."); return; }
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

  // ------------ Profile dropdown + identity helpers ------------
  function getIdentityFromJwtForUI() {
    const p = (() => { try { const t = jwt(); return (t && t.includes(".")) ? decodeJwtPayloadSafe(t) : claims; } catch { return claims; } })();
    let name =
      p.name ||
      p.displayName ||
      (p.given_name ? (p.given_name + (p.family_name ? (" " + p.family_name) : "")) : "") ||
      "";
    let email = p.email || p.upn || "";
    const uname = p["cognito:username"] || p.preferred_username || p.username || "";

    try {
      const u = JSON.parse(localStorage.getItem("user") || "{}");
      if (!name)  name  = u.name || u.displayName || u.username || name;
      if (!email) email = u.email || email;
    } catch {}

    if (!name) {
      const basis = (email || uname || "").split("@")[0];
      if (basis) name = titleCaseWords(basis.replace(/[._-]+/g, " "));
    }
    if (!name)  name  = "User";
    if (!email) email = "unknown@example.com";

    const role  = (p.access || p.role || currentRole() || "user") + "";
    return { name, email, role };
  }

  function findLogoutButton() {
    const candidates = [
      "#logoutBtn", "#logout", "#btnLogout", "[data-logout]",
      "button", "a"
    ];
    for (const sel of candidates) {
      const list = qq(sel);
      for (const n of list) {
        const t = (n.textContent || "").trim().toLowerCase();
        if (n.matches && n.matches("[data-logout]")) return n;
        if (t === "logout" || t === "sign out" || t === "signout") return n;
      }
    }
    return null;
  }

  function ensureProfileDropdown() {
    const logoutNode = findLogoutButton();
    if (!logoutNode) return;

    const { name, email, role } = getIdentityFromJwtForUI();
    const initials = (name || "U").split(/\s+/).map(s => s.charAt(0)).join("").slice(0, 2).toUpperCase();
    const roleLabel = role.charAt(0).toUpperCase() + role.slice(1);

    const wrap = document.createElement("div");
    wrap.style.position = "relative";
    wrap.style.display = "inline-block";
    wrap.style.marginLeft = "8px";
    wrap.setAttribute("data-profile-wrap", "1");

    const btn = document.createElement("button");
    btn.type = "button";
    btn.setAttribute("aria-haspopup", "menu");
    btn.setAttribute("aria-expanded", "false");
    Object.assign(btn.style, {
      display: "inline-flex", alignItems: "center", gap: "8px",
      padding: "6px 10px", border: "1px solid rgba(255,255,255,0.15)",
      background: "transparent", color: "inherit", borderRadius: "999px",
      cursor: "pointer"
    });

    const avatar = document.createElement("div");
    avatar.textContent = initials;
    Object.assign(avatar.style, {
      width: "28px", height: "28px", borderRadius: "50%", display: "inline-flex",
      alignItems: "center", justifyContent: "center", fontWeight: "700", userSelect: "none",
      background: "rgba(255,255,255,0.12)", border: "1px solid rgba(255,255,255,0.15)"
    });

    const caret = document.createElement("span");
    caret.textContent = "▾";
    caret.style.opacity = "0.8";
    caret.style.fontSize = "12px";

    btn.appendChild(avatar);
    btn.appendChild(caret);

    const dd = document.createElement("div");
    dd.setAttribute("role", "menu");
    Object.assign(dd.style, {
      position: "absolute", right: "0", top: "calc(100% + 8px)", minWidth: "260px",
      background: "var(--panel, #121b2b)", border: "1px solid rgba(255,255,255,0.12)",
      borderRadius: "12px", boxShadow: "0 8px 24px rgba(0,0,0,0.35)", padding: "10px",
      display: "none", zIndex: "1000"
    });

    const prof = document.createElement("div");
    Object.assign(prof.style, { display: "grid", gridTemplateColumns: "36px 1fr", gap: "10px" });
    const av2 = avatar.cloneNode(true);
    av2.style.width = "36px"; av2.style.height = "36px";
    const meta = document.createElement("div");
    meta.innerHTML = `
      <div style="font-weight:700">${escapeHtml(name)}</div>
      <div style="opacity:.8;font-size:12px">${escapeHtml(email)}</div>
      <div style="opacity:.8;font-size:12px">Access: ${escapeHtml(roleLabel)}</div>
    `;
    prof.appendChild(av2); prof.appendChild(meta);

    function styleMenuBtn(b) {
      Object.assign(b.style, {
        width: "100%", padding: "8px 10px",
        border: "1px solid rgba(255,255,255,0.15)",
        background: "transparent", color: "inherit",
        borderRadius: "8px", cursor: "pointer"
      });
    }
    function line() {
      const r = document.createElement("div");
      r.style.height = "1px";
      r.style.background = "rgba(255,255,255,0.08)";
      r.style.margin = "8px 0";
      return r;
    }

    const settings = document.createElement("button");
    settings.type = "button";
    settings.textContent = "Settings";
    styleMenuBtn(settings);

    const signout = document.createElement("button");
    signout.type = "button";
    signout.textContent = "Sign out";
    styleMenuBtn(signout);

    dd.appendChild(prof);
    dd.appendChild(line());
    if (!isRO()) dd.appendChild(settings);
    dd.appendChild(signout);

    wrap.appendChild(btn);
    wrap.appendChild(dd);

    logoutNode.replaceWith(wrap);

    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      const open = dd.style.display !== "none";
      dd.style.display = open ? "none" : "block";
      btn.setAttribute("aria-expanded", String(!open));
    });
    document.addEventListener("click", () => {
      dd.style.display = "none";
      btn.setAttribute("aria-expanded", "false");
    }, { capture: true });

    settings.addEventListener("click", (e) => {
      e.preventDefault();
      dd.style.display = "none";
      if (typeof showSettingsPicker === "function") showSettingsPicker();
      else showSettingsModal();
    });

    signout.addEventListener("click", () => { localStorage.clear(); location.reload(); });
  }

  function applyIdentityToExistingUI() {
    const { name, email, role } = getIdentityFromJwtForUI();
    const candidates = ["#nameEl", "#userName", ".user-name", "#profileName", "[data-user-name]"];
    for (const sel of candidates) {
      const el = document.querySelector(sel);
      if (el) { try { el.textContent = name; } catch {} }
    }
    const ecandidates = ["#userEmail", ".user-email", "#profileEmail", "[data-user-email]"];
    for (const sel of ecandidates) {
      const el = document.querySelector(sel);
      if (el) { try { el.textContent = email; } catch {} }
    }
    const rcandidates = ["#userRole", ".user-role", "[data-user-role]"];
    for (const sel of rcandidates) {
      const el = document.querySelector(sel);
      if (el) { try { el.textContent = (role.charAt(0).toUpperCase() + role.slice(1)); } catch {} }
    }
  }

  // ------------ Settings: Create User (modal) ------------
  function showSettingsModal() {
    let modal = document.getElementById("settingsModal");
    if (modal) { modal.style.display = "flex"; return; }

    modal = document.createElement("div");
    modal.id = "settingsModal";
    Object.assign(modal.style, {
      position: "fixed", top: "0", left: "0", width: "100%", height: "100%",
      background: "rgba(0,0,0,0.6)", display: "flex", alignItems: "center",
      justifyContent: "center", zIndex: "2000"
    });

    modal.innerHTML = `
      <div style="background:#162338; padding:20px; border-radius:12px; width:360px; color:#fff">
        <h3 style="margin-top:0">Create User</h3>
        <label>Name<br><input id="setName" style="width:100%"></label><br>
        <label>Email<br><input id="setEmail" style="width:100%"></label><br>
        <label>Username<br><input id="setUser" style="width:100%"></label><br>
        <label>Password<br><input type="password" id="setPass" style="width:100%"></label><br>
        <label>Access<br>
          <select id="setAccess" style="width:100%">
            <option value="admin">Admin</option>
            <option value="readonly">Readonly</option>
          </select>
        </label><br><br>
        <div id="setMsg" style="color:#ffc9c9; min-height:16px; margin:6px 0;"></div>
        <div style="display:flex; gap:10px; justify-content:flex-end">
          <button id="createUserBtn" class="btn ok" type="button">Create User</button>
          <button id="closeSet" class="btn danger" type="button">Close</button>
        </div>
      </div>
    `;

    document.body.appendChild(modal);

    modal.querySelector("#closeSet").onclick = () => { modal.style.display = "none"; };

    modal.querySelector("#createUserBtn").onclick = async () => {
      const msg = modal.querySelector("#setMsg");
      if (msg) msg.textContent = "";
      const btn = modal.querySelector("#createUserBtn");

      const name = (modal.querySelector("#setName").value || "").trim();
      const email = (modal.querySelector("#setEmail").value || "").trim();
      const username = (modal.querySelector("#setUser").value || "").trim();
      const passwordRaw = (modal.querySelector("#setPass").value || "").trim();
      const role = (modal.querySelector("#setAccess").value || "readonly").toLowerCase();

      if (!name || !email || !username || !passwordRaw || !role) {
        if (msg) msg.textContent = "All fields are required.";
        toast("All fields are required.");
        return;
      }

      try {
        if (typeof ALLOWED_DOMAIN === "string" && ALLOWED_DOMAIN) {
          const allowed = String(ALLOWED_DOMAIN).toLowerCase();
          if (!email.toLowerCase().endsWith("@" + allowed)) {
            const t = `Email must be @${allowed}`;
            if (msg) msg.textContent = t;
            toast(t);
            return;
          }
        }
      } catch {}

      const payload = {
        username,
        email,
        name,
        access: role,
        role,
        password: passwordRaw.startsWith("plain:") ? passwordRaw : `plain:${passwordRaw}`,
        overwrite: false
      };

      if (btn) { btn.disabled = true; btn.textContent = "Creating..."; }
      try {
        const r = await fetch(`${API}/create-user`, {
          method: "POST", headers: hdrs(), body: JSON.stringify(payload)
        });
        const j = await r.json();
        if (!j.ok) throw new Error(j.error || j.message || "create_failed");
        toast(j.message || "User created");
        modal.style.display = "none";
      } catch (e) {
        const em = (e && e.message) ? e.message : "Create failed";
        if (msg) msg.textContent = em;
        toast(em);
      } finally {
        if (btn) { btn.disabled = false; btn.textContent = "Create User"; }
      }
    };
  }

  function showSettingsPicker() {
    let m = document.getElementById("settingsPicker");
    if (!m) {
      m = document.createElement("div");
      m.id = "settingsPicker";
      Object.assign(m.style, {
        position: "fixed", inset: "0", background: "rgba(0,0,0,.55)",
        display: "flex", alignItems: "center", justifyContent: "center",
        zIndex: 3000
      });

      const card = document.createElement("div");
      Object.assign(card.style, {
        background: "#162338", color: "#fff", padding: "16px", borderRadius: "14px",
        width: "92%", maxWidth: "360px", border: "1px solid rgba(255,255,255,0.15)"
      });

      card.innerHTML = `
        <div style="font-weight:900;font-size:18px;margin-bottom:10px">Settings</div>
        <div style="display:flex;flex-direction:column;gap:8px">
          <button id="btnCreateUser" class="btn ok" type="button">Create New User</button>
        </div>
        <div style="text-align:right;margin-top:14px">
          <button id="btnCloseSettingsPicker" class="btn danger" type="button">Close</button>
        </div>
      `;

      m.appendChild(card);
      document.body.appendChild(m);

      document.getElementById("btnCloseSettingsPicker").onclick = () => { m.style.display = "none"; };
      document.getElementById("btnCreateUser").onclick = () => {
        m.style.display = "none";
        showSettingsModal();
      };
    }
    m.style.display = "flex";
  }

  // ------------ Init ------------
  window.DASH = { fetchInstances };

  fetchInstances().catch(err => {
    try { console.error(err); } catch {}
    toast("Failed to load instances");
    applyReadonlyUI();
  });

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => {
      try { ensureProfileDropdown(); } catch {}
      try { applyIdentityToExistingUI(); } catch {}
      try { applyReadonlyUI(); } catch {}
    }, { once: true });
  } else {
    try { ensureProfileDropdown(); } catch {}
    try { applyIdentityToExistingUI(); } catch {}
    try { applyReadonlyUI(); } catch {}
  }

  // --- Bulk IIS RESET helpers (unchanged UI/features) ---
  function __isSvcName(name){
    const n = String(name||"").toLowerCase();
    return n.includes("svc") || n.includes("service") || /(^|[-_\.])app(\d+)?($|[-_\.])/.test(n);
  }
  function __isWebName(name){
    const n = String(name||"").toLowerCase();
    return n.includes("web") || n.includes("iis") || n.includes("front");
  }

  async function __iisresetInstance(id){
    const r = await fetch(`${API}/services`, {
      method: "POST",
      headers: hdrs(),
      body: JSON.stringify({ instanceId: id, op: "iisreset" })
    });
    try { return await r.json(); } catch(e){ return { ok:false, error: "parse_failed" }; }
  }

  async function __iisResetGroup(env, role, kind){
    if (isRO()) { roNotice("IIS reset is not permitted for Readonly users."); return; }
    const list = (instancesInEnv(env)[role] || []);
    const picks = list.filter(x => {
      const nm = x.name || x.instanceName || "";
      return kind === "svc" ? __isSvcName(nm) : __isWebName(nm);
    });
    if (!picks.length) { toast(`No ${kind.toUpperCase()} servers found in ${role}`); return; }

    const base = role === "DM" ? "dm" : "ea";
    const btnSvc = document.getElementById(`${base}-iis-svc`);
    const btnWeb = document.getElementById(`${base}-iis-web`);
    const msgEl  = document.getElementById(`${base}-iis-msg`);
    if (btnSvc) btnSvc.disabled = true;
    if (btnWeb) btnWeb.disabled = true;
    if (btnSvc) btnSvc.classList.add("btn-disabled");
    if (btnWeb) btnWeb.classList.add("btn-disabled");
    if (msgEl)  msgEl.textContent = `IIS reset in progress on ${picks.length} ${kind.toUpperCase()}…`;
    try { toast(`IIS reset fan-out to ${role} ${kind.toUpperCase()} sent`); } catch {}

    let ok = 0, fail = 0;
    for (const p of picks) {
      try {
        const res = await __iisresetInstance(p.id);
        if (res && res.ok) ok++; else fail++;
      } catch { fail++; }
    }

    if (btnSvc) btnSvc.disabled = false;
    if (btnWeb) btnWeb.disabled = false;
    if (btnSvc) btnSvc.classList.remove("btn-disabled");
    if (btnWeb) btnWeb.classList.remove("btn-disabled");
    if (msgEl)  msgEl.textContent = `Completed • OK: ${ok}  Fail: ${fail}`;

    toast(`IIS reset on ${role} ${kind.toUpperCase()} • OK: ${ok}  Fail: ${fail}`);
  }

  function __ensureBulkIISButtons(env){
    const sets = [
      { role: "DM", idSvc: "dm-iis-svc", idWeb: "dm-iis-web", idMsg: "dm-iis-msg" },
      { role: "EA", idSvc: "ea-iis-svc", idWeb: "ea-iis-web", idMsg: "ea-iis-msg" },
    ];

    sets.forEach(({ role, idSvc, idWeb, idMsg }) => {
      const svcBtn = document.getElementById(idSvc);
      const webBtn = document.getElementById(idWeb);
      if (!svcBtn && !webBtn) return;

      let msg = document.getElementById(idMsg);
      if (!msg && svcBtn) {
        msg = document.createElement("span");
        msg.id = idMsg;
        msg.className = "mut";
        msg.style.marginLeft = "8px";
        svcBtn.insertAdjacentElement("afterend", msg);
      }

      if (svcBtn) svcBtn.onclick = () => __iisResetGroup(env, role, "svc", svcBtn);
      if (webBtn) webBtn.onclick = () => __iisResetGroup(env, role, "web", webBtn);
    });

    if (typeof isRO === "function" && isRO()) {
      ["#dm-iis-svc","#dm-iis-web","#ea-iis-svc","#ea-iis-web"].forEach(sel => {
        const b = document.querySelector(sel);
        if (b) { b.style.display = "none"; b.disabled = true; b.classList.add("btn-disabled"); }
      });
      const dmMsg = document.getElementById("dm-iis-msg"); if (dmMsg) dmMsg.textContent = "";
      const eaMsg = document.getElementById("ea-iis-msg"); if (eaMsg) eaMsg.textContent = "";
    }
  }

  try {
    const __origRenderEnv = renderEnv;
    renderEnv = function(env){
      const out = __origRenderEnv.apply(this, arguments);
      try { __ensureBulkIISButtons(env); } catch(e){}
      return out;
    };
  } catch(e){ /* renderEnv not defined yet */ }
})();
