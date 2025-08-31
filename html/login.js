(function () {
  const API = localStorage.getItem("api_base_url") || "";
  const u = document.getElementById("u");
  const p = document.getElementById("p");
  const btn = document.getElementById("btn");
  const msg = document.getElementById("msg");

  function setMsg(t, cls) { msg.className = "msg " + (cls || ""); msg.textContent = t || ""; }

  function ensureOtpInSession() {
    const token = sessionStorage.getItem("otp_token");
    const email = sessionStorage.getItem("otp_email");
    const ts    = Number(sessionStorage.getItem("otp_ts") || 0);
    if (token && email && ts) return true;
    try {
      const raw = localStorage.getItem("otp_bundle");
      if (!raw) return false;
      const { t, e, ts:lsTs } = JSON.parse(raw);
      if (!t || !e || !lsTs) return false;
      if ((Math.floor(Date.now()/1000) - Number(lsTs)) > 600) return false;
      sessionStorage.setItem("otp_token", t);
      sessionStorage.setItem("otp_email", e);
      sessionStorage.setItem("otp_ts", String(lsTs));
      return true;
    } catch { return false; }
  }
  function needOtp() { return !ensureOtpInSession(); }

  async function post(path, body) {
    const r = await fetch(API + path, {
      method:'POST',
      headers:{'content-type':'application/json'},
      body: JSON.stringify(body||{})
    });
    const data = await r.json().catch(()=> ({}));
    if (!r.ok) throw new Error(data.error || data.message || ('http_'+r.status));
    return data;
  }

  btn && (btn.onclick = async () => {
    setMsg("");

    if (needOtp()) { setMsg("missing_verified_otp", "err"); return; }

    const username = (u.value||"").trim();
    const password = p.value||"";
    if (!username || !password) { setMsg("bad_credentials", "err"); return; }

    try {
      btn.disabled = true;

      const otp_token = sessionStorage.getItem("otp_token");
      const otp_email = sessionStorage.getItem("otp_email");

      const res = await post("/login", { username, password, otp_token, otp_email });

      localStorage.setItem("jwt", res.token);
      localStorage.setItem("role", res.role||"read");
      localStorage.setItem("user", JSON.stringify(res.user||{}));

      // Clean up both storages
      sessionStorage.removeItem("otp_token");
      sessionStorage.removeItem("otp_email");
      sessionStorage.removeItem("otp_ts");
      localStorage.removeItem("otp_bundle");

      location.href = "/";
    } catch (e) {
      setMsg(e.message || "login_failed", "err");
    } finally {
      btn.disabled = false;
    }
  });
})();
