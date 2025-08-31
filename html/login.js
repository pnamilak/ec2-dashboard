(function () {
  const API = localStorage.getItem("api_base_url") || "";
  const u = document.getElementById("u");
  const p = document.getElementById("p");
  const btn = document.getElementById("btn");
  const msg = document.getElementById("msg");

  function setMsg(t, cls) { msg.className = "msg " + (cls || ""); msg.textContent = t || ""; }

  function needOtp() {
    const token = sessionStorage.getItem("otp_token");
    const email = sessionStorage.getItem("otp_email");
    const ts    = Number(sessionStorage.getItem("otp_ts") || 0);
    if (!token || !email) return true;
    // Optional: 10-min freshness window
    if (ts && (Math.floor(Date.now()/1000) - ts) > 600) return true;
    return false;
  }

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

  btn.onclick = async () => {
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

      // Save JWT for the app and go home
      localStorage.setItem("jwt", res.token);
      localStorage.setItem("role", res.role||"read");
      localStorage.setItem("user", JSON.stringify(res.user||{}));

      // OTP is single-use; clear to force new OTP next time
      sessionStorage.removeItem("otp_token");
      sessionStorage.removeItem("otp_email");
      sessionStorage.removeItem("otp_ts");

      location.href = "/";
    } catch (e) {
      setMsg(e.message || "login_failed", "err");
    } finally {
      btn.disabled = false;
    }
  };
})();
