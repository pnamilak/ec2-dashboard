// html/login.js
(function () {
  // API base URL is saved by index.html.tpl
  const API = localStorage.getItem("api_base_url");

  // Read OTP from either sessionStorage (preferred) or localStorage (fallback)
  const otpEmail = (
    sessionStorage.getItem("otp_email") ||
    localStorage.getItem("otp_email") ||
    ""
  ).toLowerCase();

  const $ = (id) => document.getElementById(id);
  const setMsg = (m) => { $("msg").textContent = m || ""; };

  if (!API) {
    setMsg("missing_api_base_url");
    return;
  }

  // If the OTP token isn't present, immediately send the user to the OTP page
  if (!otpEmail) {
    setMsg("missing_verified_otp");
    // Give a tiny moment so the user sees *why*, then redirect to OTP
    setTimeout(() => { window.location.replace("/"); }, 600);
    return;
  }

  function http(path, method, obj) {
    return fetch(API + path, {
      method,
      headers: { "content-type": "application/json" },
      body: JSON.stringify(obj || {}),
    }).then(async (r) => {
      const d = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error((d && (d.error || d.message)) || ("http " + r.status));
      return d;
    });
  }

  window.doLogin = function () {
    const u = $("uName").value.trim();
    const p = $("uPass").value;

    setMsg("");
    if (!u || !p) { setMsg("missing_credentials"); return; }

    http("/login", "POST", { username: u, password: p })
      .then((res) => {
        // Enforce OTP/email match if backend provides an email
        try {
          const serverEmail = ((res.user && res.user.email) || "").toLowerCase();
          if (serverEmail && serverEmail !== otpEmail) {
            throw new Error("otp_email_mismatch");
          }
        } catch (ex) {
          setMsg(ex.message || "otp_email_mismatch");
          return;
        }

        localStorage.setItem("jwt", res.token);
        localStorage.setItem("role", res.role);
        localStorage.setItem("user", JSON.stringify(res.user || { username: u, role: res.role }));

        // success → dashboard
        window.location.href = "/";
      })
      .catch((e) => setMsg(e.message || "bad_credentials"));
  };

  $("uPass").addEventListener("keydown", (e) => {
    if (e.key === "Enter") window.doLogin();
  });
})();
