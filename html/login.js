(function(){
  const api = (localStorage.getItem("api_base_url") || "").trim();
  const msg = (t)=> { document.getElementById("msg").textContent = t || ""; };

  // Require a verified OTP email
  const otpEmail = (localStorage.getItem("otp_email") || "").trim().toLowerCase();
  if(!otpEmail){
    msg("missing_verified_otp");
  }

  window.doLogin = function(){
    msg("");
    const u = document.getElementById("u").value.trim();
    const p = document.getElementById("p").value;
    if(!u || !p){ msg("missing_credentials"); return; }
    if(!api){ msg("api_unset"); return; }
    if(!otpEmail){ msg("missing_verified_otp"); return; }

    fetch(api + "/login", {
      method: "POST",
      headers: {"content-type":"application/json"},
      body: JSON.stringify({username:u, password:p, otp_email: otpEmail})
    }).then(async r => {
      const data = await r.json().catch(()=> ({}));
      if(!r.ok) throw new Error((data && (data.error||data.message)) || ("http "+r.status));
      return data;
    }).then(res => {
      localStorage.setItem("jwt",  res.token);
      localStorage.setItem("role", res.role);
      localStorage.setItem("user", JSON.stringify(res.user));
      // harden: remove OTP email now that we’re signed in
      localStorage.removeItem("otp_email");
      window.location.href = "/";
    }).catch(e => msg(e.message));
  };

  document.getElementById("p").addEventListener("keydown", e => { if(e.key==="Enter"){ doLogin(); } });
})();
