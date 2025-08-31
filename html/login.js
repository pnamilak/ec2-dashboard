(function () {
  function $(id) { return document.getElementById(id); }
  function setMsg(m){ $("msg").textContent = m || ""; }

  function http(path, method, obj){
    const API = localStorage.getItem("api_base_url") || (function(){
      // Allow embedding API base once from index.tpl:
      try { return "${api_base_url}"; } catch(_){ return ""; }
    })();
    return fetch(API + path, {method, headers:{"content-type":"application/json"}, body: obj? JSON.stringify(obj): undefined})
      .then(async r=>{
        const data = await r.json().catch(()=> ({}));
        if(!r.ok){ throw new Error((data && (data.error||data.message)) || ("http "+r.status)); }
        return data;
      });
  }

  window.doLogin = function(){
    const u = $("uName").value.trim();
    const p = $("uPass").value;
    const otp = sessionStorage.getItem("otp_token") || "";
    setMsg("");
    if(!u || !p){ setMsg("missing_credentials"); return; }
    if(!otp){ setMsg("missing_verified_otp"); return; }

    http("/login","POST",{username:u,password:p,otp})
      .then(res=>{
        try {
          localStorage.setItem("jwt", res.token);
          localStorage.setItem("role", res.role);
          localStorage.setItem("user", JSON.stringify(res.user || {username:u,role:res.role}));
        } catch(_){}
        try { sessionStorage.removeItem("otp_token"); } catch(_){}
        window.location.href = "/";
      })
      .catch(e=> setMsg(e.message || "bad_credentials"));
  };

  $("uPass").addEventListener("keydown", function(e){ if(e.key==="Enter"){ doLogin(); } });

  // Proactive error if page was opened without OTP step
  if(!sessionStorage.getItem("otp_token")){
    setMsg("missing_verified_otp");
  }
})();
