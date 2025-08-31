(function(){
  const API = localStorage.getItem("api_base_url");
  const otpEmail = (localStorage.getItem("otp_email")||"").toLowerCase();

  const $ = (id)=>document.getElementById(id);
  const setMsg = (m)=>{ $("msg").textContent=m||""; };

  if(!API){ setMsg("missing_api_base_url"); return; }
  if(!otpEmail){ setMsg("missing_verified_otp"); return; }

  function http(path, method, obj){
    return fetch(API+path,{method,headers:{"content-type":"application/json"},body:JSON.stringify(obj||{})})
      .then(async r=>{ const d=await r.json().catch(()=>({})); if(!r.ok){ throw new Error((d && (d.error||d.message))||("http "+r.status)); } return d;});
  }

  window.doLogin = function(){
    const u=$("uName").value.trim();
    const p=$("uPass").value;
    setMsg("");
    if(!u||!p){ setMsg("missing_credentials"); return; }

    http("/login","POST",{username:u,password:p})
      .then(res=>{
        // Enforce OTP email match if user record includes email
        try{
          if(res.user && res.user.email){
            const got=(res.user.email||"").toLowerCase();
            if(got && got!==otpEmail){ throw new Error("otp_email_mismatch"); }
          }
        }catch(ex){ setMsg(ex.message||"otp_email_mismatch"); return; }

        localStorage.setItem("jwt", res.token);
        localStorage.setItem("role", res.role);
        localStorage.setItem("user", JSON.stringify(res.user||{username:u,role:res.role}));
        window.location.href="/";
      })
      .catch(e=> setMsg(e.message||"bad_credentials"));
  };

  $("uPass").addEventListener("keydown",(e)=>{ if(e.key==="Enter"){ window.doLogin(); }});
})();
