(function(){
  const API = localStorage.getItem("api_base_url") || "";

  const qs = new URLSearchParams(location.search);
  const fromQS = (qs.get("e")||"").trim().toLowerCase();
  let otpEmail = fromQS || (sessionStorage.getItem("otp_email")||"").toLowerCase() || (localStorage.getItem("otp_email")||"").toLowerCase();
  if(fromQS){
    try { sessionStorage.setItem("otp_email", fromQS); localStorage.setItem("otp_email", fromQS); } catch(_) {}
  }

  if(!otpEmail){
    const m=document.getElementById("msg"); if(m) m.textContent="missing_verified_otp";
  }

  function http(path, method, obj){
    return fetch(API+path,{
      method,
      headers:{"content-type":"application/json"},
      body:JSON.stringify(obj||{})
    }).then(async r=>{
      const data = await r.json().catch(()=> ({}));
      if(!r.ok){ throw new Error((data && (data.error||data.message)) || ("http "+r.status)); }
      return data;
    });
  }

  window.signin = function(){
    const u=document.getElementById("u").value.trim();
    const p=document.getElementById("p").value;
    const msg=document.getElementById("msg");
    msg.textContent = "";

    if(!otpEmail){ msg.textContent="missing_verified_otp"; return; }

    http("/login","POST",{username:u,password:p,otp_email:otpEmail})
      .then(r=>{
        try{
          localStorage.setItem("jwt",r.jwt);
          localStorage.setItem("role",r.role||"");
          localStorage.setItem("user",JSON.stringify({username:u,role:r.role||"",name:r.name||""}));
        }catch(_){}
        location.href="/";
      })
      .catch(e=>{ msg.textContent=e.message||"invalid_password"; });
  };
})();
