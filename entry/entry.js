(function(){
  const API = window.API_URL;
  const $ = (id)=>document.getElementById(id);
  let jwt = "";

  $('send').onclick = async ()=>{
    const email = $('email').value.trim().toLowerCase();
    $('err').style.display='none'; $('msg').textContent='';
    if (!email || !email.endsWith('@'+window.ALLOWED_DOMAIN)) {
      $('err').style.display='block'; $('err').textContent='Only @'+window.ALLOWED_DOMAIN+' emails are allowed.'; return;
    }
    try{
      await fetch(API + '/auth/request-otp', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({email})});
      $('msg').textContent = 'OTP sent. Check your inbox.'; $('otpBox').style.display='block';
    }catch(e){ $('err').style.display='block'; $('err').textContent='Failed to send OTP.'; }
  };

  $('verify').onclick = async ()=>{
    const email = $('email').value.trim().toLowerCase();
    const otp   = $('otp').value.trim();
    $('err').style.display='none';
    try{
      const res = await fetch(API + '/auth/verify', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({email, otp})});
      if(!res.ok) throw new Error(await res.text());
      const j = await res.json(); jwt = j.token;

      const ad = await fetch(API + '/auth/access-details', {method:'POST', headers:{'Authorization':'Bearer '+jwt}});
      if(!ad.ok){ const txt=await ad.text(); throw new Error(txt); }
      const d = await ad.json();
      $('access').style.display='block';
      $('dashUrl').textContent  = d.dashboard_url;
      $('dashUser').textContent = d.user;
      $('dashPass').textContent = d.password;
    }catch(e){
      $('err').style.display='block';
      $('err').textContent = 'Access denied or invalid OTP.';
    }
  };
})();
