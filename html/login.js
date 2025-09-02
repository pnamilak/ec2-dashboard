/* login.js — OTP + login flow with OVT storage */

const API_BASE = window.__API_BASE__;
let jwt  = localStorage.getItem("jwt") || "";
let ovt  = localStorage.getItem("ovt") || "";
let ovtexp = parseInt(localStorage.getItem("ovt_exp") || "0", 10) || 0;

async function api(path, method = "GET", body) {
  const headers = { "Content-Type": "application/json" };
  if (jwt) headers.Authorization = "Bearer " + jwt;
  if (!jwt && ovt && Date.now() < ovtexp) headers["X-OVT"] = ovt;

  const res = await fetch(API_BASE + path, {
    method,
    headers,
    body: body == null ? undefined : JSON.stringify(body),
  });
  const txt = await res.text();
  let data = {};
  try { data = txt ? JSON.parse(txt) : {}; } catch { data = { raw: txt }; }
  if (!res.ok || data.ok === false) throw new Error(data.error || data.message || ("HTTP " + res.status));
  return data;
}

const elEmail   = document.querySelector("#email");
const elOtp     = document.querySelector("#otp");
const btnReq    = document.querySelector("#btn-request-otp");
const btnVerify = document.querySelector("#btn-verify-otp");
const btnLogin  = document.querySelector("#btn-login");

btnReq?.addEventListener("click", async () => {
  const email = (elEmail?.value || "").trim();
  if (!email) return alert("Enter email");
  try {
    const r = await api("/request-otp", "POST", { email });
    if (r.code) alert(`OTP sent. Dev code: ${r.code}`);
  } catch (e) { alert(e.message || "Failed to request OTP"); }
});

btnVerify?.addEventListener("click", async () => {
  const email = (elEmail?.value || "").trim();
  const code  = (elOtp?.value   || "").trim();
  if (!email || !code) return alert("Enter email and OTP");
  try {
    const r = await api("/verify-otp", "POST", { email, code });
    ovt = r.ovt || "";
    ovtexp = r.ovt_exp || 0;
    if (!ovt) return alert("Verification failed (no token).");
    localStorage.setItem("ovt", ovt);
    localStorage.setItem("ovt_exp", String(ovtexp));
    alert("OTP verified. You can now Sign In.");
  } catch (e) { alert(e.message || "Failed to verify OTP"); }
});

btnLogin?.addEventListener("click", async () => {
  const email = (elEmail?.value || "").trim();
  const code  = (elOtp?.value   || "").trim();
  if (!email || !code) return alert("Enter email and OTP");
  try {
    const r = await api("/login", "POST", { email, code });
    jwt = r.token || "";
    if (!jwt) return alert("Login failed.");
    localStorage.setItem("jwt", jwt);
    window.location.href = "./";
  } catch (e) { alert("Login failed: " + (e.message || "unknown")); }
});
