/* login.js — OTP + login flow with OVT storage (polished) */

const API_BASE = window.__API_BASE__;
let jwt    = localStorage.getItem("jwt") || "";
let ovt    = localStorage.getItem("ovt") || "";
let ovtExp = parseInt(localStorage.getItem("ovt_exp") || "0", 10) || 0;

async function api(path, method = "GET", body) {
  const headers = { "Content-Type": "application/json" };
  if (jwt) headers.Authorization = "Bearer " + jwt;
  // If we don't have a JWT yet but we DO have a valid OVT, include it
  if (!jwt && ovt && Date.now() < ovtExp) headers["X-OVT"] = ovt;

  const res = await fetch(API_BASE + path, {
    method,
    headers,
    body: body == null ? undefined : JSON.stringify(body),
  });
  const txt = await res.text();

  // Normalize any response into an object
  let data = {};
  try { data = txt ? JSON.parse(txt) : {}; } catch { data = { raw: txt }; }

  // The backend always returns 200 with { ok: false } for logical errors
  if (!res.ok || data.ok === false) {
    throw new Error(data.error || data.message || ("HTTP " + res.status));
  }
  return data;
}

// Elements
const elEmail   = document.querySelector("#email");
const elOtp     = document.querySelector("#otp");
const btnReq    = document.querySelector("#btn-request-otp");
const btnVerify = document.querySelector("#btn-verify-otp");
const btnLogin  = document.querySelector("#btn-login");

function disable(el, on) { if (el) el.disabled = !!on; }

// Request OTP
btnReq?.addEventListener("click", async () => {
  const email = (elEmail?.value || "").trim();
  if (!email) return alert("Enter your email.");
  try {
    disable(btnReq, true);
    const r = await api("/request-otp", "POST", { email });
    if (r.code) alert(`OTP sent. (Dev code: ${r.code})`);
    else alert("OTP sent to your email.");
  } catch (e) {
    alert(e.message || "Failed to request OTP");
  } finally {
    disable(btnReq, false);
  }
});

// Verify OTP → obtain OVT
btnVerify?.addEventListener("click", async () => {
  const email = (elEmail?.value || "").trim();
  const code  = (elOtp?.value   || "").trim();
  if (!email || !code) return alert("Enter email and OTP.");
  try {
    disable(btnVerify, true);
    const r = await api("/verify-otp", "POST", { email, code });
    ovt    = r.ovt || "";
    ovtExp = r.ovt_exp || 0;
    if (!ovt) return alert("Verification failed.");
    localStorage.setItem("ovt", ovt);
    localStorage.setItem("ovt_exp", String(ovtExp));
    alert("OTP verified. You can now Sign In.");
  } catch (e) {
    alert(e.message || "Failed to verify OTP");
  } finally {
    disable(btnVerify, false);
  }
});

// Login (still OTP mode)
btnLogin?.addEventListener("click", async () => {
  const email = (elEmail?.value || "").trim();
  const code  = (elOtp?.value   || "").trim();
  if (!email || !code) return alert("Enter email and OTP.");
  try {
    disable(btnLogin, true);
    const r = await api("/login", "POST", { email, code });
    jwt = r.token || "";
    if (!jwt) return alert("Login failed.");
    localStorage.setItem("jwt", jwt);
    // go to dashboard
    window.location.href = "./";
  } catch (e) {
    alert("Login failed: " + (e.message || "unknown"));
  } finally {
    disable(btnLogin, false);
  }
});

// Optional: Enter key submits “verify” then “login”
[elEmail, elOtp].forEach(el => el?.addEventListener("keydown", (ev) => {
  if (ev.key === "Enter") btnLogin?.click();
}));
