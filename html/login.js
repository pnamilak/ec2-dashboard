// ----- REQUIRED: set your API Gateway base URL (with stage) -----
// Example: "https://abc123.execute-api.us-east-2.amazonaws.com/prod"
let API_BASE = (localStorage.getItem("api_base_url") || "").trim();
// If localStorage isn't set correctly, hardcode it below:
// API_BASE = "https://YOUR_API_ID.execute-api.us-east-2.amazonaws.com/prod";
// ---------------------------------------------------------------

function normalizeBase(u){ return /^https?:\/\//i.test(u) ? u.replace(/\/+$/,"") : ""; }
API_BASE = normalizeBase(API_BASE);

const OTP_FLAG_KEY = "otp_verified_until";
const allowedDomain = localStorage.getItem("allowed_domain");

// Show domain hint
const domainHintEl = document.getElementById("domain-hint");
if (allowedDomain && domainHintEl) domainHintEl.textContent = `Only users from ${allowedDomain} can sign in.`;

// Require recent OTP
(function enforceOtpGate() {
  try {
    const until = parseInt(localStorage.getItem(OTP_FLAG_KEY) || "0", 10);
    if (!until || Date.now() > until) window.location.replace("./");
  } catch { window.location.replace("./"); }
})();

const form = document.getElementById("login-form");
const errorEl = document.getElementById("error");
function niceError(status, text) {
  const looksHtml = /<\s*html|<\s*!doctype/i.test(text || "");
  if (!API_BASE) errorEl.textContent = "API URL missing. Either index.html.tpl must set api_base_url or hardcode API_BASE in login.js.";
  else if (status === 403 && looksHtml) errorEl.textContent = "Got 403 HTML from CloudFront → your request hit the static site. Fix API_BASE to your API Gateway URL.";
  else errorEl.textContent = (text && text.slice(0,300)) || `Login failed (${status || "network"})`;
}

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  errorEl.textContent = "";
  const username = document.getElementById("username").value.trim();
  const password = document.getElementById("password").value;
  if (!username || !password) { errorEl.textContent = "Please enter both username and password."; return; }
  if (!API_BASE) { niceError(null, "no-api"); return; }
  try {
    const resp = await fetch(`${API_BASE}/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({ username, password }),
    });
    const raw = await resp.text();
    if (!resp.ok) { niceError(resp.status, raw); return; }
    const data = JSON.parse(raw || "{}");
    if (data?.token) localStorage.setItem("jwt", data.token);
    if (data?.role)  localStorage.setItem("role", data.role);
    if (data?.user)  localStorage.setItem("user", JSON.stringify(data.user));
    window.location.href = "./";
  } catch (err) {
    niceError(null, String(err && err.message || err));
  }
});
