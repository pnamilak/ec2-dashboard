// --- Resolve API base ---
// Primary source: index.html.tpl seeds it → localStorage.setItem("api_base_url", API)
let API_BASE = (localStorage.getItem("api_base_url") || "").trim();

// OPTIONAL hard override: uncomment and set your API Gateway endpoint if needed:
// API_BASE = "https://YOURID.execute-api.us-east-2.amazonaws.com";

function normalizeBase(u) {
  if (!u) return "";
  if (!/^https?:\/\//i.test(u) || u.includes("${api_base_url}")) return "";
  return u.replace(/\/+$/,"");
}
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

function showNiceError(status, text) {
  const looksHtml = /<\s*html|<\s*!doctype/i.test(text || "");
  if (status === 403 && looksHtml) {
    errorEl.textContent = "403 from CloudFront: your login request is hitting the site domain.\nFix: set API_BASE to your API Gateway endpoint.";
  } else if (!API_BASE) {
    errorEl.textContent = "API base URL is not set. Ensure index.html.tpl saves it (api_base_url), or hardcode it in login.js.";
  } else {
    errorEl.textContent = (text && text.slice(0,300)) || `Login failed (${status || "network"})`;
  }
}

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  errorEl.textContent = "";

  const username = document.getElementById("username").value.trim();
  const password = document.getElementById("password").value;

  if (!username || !password) { errorEl.textContent = "Please enter both username and password."; return; }
  if (!API_BASE) { showNiceError(null, "no-api"); return; }

  try {
    const resp = await fetch(`${API_BASE}/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({ username, password }),
    });

    const raw = await resp.text();
    if (!resp.ok) { showNiceError(resp.status, raw); return; }

    const data = JSON.parse(raw || "{}");
    if (data?.token) localStorage.setItem("jwt", data.token);
    if (data?.role)  localStorage.setItem("role", data.role);
    if (data?.user)  localStorage.setItem("user", JSON.stringify(data.user));

    // Back to dashboard
    window.location.href = "./";
  } catch (err) {
    showNiceError(null, String(err && err.message || err));
  }
});
