// ----- API base URL -----
// Prefer the value seeded by index.html.tpl:
let API_BASE = (localStorage.getItem("api_base_url") || "").trim();

// If you want to hard-set it, uncomment and paste your URL:
// API_BASE = "https://YOUR_API_ID.execute-api.us-east-2.amazonaws.com";        // for $default stage
// API_BASE = "https://YOUR_API_ID.execute-api.us-east-2.amazonaws.com/prod";   // for named stage

function normalize(u){ return /^https?:\/\//i.test(u) ? u.replace(/\/+$/,"") : ""; }
API_BASE = normalize(API_BASE);
// ------------------------

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

function showErr(status, text) {
  const looksHtml = /<\s*html|<\s*!doctype/i.test(text || "");
  if (!API_BASE) errorEl.textContent = "API base URL missing. Seeded by index.html.tpl or hardcode in login.js.";
  else if (status === 403 && looksHtml) errorEl.textContent = "CORS/CloudFront 403 (your request hit the static site). Fix API_BASE to the API Gateway URL.";
  else errorEl.textContent = (text && text.slice(0,300)) || `Login failed (${status || "network"})`;
}

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  errorEl.textContent = "";

  const username = document.getElementById("username").value.trim();
  const password = document.getElementById("password").value;
  if (!username || !password) { errorEl.textContent = "Please enter both username and password."; return; }
  if (!API_BASE) { showErr(null, "no-api"); return; }

  try {
    const resp = await fetch(`${API_BASE}/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      // DO NOT use credentials: "include" → keeps CORS simple
      body: JSON.stringify({ username, password }),
    });

    const raw = await resp.text();
    if (!resp.ok) { showErr(resp.status, raw); return; }

    const data = JSON.parse(raw || "{}");
    if (data?.token) localStorage.setItem("jwt", data.token);
    if (data?.role)  localStorage.setItem("role", data.role);
    if (data?.user)  localStorage.setItem("user", JSON.stringify(data.user));

    // Back to dashboard (authed UI will render)
    window.location.href = "./";
  } catch (err) {
    showErr(null, String(err && err.message || err));
  }
});
