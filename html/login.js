// If you templated API into localStorage from index.html.tpl, this picks it up:
const API_BASE = localStorage.getItem("api_base_url") || ""; 
// Or hardcode: const API_BASE = "https://YOURID.execute-api.us-east-2.amazonaws.com";

const OTP_FLAG_KEY = "otp_verified_until";
const allowedDomain = localStorage.getItem("allowed_domain");

// Hint
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

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  errorEl.textContent = "";

  const username = document.getElementById("username").value.trim();
  const password = document.getElementById("password").value;

  if (!username || !password) { errorEl.textContent = "Please enter both username and password."; return; }

  try {
    const resp = await fetch(`${API_BASE}/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({ username, password }),
    });
    if (!resp.ok) throw new Error((await resp.text()) || `Login failed (${resp.status})`);

    const data = await resp.json();
    if (data?.token) localStorage.setItem("jwt", data.token);
    if (data?.role)  localStorage.setItem("role", data.role);
    if (data?.user)  localStorage.setItem("user", JSON.stringify(data.user));

    // Back to dashboard
    window.location.href = "./";
  } catch (err) {
    errorEl.textContent = err?.message || "Something went wrong. Please try again.";
  }
});
