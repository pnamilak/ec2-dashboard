// ---- config ----
const API_BASE = "YOUR_API_BASE_URL";   // e.g., https://d5h54xay1m.execute-api.us-east-2.amazonaws.com
const OTP_FLAG_KEY = "otp_verified_until";     // set by OTP page on success
const OTP_GRACE_MS = 10 * 60 * 1000;           // 10 min grace after OTP verify

// Show domain hint if OTP page stored it
const allowedDomain = localStorage.getItem("allowed_domain");
const domainHintEl = document.getElementById("domain-hint");
if (allowedDomain && domainHintEl) {
  domainHintEl.textContent = `Only users from ${allowedDomain} can sign in.`;
}

// Enforce that OTP happened recently
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

  if (!username || !password) {
    errorEl.textContent = "Please enter both username and password.";
    return;
  }

  try {
    const resp = await fetch(`${API_BASE}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({ username, password }),
    });

    if (!resp.ok) throw new Error((await resp.text()) || `Login failed (${resp.status})`);
    const data = await resp.json();

    // Save token/role for protected calls
    if (data?.token) localStorage.setItem("ec2dash_token", data.token);
    if (data?.role) localStorage.setItem("ec2dash_role", data.role);

    // Go to dashboard
    window.location.href = "./dashboard.html";
  } catch (err) {
    errorEl.textContent = err?.message || "Something went wrong. Please try again.";
  }
});
