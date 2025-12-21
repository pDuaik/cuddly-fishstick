// /script.js
(() => {
  "use strict";

  // ------------------------------------------------------------
  // Runtime config (public, no secrets)
  // ------------------------------------------------------------
  const DEFAULTS = {
    runtimeJsonPath: "/config/runtime.json", // served as no-store by CloudFront behaviour

    // Cookies/headers used by your backend
    csrfCookieName: "__Host-csrf",
    csrfHeaderName: "X-CSRF-Token",

    // Routes (can be overridden by runtime.json)
    mePath: "/api/me",
    authStartPath: "/auth/start",
    logoutPath: "/auth/logout",

    // Demo endpoint (must be implemented server-side)
    csrfDemoPath: "/api/demo/csrf",

    // Where to send users after login
    postLoginPath: "/app/protected.html",
  };

  let CFG = { ...DEFAULTS };

  // ------------------------------------------------------------
  // Helpers
  // ------------------------------------------------------------
  function $(id) {
    return document.getElementById(id);
  }

  function setText(id, text) {
    const el = $(id);
    if (!el) return;
    el.textContent = typeof text === "string" ? text : String(text ?? "");
  }

  function safeRedirect(path) {
    // Only allow same-origin relative paths that start with /
    if (typeof path !== "string") return;
    if (!path.startsWith("/")) return;
    if (path.startsWith("//")) return; // blocks protocol-relative
    if (path.toLowerCase().startsWith("/javascript:")) return;

    window.location.assign(path);
  }

  function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return (parts.pop() || "").split(";").shift() || "";
    return "";
  }

  async function safeJson(res) {
    try {
      return await res.json();
    } catch {
      return null;
    }
  }

  async function fetchRuntimeConfig() {
    // Optional: if runtime.json not present, we keep defaults.
    try {
      const res = await fetch(DEFAULTS.runtimeJsonPath, { cache: "no-store" });
      if (!res.ok) return;

      const data = await res.json();
      if (!data || typeof data !== "object") return;

      // Only allow known keys to prevent surprises
      const next = { ...CFG };

      if (typeof data.mePath === "string") next.mePath = data.mePath;
      if (typeof data.authStartPath === "string") next.authStartPath = data.authStartPath;
      if (typeof data.logoutPath === "string") next.logoutPath = data.logoutPath;
      if (typeof data.csrfDemoPath === "string") next.csrfDemoPath = data.csrfDemoPath;
      if (typeof data.postLoginPath === "string") next.postLoginPath = data.postLoginPath;

      if (typeof data.csrfCookieName === "string") next.csrfCookieName = data.csrfCookieName;
      if (typeof data.csrfHeaderName === "string") next.csrfHeaderName = data.csrfHeaderName;

      CFG = next;
    } catch {
      // ignore, keep defaults
    }
  }

  function normalizeSameOriginPath(p, fallback) {
    const s = String(p ?? "").trim();
    if (!s) return fallback;
    // Keep the same-origin rule: must be relative path starting with /
    if (!s.startsWith("/")) return fallback;
    if (s.startsWith("//")) return fallback;
    if (s.toLowerCase().startsWith("/javascript:")) return fallback;
    return s;
  }

  function toPretty(obj) {
    try {
      return JSON.stringify(obj, null, 2);
    } catch {
      return String(obj);
    }
  }

  // ------------------------------------------------------------
  // Index: login button
  // Expects: id="loginBtn" (can be <a> or <button>)
  // ------------------------------------------------------------
  async function handleLoginClick(e) {
    if (e?.preventDefault) e.preventDefault();

    const postLogin = normalizeSameOriginPath(CFG.postLoginPath, DEFAULTS.postLoginPath);

    // If already logged in, go straight to app.
    try {
      const res = await fetch(CFG.mePath, {
        method: "GET",
        credentials: "include",
        cache: "no-store",
      });
      if (res.ok) {
        safeRedirect(postLogin);
        return;
      }
    } catch {
      // ignore
    }

    // Start OAuth flow (server sets state + pkce cookies and redirects to Hosted UI)
    safeRedirect(CFG.authStartPath + "?next=" + encodeURIComponent(postLogin));
  }

  function wireIndexLoginButton() {
    const btn = $("loginBtn");
    if (!btn) return;

    // If it's an <a href="/auth/start"> you still want JS to run first.
    btn.addEventListener("click", handleLoginClick);
  }

  // ------------------------------------------------------------
  // Protected page demo: GET /api/me
  // Expects: id="meBtn" and optional id="output"
  // ------------------------------------------------------------
  async function callMe() {
    setText("output", "Calling /api/me ...");

    try {
      const res = await fetch(CFG.mePath, {
        method: "GET",
        credentials: "include",
        cache: "no-store",
      });

      const body = await safeJson(res);
      if (res.ok) {
        setText("output", toPretty(body ?? { ok: true }));
        return;
      }

      // If session missing/expired, send user back to login
      if (res.status === 401 || res.status === 403) {
        setText("output", `Not authenticated (HTTP ${res.status}). Redirecting to login...`);
        safeRedirect("/");
        return;
      }

      setText(
        "output",
        `Failed (HTTP ${res.status})\n` + toPretty(body ?? { message: "Unknown error" }),
      );
    } catch {
      setText("output", "Network error calling /api/me");
    }
  }

  function wireMeButton() {
    const btn = $("meBtn");
    if (!btn) return;
    btn.addEventListener("click", (e) => {
      if (e?.preventDefault) e.preventDefault();
      callMe();
    });
  }

  // ------------------------------------------------------------
  // Protected page demo: POST /api/demo/csrf (increments demo_counter)
  // Expects: id="csrfBtn" and optional id="output"
  // ------------------------------------------------------------
  async function callCsrfDemo() {
    setText("output", "Calling CSRF demo POST ...");

    const csrfCookieName = CFG.csrfCookieName || DEFAULTS.csrfCookieName;
    const csrfHeaderName = CFG.csrfHeaderName || DEFAULTS.csrfHeaderName;

    const csrf = getCookie(csrfCookieName);

    // If cookie is readable but missing, fail loudly (helps debug)
    if (!csrf) {
      setText(
        "output",
        `Missing CSRF cookie "${csrfCookieName}". Try refreshing the page, or re-login.`,
      );
      return;
    }

    const headers = { "Content-Type": "application/json" };
    headers[csrfHeaderName] = csrf;

    try {
      const res = await fetch(CFG.csrfDemoPath, {
        method: "POST",
        credentials: "include",
        cache: "no-store",
        headers,
        body: JSON.stringify({ action: "increment" }),
      });

      const body = await safeJson(res);

      if (res.ok) {
        setText("output", toPretty(body ?? { ok: true }));
        return;
      }

      // If session missing/expired, send user back to login
      if (res.status === 401 || res.status === 403) {
        setText("output", `Not authenticated (HTTP ${res.status}). Redirecting to login...`);
        safeRedirect("/");
        return;
      }

      setText(
        "output",
        `Failed (HTTP ${res.status})\n` + toPretty(body ?? { message: "Unknown error" }),
      );
    } catch {
      setText("output", "Network error calling CSRF demo endpoint");
    }
  }

  function wireCsrfButton() {
    const btn = $("csrfBtn");
    if (!btn) return;
    btn.addEventListener("click", (e) => {
      if (e?.preventDefault) e.preventDefault();
      callCsrfDemo();
    });
  }

  // ------------------------------------------------------------
  // logout button wiring (if you prefer JS redirect)
  // If you use a normal <a href="/auth/logout">Logout</a> you don't need this.
  // Expects: id="logoutBtn"
  // ------------------------------------------------------------
  function wireLogoutButton() {
    const btn = $("logoutBtn");
    if (!btn) return;
    btn.addEventListener("click", (e) => {
      if (e?.preventDefault) e.preventDefault();
      safeRedirect(CFG.logoutPath || DEFAULTS.logoutPath);
    });
  }

  // ------------------------------------------------------------
  // Init
  // ------------------------------------------------------------
  (async () => {
    await fetchRuntimeConfig();

    // Wire buttons if present on this page
    wireIndexLoginButton();
    wireMeButton();
    wireCsrfButton();
    wireLogoutButton();

    // Optional debug (remove later)
    window.__poc = {
      cfg: () => ({ ...CFG }),
      getCookie,
      callMe,
      callCsrfDemo,
    };
  })();
})();
