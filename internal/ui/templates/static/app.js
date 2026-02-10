// ShushTLS — Minimal JavaScript for API-backed form actions.
// This file is intentionally small. All business logic lives server-side.
// The UI works without JS (noscript blocks provide curl fallbacks).

(function () {
  "use strict";

  // --- Initialize form (/setup) ---

  const initForm = document.getElementById("init-form");
  const initResult = document.getElementById("init-result");

  if (initForm) {
    initForm.addEventListener("submit", async function (e) {
      e.preventDefault();

      const btn = document.getElementById("init-btn");
      btn.setAttribute("aria-busy", "true");
      btn.disabled = true;
      initResult.hidden = true;

      // Build request body from form fields, omitting empty values.
      const body = {};
      const org = document.getElementById("organization").value.trim();
      const cn = document.getElementById("common_name").value.trim();
      const years = document.getElementById("validity_years").value.trim();

      if (org) body.organization = org;
      if (cn) body.common_name = cn;
      if (years) body.validity_years = parseInt(years, 10);

      try {
        const resp = await fetch("/api/initialize", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: Object.keys(body).length > 0 ? JSON.stringify(body) : undefined,
        });

        const data = await resp.json();

        if (resp.ok) {
          initResult.innerHTML =
            '<p><strong>Success!</strong> ' + escapeHtml(data.message) + "</p>" +
            '<p>Redirecting to trust page&hellip;</p>';
          initResult.setAttribute("class", "");
          initResult.hidden = false;
          initForm.hidden = true;
          // Give the server a moment to activate HTTPS, then redirect.
          // HTTP is now in redirect mode, so this navigates via HTTPS.
          setTimeout(function () {
            window.location.href = "/trust";
          }, 1000);
        } else {
          showError(initResult, data.error || "Initialization failed.");
          btn.setAttribute("aria-busy", "false");
          btn.disabled = false;
        }
      } catch (err) {
        showError(initResult, "Network error: " + err.message);
        btn.setAttribute("aria-busy", "false");
        btn.disabled = false;
      }
    });
  }

  // --- Issue certificate form (/certificates) ---

  const issueForm = document.getElementById("issue-form");
  const issueResult = document.getElementById("issue-result");

  if (issueForm) {
    issueForm.addEventListener("submit", async function (e) {
      e.preventDefault();

      const btn = document.getElementById("issue-btn");
      btn.setAttribute("aria-busy", "true");
      btn.disabled = true;
      issueResult.hidden = true;

      const raw = document.getElementById("dns_names").value;
      const dnsNames = raw
        .split(",")
        .map(function (s) { return s.trim(); })
        .filter(function (s) { return s.length > 0; });

      if (dnsNames.length === 0) {
        showError(issueResult, "Enter at least one DNS name.");
        btn.setAttribute("aria-busy", "false");
        btn.disabled = false;
        return;
      }

      try {
        const resp = await fetch("/api/certificates", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ dns_names: dnsNames }),
        });

        const data = await resp.json();

        if (resp.ok) {
          window.location.reload();
          return;
        } else {
          showError(issueResult, data.error || "Certificate issuance failed.");
        }

        btn.setAttribute("aria-busy", "false");
        btn.disabled = false;
      } catch (err) {
        showError(issueResult, "Network error: " + err.message);
        btn.setAttribute("aria-busy", "false");
        btn.disabled = false;
      }
    });
  }

  // --- Auth enable form (/settings) ---

  const authEnableForm = document.getElementById("auth-enable-form");
  const authUpdateForm = document.getElementById("auth-update-form");
  const authDisableBtn = document.getElementById("auth-disable-btn");
  const authResult = document.getElementById("auth-result");

  function handleAuthEnable(e) {
    e.preventDefault();

    var btn = e.target.querySelector("button[type=submit]");
    btn.setAttribute("aria-busy", "true");
    btn.disabled = true;
    authResult.hidden = true;

    var username = document.getElementById("auth-username").value.trim();
    var password = document.getElementById("auth-password").value;

    fetch("/api/auth", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ enabled: true, username: username, password: password }),
    })
      .then(function (resp) { return resp.json().then(function (data) { return { ok: resp.ok, data: data }; }); })
      .then(function (result) {
        if (result.ok) {
          authResult.innerHTML = "<p><strong>Success!</strong> " + escapeHtml(result.data.message) + "</p>" +
            "<p>Reloading&hellip;</p>";
          authResult.setAttribute("class", "");
          authResult.hidden = false;
          setTimeout(function () { window.location.reload(); }, 1000);
        } else {
          showError(authResult, result.data.error || "Failed to enable auth.");
          btn.setAttribute("aria-busy", "false");
          btn.disabled = false;
        }
      })
      .catch(function (err) {
        showError(authResult, "Network error: " + err.message);
        btn.setAttribute("aria-busy", "false");
        btn.disabled = false;
      });
  }

  if (authEnableForm) {
    authEnableForm.addEventListener("submit", handleAuthEnable);
  }
  if (authUpdateForm) {
    authUpdateForm.addEventListener("submit", handleAuthEnable);
  }

  if (authDisableBtn) {
    authDisableBtn.addEventListener("click", function () {
      authDisableBtn.setAttribute("aria-busy", "true");
      authDisableBtn.disabled = true;
      authResult.hidden = true;

      fetch("/api/auth", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enabled: false }),
      })
        .then(function (resp) { return resp.json().then(function (data) { return { ok: resp.ok, data: data }; }); })
        .then(function (result) {
          if (result.ok) {
            authResult.innerHTML = "<p><strong>Success!</strong> " + escapeHtml(result.data.message) + "</p>" +
              "<p>Reloading&hellip;</p>";
            authResult.setAttribute("class", "");
            authResult.hidden = false;
            setTimeout(function () { window.location.reload(); }, 1000);
          } else {
            showError(authResult, result.data.error || "Failed to disable auth.");
            authDisableBtn.setAttribute("aria-busy", "false");
            authDisableBtn.disabled = false;
          }
        })
        .catch(function (err) {
          showError(authResult, "Network error: " + err.message);
          authDisableBtn.setAttribute("aria-busy", "false");
          authDisableBtn.disabled = false;
        });
    });
  }

  // --- Copy-to-clipboard buttons on <pre><code> blocks ---

  document.querySelectorAll("pre > code").forEach(function (code) {
    var pre = code.parentElement;
    var btn = document.createElement("button");
    btn.className = "copy-btn";
    var clipSvg = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>';
    var checkSvg = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>';
    btn.innerHTML = clipSvg;
    btn.title = "Copy to clipboard";
    btn.addEventListener("click", function () {
      var text = code.textContent;
      navigator.clipboard.writeText(text).then(function () {
        btn.innerHTML = checkSvg;
        btn.classList.add("copied");
        setTimeout(function () {
          btn.innerHTML = clipSvg;
          btn.classList.remove("copied");
        }, 1500);
      });
    });
    pre.appendChild(btn);
  });

  // --- Helpers ---

  function showError(el, msg) {
    el.innerHTML = "<p><strong>Error:</strong> " + escapeHtml(msg) + "</p>";
    el.setAttribute("class", "pico-color-red-500");
    el.hidden = false;
  }

  function escapeHtml(str) {
    var div = document.createElement("div");
    div.appendChild(document.createTextNode(str));
    return div.innerHTML;
  }
})();
