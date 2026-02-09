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
          issueResult.innerHTML =
            "<p><strong>Certificate issued!</strong> " +
            "Primary SAN: <code>" + escapeHtml(data.certificate.primary_san) + "</code></p>" +
            "<p>Reload the page to see it in the table.</p>";
          issueResult.setAttribute("class", "");
          issueResult.hidden = false;
          document.getElementById("dns_names").value = "";
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
