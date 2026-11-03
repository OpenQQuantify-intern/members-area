"use strict";

(async () => {
  const root = document.querySelector("[data-recovery-reset]");
  if (!root) return;
  const form = document.getElementById("reset-password-form");
  const tokenInput = form.querySelector('input[name="token"]');
  const csrfInput = form.querySelector('input[name="csrf_token"]');
  const status = document.getElementById("reset-link-status");
  const error = document.getElementById("reset-link-error");
  const newLink = document.getElementById("reset-new-link");
  const fragmentToken = new URLSearchParams(window.location.hash.slice(1)).get("token");

  // Remove the secret from browser history before making any network request.
  if (window.location.hash) {
    window.history.replaceState(null, "", window.location.pathname);
  }
  if (root.dataset.ready === "true" && !fragmentToken) return;

  function rejectLink(message) {
    tokenInput.value = "";
    form.hidden = true;
    status.hidden = true;
    error.textContent = message;
    error.hidden = false;
    newLink.hidden = false;
  }

  if (!fragmentToken || !/^[A-Za-z0-9_-]{43}$/.test(fragmentToken)) {
    rejectLink("This link is invalid or has expired. Please request a new one.");
    return;
  }
  tokenInput.value = fragmentToken;
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), 10000);
  try {
    const response = await fetch(root.dataset.checkUrl, {
      method: "POST",
      credentials: "same-origin",
      headers: {"X-CSRFToken": csrfInput.value},
      body: new URLSearchParams({token: fragmentToken}),
      signal: controller.signal,
    });
    const result = await response.json();
    if (!response.ok || result.valid !== true) {
      rejectLink(result.message || "This link could not be verified. Please request a new one.");
      return;
    }
    status.hidden = true;
    error.hidden = true;
    newLink.hidden = true;
    form.hidden = false;
    form.querySelector('input[name="new_password"]').focus();
  } catch {
    rejectLink("We couldn’t verify this link. Reopen it from your email and try again.");
  } finally {
    window.clearTimeout(timeout);
  }
})();
