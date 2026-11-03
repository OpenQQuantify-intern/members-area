"use strict";

// Progressive enhancement: forms still work when JavaScript is unavailable.
document.querySelectorAll("[data-toggle-password]").forEach((button) => {
  button.addEventListener("click", () => {
    const input = document.getElementById(button.dataset.togglePassword);
    if (!input) return;
    const show = input.type === "password";
    input.type = show ? "text" : "password";
    button.textContent = show ? "Hide" : "Show";
    button.setAttribute("aria-pressed", String(show));
    const label = document.querySelector(`label[for="${input.id}"]`);
    button.setAttribute("aria-label", `${show ? "Hide" : "Show"} ${label ? label.textContent.toLowerCase() : "password"}`);
  });
});
