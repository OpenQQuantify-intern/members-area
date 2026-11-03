"use strict";

// Optional Node checks for the vanilla JavaScript behavior. No browser or
// backend runtime depends on Node; Python remains the application's server.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const source = fs.readFileSync(path.join(__dirname, "../members/static/js/recovery.js"), "utf8");

async function scenario({fragment, valid = true, ready = false, networkError = false}) {
  const events = [];
  const tokenInput = {value: ready ? "previously-posted-token" : ""};
  const csrfInput = {value: "browser-specific-csrf"};
  const passwordInput = {focused: false, focus() { this.focused = true; }};
  const form = {
    hidden: !ready,
    querySelector(selector) {
      if (selector.includes('name="token"')) return tokenInput;
      if (selector.includes('name="csrf_token"')) return csrfInput;
      if (selector.includes('name="new_password"')) return passwordInput;
      throw new Error("Unexpected field selector");
    },
  };
  const nodes = {
    "reset-password-form": form,
    "reset-link-status": {hidden: ready},
    "reset-link-error": {hidden: true, textContent: ""},
    "reset-new-link": {hidden: ready},
  };
  const root = {dataset: {ready: String(ready), checkUrl: "/reset-password/check"}};
  let request;
  const context = {
    document: {querySelector: () => root, getElementById: id => nodes[id]},
    window: {
      location: {hash: fragment, pathname: "/reset-password"},
      history: {replaceState(state, title, url) { events.push("history"); assert.equal(url, "/reset-password"); }},
      setTimeout, clearTimeout,
    },
    URLSearchParams, AbortController,
    fetch: async (url, options) => {
      events.push("fetch");
      request = {url, options};
      if (networkError) throw new Error("Connection failed");
      return {ok: valid, json: async () => ({valid, message: valid ? undefined : "Invalid link"})};
    },
  };
  await vm.runInNewContext(source, context);
  return {events, request, nodes, form, tokenInput, passwordInput};
}

(async () => {
  const token = "A".repeat(43);
  const success = await scenario({fragment: "#token=" + token});
  assert.deepEqual(success.events, ["history", "fetch"]);
  assert.equal(success.request.url, "/reset-password/check");
  assert.equal(success.request.options.method, "POST");
  assert.equal(success.request.options.body.get("token"), token);
  assert.equal(success.request.options.headers["X-CSRFToken"], "browser-specific-csrf");
  assert.equal(success.form.hidden, false);
  assert.equal(success.passwordInput.focused, true);
  const invalid = await scenario({fragment: "#token=" + token, valid: false});
  assert.equal(invalid.form.hidden, true);
  assert.equal(invalid.tokenInput.value, "");
  assert.equal(invalid.nodes["reset-link-error"].textContent, "Invalid link");
  const missing = await scenario({fragment: ""});
  assert.equal(missing.request, undefined);
  assert.equal(missing.form.hidden, true);
  const failed = await scenario({fragment: "#token=" + token, networkError: true});
  assert.equal(failed.form.hidden, true);
  assert.equal(failed.tokenInput.value, "");
  const posted = await scenario({fragment: "", ready: true});
  assert.equal(posted.request, undefined);
  assert.equal(posted.form.hidden, false);
  console.log("PASS: five recovery client scenarios, including removing the fragment before sending a CSRF-protected POST.");
})().catch(error => { console.error(error); process.exitCode = 1; });
