window.__ModuleLoader__.load({ id: "@aukora/dsh-plugin-auma-theme", factory: (require) => {
var module = { exports: {} }; var exports = module.exports;
"use strict";
// CLIENT HALF of aukora-auma-theme (hand-written, no build step). Follows the gate-applied theme accent live: polls the
// authenticated host route and applies the accent as one Cordis theme override layer (dispose + re-apply on change).
// "default" removes the layer. Nothing here can propose or approve anything.
var SOURCE = "@aukora/auma-theme";
var ROUTE = "/api/aukora/theme";
var HEX = /^#[0-9A-F]{6}$/;
function tokensFor(hex) {
  var v = { light: hex, dark: hex };
  return {
    "--dsw-alias-brand-primary": v,
    "--dsw-alias-button-primary-fill": v,
    "--dsw-specific-sidebar-nav-item-active-accent": v,
    "--dsw-alias-link": v
  };
}
exports.inject = ["theme"];
exports.apply = function apply(ctx) {
  ctx.effect(function () {
    var current = "default", layer = null, stopped = false, timer = null;
    function drop() { if (typeof layer === "function") { try { layer(); } catch (e) {} } layer = null; }
    function set(accent) {
      if (accent === current) return;
      drop();
      current = accent;
      if (HEX.test(accent)) layer = ctx.theme.overrideTokens(SOURCE, tokensFor(accent));
      try { document.documentElement.setAttribute("data-auma-accent", accent); } catch (e) {}
    }
    function tick() {
      fetch(ROUTE, { credentials: "same-origin", cache: "no-store" })
        .then(function (r) { return r.ok ? r.json() : null; })
        .then(function (j) { if (j && typeof j.accent === "string" && (j.accent === "default" || HEX.test(j.accent))) set(j.accent); })
        .catch(function () {})
        .then(function () { if (!stopped) timer = setTimeout(tick, 2000); });
    }
    tick();
    return function () { stopped = true; if (timer) clearTimeout(timer); drop(); };
  }, "aukora-auma-theme.live-accent");
};
return module.exports; } });
