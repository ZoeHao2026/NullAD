/* NullAD colour-theme bootstrap.
 *
 * Two constraints shape this file:
 *
 *   1. The app's CSP is `script-src 'self'`, so an inline bootstrap in
 *      index.html would be refused. The theme has to live in its own
 *      same-origin file.
 *   2. It is loaded synchronously from <head>, *before* the stylesheet, so the
 *      `data-theme` attribute is on <html> before the first paint. A deferred
 *      script would flash the default theme first.
 *
 * Light is the default: the classic Swiss paper ground. The stored choice wins
 * when one exists; the operating system's colour preference is deliberately not
 * consulted, so the application looks the same on every machine until the user
 * says otherwise.
 */
"use strict";

(function () {
  var KEY = "nullad.theme";
  var LIGHT = "light";
  var DARK = "dark";
  var root = document.documentElement;
  /** Theme currently applied, so the buttons can be re-synced after parsing. */
  var current = LIGHT;

  /** Reads the stored preference, tolerating a webview without storage. */
  function read() {
    try {
      return window.localStorage.getItem(KEY);
    } catch (err) {
      return null;
    }
  }

  /** Persists the preference. A theme that cannot be remembered still works. */
  function write(theme) {
    try {
      window.localStorage.setItem(KEY, theme);
    } catch (err) {
      /* Storage unavailable; the theme simply does not survive a reload. */
    }
  }

  /** Applies a theme and syncs the switch. Safe to call before the DOM exists. */
  function apply(theme) {
    current = theme === DARK ? DARK : LIGHT;
    root.setAttribute("data-theme", current);

    var options = [
      [document.getElementById("theme-light"), LIGHT],
      [document.getElementById("theme-dark"), DARK],
    ];

    options.forEach(function (option) {
      var element = option[0];
      if (!element) return;
      var active = option[1] === current;
      element.classList.toggle("is-active", active);
      element.setAttribute("aria-pressed", active ? "true" : "false");
    });
  }

  // Runs before the first paint, which is the whole point of this file.
  apply(read() === DARK ? DARK : LIGHT);

  document.addEventListener("DOMContentLoaded", function () {
    var light = document.getElementById("theme-light");
    var dark = document.getElementById("theme-dark");

    if (light) {
      light.addEventListener("click", function () {
        write(LIGHT);
        apply(LIGHT);
      });
    }
    if (dark) {
      dark.addEventListener("click", function () {
        write(DARK);
        apply(DARK);
      });
    }

    // The buttons did not exist for the call above; sync them now.
    apply(current);
  });
})();
