/* Run before the stylesheet so a stored dark theme never flashes light. */
(function () {
  "use strict";
  const key = "nullad.theme";
  let theme = "light";
  try { if (localStorage.getItem(key) === "dark") theme = "dark"; } catch (_) {}
  document.documentElement.dataset.theme = theme;
  document.addEventListener("DOMContentLoaded", () => {
    const select = document.getElementById("theme-select");
    select.value = theme;
    select.addEventListener("change", () => {
      theme = select.value === "dark" ? "dark" : "light";
      document.documentElement.dataset.theme = theme;
      try { localStorage.setItem(key, theme); } catch (_) {}
    });
  });
})();
