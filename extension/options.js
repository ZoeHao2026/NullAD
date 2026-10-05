(function () {
  "use strict";
  const { t, apply } = NullADText;
  const $ = (id) => document.getElementById(id);
  const send = async (message) => { const value = await chrome.runtime.sendMessage(message); if (!value || !value.ok) throw new Error(value && value.error || "Worker unavailable"); return value; };
  let pending = false;
  async function refresh() {
    const state = await send({ type:"STATE" }); apply(state.settings.language);
    $("sites").replaceChildren();
    if (!state.settings.allowSites.length) $("sites").textContent = t("empty");
    for (const host of state.settings.allowSites) {
      const row = document.createElement("div"), label = document.createElement("code"), button = document.createElement("button");
      row.className = "site-row"; label.textContent = host; button.textContent = t("remove");
      button.addEventListener("click", () => operation({ type:"REMOVE_SITE", host }));
      row.append(label, button); $("sites").appendChild(row);
    }
  }
  async function operation(message) {
    if (pending) return; pending = true;
    document.querySelectorAll("button,select").forEach((element) => element.disabled = true);
    try { const result = await send(message); await refresh(); const warning = result.warnings && result.warnings.length; $("feedback").textContent = warning ? result.warnings.join("\n") : t(message.type === "STOP" ? "stopped" : "saved"); $("feedback").classList.toggle("error", !!warning); }
    catch (error) { $("feedback").textContent = t("failed", { error:error.message }); $("feedback").classList.add("error"); }
    finally { pending = false; document.querySelectorAll("button,select").forEach((element) => element.disabled = false); }
  }
  $("language").addEventListener("change", () => operation({ type:"LANGUAGE", language:$("language").value }));
  $("stop").addEventListener("click", () => operation({ type:"STOP" }));
  refresh().catch((error) => { $("feedback").textContent = t("failed", { error:error.message }); });
})();
