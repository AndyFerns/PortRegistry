// PortRegistry GUI helpers. Live updates are driven by htmx + the SSE extension;
// this file only reflects the SSE connection state and adds keyboard shortcuts.
(function () {
  "use strict";

  function setConnection(state) {
    var el = document.getElementById("conn");
    if (!el) return;
    el.dataset.state = state;
    el.textContent = state === "live" ? "Live" : "Disconnected";
    el.title = state === "live"
      ? "Receiving live updates from the daemon"
      : "Lost connection to the daemon; showing last loaded data. Reconnecting...";
    document.body.classList.toggle("pr-offline", state !== "live");
  }

  document.addEventListener("htmx:sseOpen", function () { setConnection("live"); });
  document.addEventListener("htmx:sseError", function () { setConnection("offline"); });
  document.addEventListener("htmx:sseClose", function () { setConnection("offline"); });

  // ------------------------------------------------- desktop notifications
  // Opt-in, per browser. Uses the Notification API on SSE "alerts" events.
  var STORAGE_KEY = "portregistry.notify";

  function notifyEnabled() {
    try { return window.localStorage.getItem(STORAGE_KEY) === "1"; } catch (e) { return false; }
  }

  function setNotify(on) {
    try { window.localStorage.setItem(STORAGE_KEY, on ? "1" : "0"); } catch (e) { /* storage blocked */ }
    renderNotifyButton();
  }

  function renderNotifyButton() {
    var btn = document.getElementById("pr-notify");
    if (!btn) return;
    if (!("Notification" in window)) {
      btn.textContent = "Desktop alerts: unsupported";
      btn.disabled = true;
      return;
    }
    var on = notifyEnabled() && Notification.permission === "granted";
    btn.dataset.on = on ? "1" : "0";
    btn.textContent = "Desktop alerts: " + (on ? "on" : (Notification.permission === "denied" ? "blocked" : "off"));
  }

  document.addEventListener("click", function (event) {
    if (!event.target || event.target.id !== "pr-notify") return;
    if (notifyEnabled() && Notification.permission === "granted") { setNotify(false); return; }
    Notification.requestPermission().then(function (permission) {
      setNotify(permission === "granted");
    });
  });

  var TITLES = {
    "conflict.detected": "Port conflict",
    "conflict.resolved": "Conflict resolved",
    "docker.unavailable": "Docker unavailable",
    "docker.available": "Docker available",
    "scan.failed": "Discovery failed"
  };

  document.addEventListener("htmx:sseMessage", function (event) {
    var message = event.detail;
    if (!message || message.type !== "alerts" || !notifyEnabled()) return;
    if (!("Notification" in window) || Notification.permission !== "granted") return;
    var payload;
    try { payload = JSON.parse(message.data); } catch (e) { return; }
    var data = payload.data || {};
    // Notification bodies are plain text (never HTML), so no escaping issues.
    new Notification(TITLES[payload.type] || "PortRegistry", {
      body: String(data.summary || payload.type).slice(0, 240),
      tag: "portregistry-" + (data.entity_id || payload.seq)
    });
  });

  document.addEventListener("DOMContentLoaded", renderNotifyButton);

  // "/" focuses the page's search box (unless typing in a field already).
  document.addEventListener("keydown", function (event) {
    var tag = (document.activeElement && document.activeElement.tagName) || "";
    if (event.key === "/" && ["INPUT", "TEXTAREA", "SELECT"].indexOf(tag) === -1) {
      var search = document.querySelector("[data-search]");
      if (search) {
        event.preventDefault();
        search.focus();
        search.select();
      }
    }
  });
})();
