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
