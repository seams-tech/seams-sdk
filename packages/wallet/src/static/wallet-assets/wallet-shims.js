window.global ||= window;
window.process ||= { env: {} };

(function () {
  try {
    var script =
      typeof document !== 'undefined' && document.currentScript ? document.currentScript.src : '';
    if (!script) return;
    var url = new URL(script, typeof location !== 'undefined' ? location.href : '');
    var href = url.href;
    var base = href.slice(0, href.lastIndexOf('/') + 1);
    if (typeof window !== 'undefined' && !window.__W3A_WALLET_SDK_BASE__) {
      window.__W3A_WALLET_SDK_BASE__ = base;
    }
  } catch (error) {}
})();
