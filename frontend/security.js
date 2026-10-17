/* Encode untrusted telemetry before insertion into dashboard HTML templates. */
(function (root) {
  'use strict';
  const entities = Object.freeze({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  });
  function escapeHtml(value) {
    return String(value ?? '').replace(/[&<>"']/g, character => entities[character]);
  }
  const api = Object.freeze({escapeHtml});
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  } else {
    root.AISiemSecurity = api;
  }
})(typeof globalThis !== 'undefined' ? globalThis : this);
