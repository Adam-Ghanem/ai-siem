const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {escapeHtml} = require('../frontend/security.js');
test('escapes hostile telemetry correctly', () => {
  assert.equal(escapeHtml(`<img src="x" onerror='alert(1)'>&`),
    '&lt;img src=&quot;x&quot; onerror=&#39;alert(1)&#39;&gt;&amp;');
});
test('handles null, numeric and array evidence safely', () => {
  assert.equal(escapeHtml(null), '');
  assert.equal(escapeHtml(42), '42');
  assert.equal(escapeHtml(['<svg/onload=alert(1)>']), '&lt;svg/onload=alert(1)&gt;');
});
test('app sanitizes dynamic templates and never persists bearer keys', () => {
  const app = fs.readFileSync(path.join(__dirname, '../frontend/app.js'), 'utf8');
  assert.match(app, /const safe\s*=.*AISiemSecurity\.escapeHtml/);
  assert.match(app, /safe\(\(i\.related_alert_ids/);
  assert.match(app, /safe\(Object\.entries/);
  assert.match(app, /safe\(action\)/);
  assert.doesNotMatch(app, /localStorage\.(?:getItem|setItem)\(['"]AI_SIEM_API_KEY/);
  assert.doesNotMatch(app, /Math\.random\(\)/);
  assert.match(app, /function renderSeverityDonut\(\)/);
  assert.match(app, /counts\[level\]\+\+/);
  assert.match(app, /let apiToken = ''/);
});
test('HTML loads security module before dashboard entrypoint', () => {
  const html = fs.readFileSync(path.join(__dirname, '../frontend/index.html'), 'utf8');
  assert.ok(html.indexOf('security.js') < html.indexOf('app.js'));
});
