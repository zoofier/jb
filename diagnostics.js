(() => {
'use strict';
const out = document.getElementById('log');
const fw = document.getElementById('fw');
const log = s => out.textContent += s + "\n";
const ua = navigator.userAgent || '';
const m = ua.match(/PlayStation 4[ /]([0-9.]+)/i);

fw.textContent = m ? m[1] : 'UNKNOWN';
fw.className = m && m[1].startsWith('14.00') ? 'ok' : 'warn';

log('ZOOF13R 14.00 verification layer');
log('User agent: ' + ua);
log('URL: ' + location.href);
log('WebKit object: ' + (window.webkit ? 'present' : 'unknown'));
log('Exploit execution: disabled in this staging build');
log('HEN execution: disabled until a verified chain is supplied');

document.getElementById('diag').onclick = () => {
  log('Diagnostics completed.');
};
})();