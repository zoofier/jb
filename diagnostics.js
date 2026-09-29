(function(){
'use strict';
const out=document.getElementById('log');
const fw=document.getElementById('fw');
function log(s){out.textContent += s + "\n";}
function detect(){
  const ua=navigator.userAgent||'';
  const m=ua.match(/PlayStation 4[ /]([0-9.]+)/i);
  fw.textContent=m?m[1]:'UNKNOWN';
  fw.className=m&&m[1].startsWith('14.00')?'ok':'warn';
  log('ZOOF13R 14.00 verification layer');
  log('User agent: '+ua);
  log('Location: '+location.href);
  log('WebKit engine: '+(window.webkit?'present':'unknown'));
  log('Exploit execution: intentionally disabled in this diagnostic build');
}
document.getElementById('diag').onclick=detect;
detect();
})();