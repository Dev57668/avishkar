const { execFile } = require('child_process');
function f(h) {
  execFile('ping', [h]);
  el.textContent = h;
}
