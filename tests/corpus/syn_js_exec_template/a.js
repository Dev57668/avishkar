const cp = require('child_process');
function f(h) {
  cp.exec(`ping ${h}`);
}
