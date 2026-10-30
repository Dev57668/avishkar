const vm = require('vm');

function parse(text) {
  return JSON.parse(text);
}

function run(code) {
  return eval(code);
}

function sandboxed(userCode) {
  return vm.runInNewContext(userCode);
}
