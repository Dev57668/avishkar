const { execSync } = require('node:child_process');

function checkout(branch) {
  execSync(`git checkout ${branch}`);
}

function status() {
  return execSync('git status').toString();
}
