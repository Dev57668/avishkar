const fs = require('fs');
const path = require('path');
const BASE = path.resolve('/srv/uploads');

function read(name) {
  const full = path.resolve(BASE, name);
  if (!full.startsWith(BASE + path.sep)) throw new Error('invalid path');
  return fs.readFileSync(full, 'utf8');
}
module.exports = { read };
