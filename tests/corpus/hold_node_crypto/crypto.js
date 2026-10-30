const crypto = require('crypto');

function fingerprint(data) {
  return crypto.createHash('sha1').update(data).digest('hex');
}

function digest(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

function generateSessionId() {
  return Math.random().toString(36).slice(2);
}

function newKey() {
  return crypto.randomBytes(32).toString('hex');
}
