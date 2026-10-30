const jwt = require('jsonwebtoken');

function issue(payload) {
  return jwt.sign(payload, 'supersecretkey123');
}

function check(token) {
  return jwt.verify(token, process.env.JWT_SECRET);
}
