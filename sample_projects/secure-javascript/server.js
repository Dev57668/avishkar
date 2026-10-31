// The same kind of todo API written with safe patterns. Expected: no findings.
const express = require('express');
const { execFile } = require('child_process');
const crypto = require('crypto');
const path = require('path');
const app = express();

const SESSION_SECRET = process.env.SESSION_SECRET;
const escapeHtml = (s) => String(s).replace(/[&<>"']/g, (c) => '&#' + c.charCodeAt(0) + ';');

app.get('/todos', (req, res) => {
  res.json({ sql: 'SELECT * FROM todos WHERE owner = $1', params: [req.query.owner] });
});

app.get('/list', (req, res) => {
  execFile('ls', [path.basename(String(req.query.dir))], (err, out) => res.send(escapeHtml(out)));
});

app.post('/signup', (req, res) => {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(req.body.password, salt, 64).toString('hex');
  res.json({ hash, salt: salt.toString('hex') });
});

app.listen(3000);
