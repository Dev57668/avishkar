// A small todo API. Intentionally insecure, for education.
const express = require('express');
const { exec } = require('child_process');
const crypto = require('crypto');
const app = express();

const SESSION_SECRET = 'todo-session-secret-7d21a9c4e1';

app.get('/todos', (req, res) => {
  const owner = req.query.owner;
  const sql = `SELECT * FROM todos WHERE owner = '${owner}'`;
  res.json({ sql });
});

app.get('/run', (req, res) => {
  exec(`ls ${req.query.dir}`, (err, out) => res.send(out));
});

app.get('/calc', (req, res) => {
  res.send(String(eval(req.query.expr)));
});

app.post('/signup', (req, res) => {
  const hash = crypto.createHash('sha1').update(req.body.password).digest('hex');
  res.json({ hash });
});

app.listen(3000);
