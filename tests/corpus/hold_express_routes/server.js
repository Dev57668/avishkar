const express = require('express');
const { exec } = require('child_process');
const app = express();

app.get('/hello', (req, res) => {
  res.send(`<p>Hello ${req.query.name}</p>`);
});

app.get('/user/:id', (req, res) => {
  db.query("SELECT * FROM users WHERE id = " + req.params.id, (err, rows) => res.json(rows));
});

app.get('/ls', (req, res) => {
  exec("ls " + req.query.dir, (err, out) => res.send(out));
});

app.get('/ok', (req, res) => res.json({ ok: true }));
