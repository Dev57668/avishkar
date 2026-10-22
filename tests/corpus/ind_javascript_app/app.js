"""
Intentionally Vulnerable JavaScript/Node.js Application
FOR DEMO/TESTING PURPOSES ONLY
"""

const express = require('express');
const app = express();

// VULNERABILITY: Hardcoded secrets
const API_KEY = 'sk-test-1234567890abcdef';
const DATABASE_PASSWORD = 'admin123';

// VULNERABILITY: SQL Injection
const sqlite3 = require('sqlite3');
const db = new sqlite3.Database('users.db');

function login(username, password) {
    // SQL Injection vulnerability
    const query = `SELECT * FROM users WHERE username='${username}' AND password='${password}'`;
    return new Promise((resolve, reject) => {
        db.get(query, (err, row) => {
            if (err) reject(err);
            resolve(row);
        });
    });
}

// VULNERABILITY: Command Injection
const { exec } = require('child_process');

function pingHost(host) {
    // Command injection vulnerability
    exec(`ping ${host}`, (error, stdout, stderr) => {
        console.log(stdout);
    });
}

// VULNERABILITY: eval() usage
function calculate(expression) {
    // Code injection via eval
    return eval(expression);
}

// VULNERABILITY: Insecure crypto
const crypto = require('crypto');

function hashPassword(password) {
    // Using MD5 for passwords
    return crypto.createHash('md5').update(password).digest('hex');
}

// VULNERABILITY: Path traversal
const fs = require('fs');

function readFile(filename) {
    // No path validation
    const filepath = `./uploads/${filename}`;
    return fs.readFileSync(filepath, 'utf8');
}

// VULNERABILITY: XSS vulnerability
app.get('/search', (req, res) => {
    const query = req.query.q;
    // Reflected XSS - no sanitization
    res.send(`<h1>Search results for: ${query}</h1>`);
});

// VULNERABILITY: Insecure JWT
const jwt = require('jsonwebtoken');
const JWT_SECRET = 'secret123';

function createToken(user) {
    // Weak secret, no expiration
    return jwt.sign({ id: user.id }, JWT_SECRET);
}

// VULNERABILITY: No rate limiting on sensitive endpoint
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await login(username, password);
    if (user) {
        res.json({ token: createToken(user) });
    } else {
        res.status(401).json({ error: 'Invalid credentials' });
    }
});

// VULNERABILITY: Debug mode enabled
app.listen(3000, () => {
    console.log('Server running on port 3000');
    console.log('Debug mode: ENABLED');
    console.log(`API Key: ${API_KEY}`);  // Logging sensitive data
});

module.exports = app;
