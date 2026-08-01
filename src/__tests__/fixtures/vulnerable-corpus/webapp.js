/**
 * Intentionally vulnerable Express web app — corpus fixture.
 * Every block exists to trigger a specific rule family in the auth,
 * web-security, and frontend groups.
 */
const express = require('express');
const jwt = require('jsonwebtoken');
const https = require('https');

const app = express();

// CORS001: wildcard CORS
app.use(require('cors')({ origin: '*' }));

// AUTH001: JWT signed with an inline string secret
function issueToken(user) {
  return jwt.sign({ sub: user.id }, 'super-secret-signing-key');
}

// AUTH002: session cookie without httpOnly / secure
app.use(require('cookie-session')({ name: 's', httpOnly: false, secure: false }));

// CSRF003: SameSite=None cookie
app.use((req, res, next) => {
  res.cookie('pref', 'x', { sameSite: 'none' });
  next();
});

// CSRF004: state change over GET
app.get('/account/delete', (req, res) => {
  res.send('deleted');
});

// AUTH003: plaintext password comparison against user input
function login(req, storedPassword) {
  return storedPassword === req.body.password;
}

// AUTH005: 4-char minimum password
const passwordPolicy = { minlength: 4 };

// ENC002: hardcoded encryption key
const encryption_key = 'AAAABBBBCCCCDDDD';

// ENC004: TLS verification disabled
const agent = new https.Agent({ rejectUnauthorized: false });

// ENC005: Math.random for a security token
// CSRF006: CSRF token from Math.random
const csrfToken = 'csrf-' + Math.random().toString(36);

// ENC007: secret logged to console
console.log('issued token', csrfToken);

// API004: 500 handler that returns the raw error
app.use((err, req, res, next) => {
  res.status(500).json(err);
});

// API006: debug mode left on
const config = { DEBUG: true };

// API011: wildcard role
const superUser = { role: '*' };

// XSS014: reflected request data in the response
app.get('/echo', (req, res) => {
  res.send('you said ' + req.query.q);
});

// SSRF001: fetch of a user-controlled URL
app.post('/preview', async (req, res) => {
  const page = await fetch(req.body.url);
  res.send(await page.text());
});

// DESER008: eval of request data
app.post('/calc', (req, res) => {
  res.json({ result: eval(req.body.expression) });
});

// CMD001: shell command concatenated from request input
const { exec } = require('child_process');
app.get('/ping', (req, res) => {
  exec('ping -c1 ' + req.query.host, (e, out) => res.send(out));
});

// FE007c: prototype-pollution-prone spread of request body
app.post('/settings', (req, res) => {
  const merged = { ...req.body.preferences };
  res.json(merged);
});

// BIZ008: client-supplied usage counter trusted
app.post('/meter', (req, res) => {
  res.json({ charged: req.body.count });
});

// AUTH007 + FE011: token stored in localStorage (client bundle)
const clientSnippet = () => {
  localStorage.setItem('token', csrfToken);
};

// FE006: document.cookie written directly
const setCookie = () => {
  document.cookie = 'tracking=1';
};

// XSS001 + FE012: location data into innerHTML
const renderHash = () => {
  document.getElementById('out').innerHTML = location.hash.slice(1);
};

module.exports = app;
