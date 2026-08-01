/**
 * Idiomatic, SECURE Express controller. Nothing in this file should
 * trigger an Error- or Warning-severity finding — it exists to catch
 * false-positive regressions in the rule set.
 */
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const { body, validationResult } = require('express-validator');

const app = express();
app.use(helmet());
app.use(express.json({ limit: '100kb' }));

const db = require('./db');

// Parameterized query — no string concatenation.
async function findUserByEmail(email) {
  const result = await db.query('SELECT id, email FROM users WHERE email = $1', [email]);
  return result.rows[0];
}

app.post(
  '/login',
  body('email').isEmail().normalizeEmail(),
  body('secret').isLength({ min: 12 }),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const user = await findUserByEmail(req.body.email);
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const ok = await bcrypt.compare(req.body.secret, user.passwordHash);
    if (!ok) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ sub: user.id }, process.env.JWT_SIGNING_KEY, {
      algorithm: 'HS256',
      expiresIn: '15m',
    });
    res.set('Cache-Control', 'no-store');
    res.json({ token });
  }
);

// Reads the id from the authenticated session, not from user input —
// the caller can only ever fetch their own profile.
app.get('/me', requireAuth, async (req, res) => {
  const result = await db.query('SELECT id, name FROM users WHERE id = $1', [req.user.sub]);
  if (!result.rows[0]) {
    return res.status(404).json({ error: 'Not found' });
  }
  res.json(result.rows[0]);
});

function requireAuth(req, res, next) {
  try {
    const header = req.get('authorization') || '';
    const token = header.replace(/^Bearer\s+/i, '');
    req.user = jwt.verify(token, process.env.JWT_SIGNING_KEY, { algorithms: ['HS256'] });
    next();
  } catch {
    res.status(401).json({ error: 'Unauthorized' });
  }
}

module.exports = app;
