const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const session = require('express-session');
const path = require('path');
const csrf = require('csurf');

const app = express();
const PORT = 3000;

// =======================
// MIDDLEWARE
// =======================
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Serve static files (CSS)
app.use(express.static('public'));

app.use(session({
  secret: 'secure-auth-secret',
  resave: false,
  saveUninitialized: false
}));

// CSRF protection (after session)
const csrfProtection = csrf();
app.use(csrfProtection);

// =======================
// DATABASE SETUP
// =======================
const db = new sqlite3.Database('./users.db');

db.run(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    password TEXT
  )
`);

// =======================
// ROUTES
// =======================

// Root test
app.get('/', (req, res) => {
  res.send('Secure Auth Web App Running');
});

// =======================
// AUTH PAGES
// =======================

app.get('/signup', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Sign Up</title>
      <link rel="stylesheet" href="/style.css">
    </head>
    <body>
      <div class="container">
        <h2>Create Account</h2>

        <form method="POST" action="/signup">
          <input type="hidden" name="_csrf" value="${req.csrfToken()}">

          <input name="email" placeholder="Email" required>
          <input type="password" name="password" placeholder="Password" required>

          <button>Sign Up</button>
        </form>

        <a href="/login">Already have an account? Login</a>
      </div>
    </body>
    </html>
  `);
});

app.get('/login', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Login</title>
      <link rel="stylesheet" href="/style.css">
    </head>
    <body>
      <div class="container">
        <h2>Login</h2>

        <form method="POST" action="/login">
          <input type="hidden" name="_csrf" value="${req.csrfToken()}">

          <input name="email" placeholder="Email" required>
          <input type="password" name="password" placeholder="Password" required>

          <button>Login</button>
        </form>

        <a href="/signup">No account? Create one</a>
      </div>
    </body>
    </html>
  `);
});

// =======================
// AUTH LOGIC
// =======================

const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// Handle signup
app.post('/signup', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.send('Email and password required');
  }

  if (!emailRegex.test(email)) {
    return res.send('Invalid email format');
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    db.run(
      `INSERT INTO users (email, password) VALUES (?, ?)`,
      [email, hashedPassword],
      function (err) {
        if (err) {
          return res.send('User already exists');
        }

        req.session.userId = this.lastID;
        res.redirect('/home');
      }
    );
  } catch {
    res.send('Signup error');
  }
});

// Handle login
app.post('/login', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.send('Email and password required');
  }

  if (!emailRegex.test(email)) {
    return res.send('Invalid email format');
  }

  db.get(
    `SELECT * FROM users WHERE email = ?`,
    [email],
    async (err, user) => {
      if (err || !user) {
        return res.send('Invalid email or password');
      }

      const valid = await bcrypt.compare(password, user.password);
      if (!valid) {
        return res.send('Invalid email or password');
      }

      req.session.userId = user.id;
      res.redirect('/home');
    }
  );
});

// =======================
// PROTECTED ROUTES
// =======================

app.get('/home', (req, res) => {
  if (!req.session.userId) {
    return res.redirect('/login');
  }

  res.sendFile(path.join(__dirname, 'views', 'home.html'));
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login');
  });
});

// =======================
// SERVER START
// =======================
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
