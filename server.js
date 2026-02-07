const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const session = require('express-session');
const path = require('path');
const csrf = require('csurf');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = 3000;

/* =======================
   MIDDLEWARE
======================= */
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// Static files (CSS)
app.use(express.static(path.join(__dirname, 'public')));

// Session
app.use(
  session({
    secret: 'secure-auth-secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'strict'
    }
  })
);

// CSRF (AFTER session)
const csrfProtection = csrf();

/* =======================
   DATABASE
======================= */
const db = new sqlite3.Database('./users.db');

db.run(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    password TEXT
  )
`);

/* =======================
   RATE LIMITING
======================= */
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    return res.redirect('/login?error=rate');
  }
});

/* =======================
   HELPERS
======================= */
const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.redirect('/login');
  }
  next();
}

/* =======================
   ROUTES
======================= */

// Root
app.get('/', (req, res) => {
  res.redirect('/login');
});

/* =======================
   AUTH PAGES
======================= */

app.get('/login', csrfProtection, (req, res) => {
  let error = '';

if (req.query.error === 'invalid') {
  error = 'Invalid email or password';
} else if (req.query.error === 'rate') {
  error = 'Too many failed attempts. Try again later.';
} else if (req.query.error === 'csrf') {
  error = 'Session expired. Please try again.';
}


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

    ${error ? `<div class="error">${error}</div>` : ''}

    <form method="POST" action="/login">
      <input type="hidden" name="_csrf" value="${req.csrfToken()}">
      <input type="email" name="email" placeholder="Email" required>
      <input type="password" name="password" placeholder="Password" required>
      <button type="submit">Login</button>
    </form>

    <p><a href="/signup">No account? Create one</a></p>
  </div>
</body>
</html>
`);
});

app.get('/signup', csrfProtection, (req, res) => {
  let error = '';

  if (req.query.error === 'exists') {
    error = 'User already exists';
  } else if (req.query.error === 'invalid') {
    error = 'Invalid email format';
  }

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

    ${error ? `<div class="error">${error}</div>` : ''}

    <form method="POST" action="/signup">
      <input type="hidden" name="_csrf" value="${req.csrfToken()}">
      <input type="email" name="email" placeholder="Email" required>
      <input type="password" name="password" placeholder="Password" required>
      <button type="submit">Sign Up</button>
    </form>

    <p><a href="/login">Already have an account? Login</a></p>
  </div>
</body>
</html>
`);
});

/* =======================
   AUTH LOGIC
======================= */

// Signup
app.post('/signup', csrfProtection, async (req, res) => {
  const { email, password } = req.body;

  if (!emailRegex.test(email)) {
    return res.redirect('/signup?error=invalid');
  }

  try {
    const hash = await bcrypt.hash(password, 10);

    db.run(
      `INSERT INTO users (email, password) VALUES (?, ?)`,
      [email, hash],
      function (err) {
        if (err) return res.redirect('/signup?error=exists');

        req.session.userId = this.lastID;
        res.redirect('/home');
      }
    );
  } catch {
    res.redirect('/signup');
  }
});

// Login
app.post('/login', loginLimiter, csrfProtection, (req, res) => {
  const { email, password } = req.body;

  if (!email || !password || !emailRegex.test(email)) {
    return res.redirect('/login?error=invalid');
  }

  db.get(
    `SELECT * FROM users WHERE email = ?`,
    [email],
    async (err, user) => {
      if (!user) {
        return res.redirect('/login?error=invalid');
      }

      const match = await bcrypt.compare(password, user.password);
      if (!match) {
        return res.redirect('/login?error=invalid');
      }

      req.session.userId = user.id;
      res.redirect('/home');
    }
  );
});

/* =======================
   PROTECTED ROUTES
======================= */

app.get('/home', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'home.html'));
});

app.get('/logout', requireAuth, (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login');
  });
});
app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') {
    return res.redirect('/login?error=csrf');
  }
  next(err);
});


/* =======================
   SERVER
======================= */
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
