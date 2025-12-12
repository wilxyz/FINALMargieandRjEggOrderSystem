require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const mysql = require('mysql');
const bcrypt = require('bcryptjs');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const nodemailer = require('nodemailer');
const path = require('path');

const app = express();

// -----------------------
// Config
// -----------------------
const PORT = process.env.PORT || 3000;
const SESSION_COOKIE_NAME = process.env.SESSION_COOKIE_NAME || 'connect.sid';
const ADMIN_EMAIL_DOMAIN = (process.env.ADMIN_EMAIL_DOMAIN || '').toLowerCase().trim();

// -----------------------
// Middleware
// -----------------------
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(session({
  name: SESSION_COOKIE_NAME,
  secret: process.env.SESSION_SECRET || 'eggsecret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    sameSite: 'lax',
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production'
  }
}));
app.use(passport.initialize());
app.use(passport.session());

// Serve static files from project root
app.use(express.static(__dirname));

// Serve vendor files (Chart.js) from node_modules
app.use('/vendor', express.static(path.join(__dirname, 'node_modules')));


// Helper to detect AJAX / fetch requests
function isAjax(req) {
  const accept = req.get('Accept') || '';
  const xrw = req.get('X-Requested-With') || '';
  return accept.includes('application/json') || xrw === 'XMLHttpRequest' || req.is('application/json');
}

// -----------------------
// Database
// -----------------------
const db = mysql.createConnection({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'eggs_db',
  port: process.env.DB_PORT || 3306,
  multipleStatements: false
});
db.connect(err => {
  if (err) {
    console.error('MySQL connection error:', err);
    process.exit(1);
  }
  console.log('✅ MySQL Connected!');
});

// -----------------------
// Price sets (server-side reference)
// -----------------------
const PRICE_SETS = {
  full: { small: 220, medium: 230, large: 240, xlarge: 255, jumbo: 265, superjumbo: 275 },
  half: { small: 112, medium: 120, large: 123, xlarge: 130, jumbo: 135, superjumbo: 142 }
};
const HALF_PRICE_SET = new Set(Object.values(PRICE_SETS.half).map(p => Number(p)));

// -----------------------
// Passport Google OAuth
// -----------------------
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: process.env.GOOGLE_CALLBACK_URL
}, (accessToken, refreshToken, profile, done) => {
  const email = profile.emails && profile.emails[0] && profile.emails[0].value;
  if (!email) return done(new Error('No email from Google profile'));

  db.query("SELECT * FROM users WHERE email = ?", [email], (err, users) => {
    if (err) return done(err);
    if (users.length > 0) return done(null, users[0]);

    db.query("INSERT INTO users (username, email, google_id) VALUES (?, ?, ?)",
      [profile.displayName || 'GoogleUser', email, profile.id],
      (err2, result) => {
        if (err2) return done(err2);
        db.query("SELECT * FROM users WHERE id = ?", [result.insertId], (err3, newUser) => {
          if (err3) return done(err3);
          return done(null, newUser[0]);
        });
      });
  });
}));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => {
  db.query("SELECT * FROM users WHERE id = ?", [id], (err, users) => {
    done(err, users && users[0] ? users[0] : null);
  });
});

// -----------------------
// Utility helpers
// -----------------------
function toISODate(val) {
  if (!val) return null;
  const d = new Date(val);
  if (isNaN(d)) return null;
  return d.toISOString().slice(0, 10);
}
function sanitizeTrayType(value) {
  if (!value) return 'full';
  const v = String(value).toLowerCase();
  return v === 'half' ? 'half' : 'full';
}
function determineTrayTypeFromItem(it) {
  if (it.tray_type && (it.tray_type === 'half' || it.tray_type === 'full')) return sanitizeTrayType(it.tray_type);
  const priceNum = Number(it.price);
  if (!isNaN(priceNum) && HALF_PRICE_SET.has(priceNum)) return 'half';
  return 'full';
}
function sanitizeOrderType(value) {
  if (!value) return 'pickup';
  const v = String(value).toLowerCase();
  return v === 'delivery' ? 'delivery' : 'pickup';
}
function emailDomainIsAdmin(email) {
  if (!ADMIN_EMAIL_DOMAIN) return false;
  if (!email) return false;
  const parts = String(email).split('@');
  if (parts.length !== 2) return false;
  return parts[1].toLowerCase() === ADMIN_EMAIL_DOMAIN;
}

// -----------------------
// Auth middlewares
// -----------------------
function requireLogin(req, res, next) {
  const user = req.session && req.session.user ? req.session.user : (req.user ? req.user : null);
  if (!user || !user.id) {
    if (isAjax(req)) return res.status(401).json({ error: 'Unauthorized. Please log in.' });
    return res.redirect('/login');
  }
  req.currentUser = user;
  next();
}

function requireAdmin(req, res, next) {
  const user = req.session && req.session.user ? req.session.user : (req.user ? req.user : null);
  const isAdminFlag = user && (user.is_admin === 1 || user.is_admin === true);
  const domainAdmin = user && emailDomainIsAdmin(user.email);
  if (!user || !user.id || !(isAdminFlag || domainAdmin)) {
    if (isAjax(req) || req.path.startsWith('/admin/api/')) {
      return res.status(403).json({ error: 'Forbidden. Admins only.' });
    }
    return res.redirect('/login');
  }
  req.currentUser = user;
  next();
}

// -----------------------
// Routes (pages + auth)
// -----------------------
app.get('/', (req, res) => res.redirect('/login'));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/signup', (req, res) => res.sendFile(path.join(__dirname, 'index2.html')));
app.get('/testing.html', (req, res) => {
  if (!req.session.user && !req.user) {
    if (isAjax(req)) return res.status(401).json({ error: 'Unauthorized. Please log in.' });
    return res.redirect('/login');
  }
  res.sendFile(path.join(__dirname, 'testing.html'));
});

// Serve admin UI (admin.html, admin.css, admin.js should be in project root)
app.get('/admin', requireLogin, requireAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});
app.get('/admin/:asset', requireLogin, requireAdmin, (req, res, next) => {
  const asset = req.params.asset;
  const allowed = ['admin.css', 'admin.js'];
  if (allowed.includes(asset)) {
    return res.sendFile(path.join(__dirname, asset));
  }
  next();
});

// -----------------------
// Logout helpers
// -----------------------
function finishLogoutResponse(req, res, err) {
  try { res.clearCookie(SESSION_COOKIE_NAME); } catch (e) { /* ignore */ }

  if (err) {
    console.error('Logout error:', err);
    if (isAjax(req)) return res.status(500).json({ error: 'Failed to logout. Please try again.' });
    return res.status(500).send('Failed to logout. Please try again.');
  }

  if (isAjax(req)) return res.json({ success: true, redirect: '/login' });
  return res.redirect('/login');
}

function attemptPassportLogout(req, res, next) {
  if (typeof req.logout === 'function') {
    try {
      req.logout(function (err) {
        if (err) return next(err);
        return next();
      });
    } catch (e) {
      try { req.logout(); } catch (e2) { /* ignore */ }
      return next();
    }
  } else {
    return next();
  }
}

app.post('/logout', (req, res) => {
  attemptPassportLogout(req, res, (logoutErr) => {
    if (logoutErr) {
      if (req.session) {
        req.session.destroy(() => finishLogoutResponse(req, res, logoutErr));
      } else {
        finishLogoutResponse(req, res, logoutErr);
      }
      return;
    }

    if (req.session) {
      req.session.destroy((err) => {
        finishLogoutResponse(req, res, err);
      });
    } else {
      finishLogoutResponse(req, res);
    }
  });
});

app.get('/logout', (req, res) => {
  attemptPassportLogout(req, res, (logoutErr) => {
    if (logoutErr) {
      if (req.session) {
        req.session.destroy(() => finishLogoutResponse(req, res, logoutErr));
      } else {
        finishLogoutResponse(req, res, logoutErr);
      }
      return;
    }

    if (req.session) {
      req.session.destroy((err) => {
        finishLogoutResponse(req, res, err);
      });
    } else {
      finishLogoutResponse(req, res);
    }
  });
});

// -----------------------
// Auth endpoints
// -----------------------
app.post('/login', (req, res) => {
  const { email, password } = req.body;
  db.query("SELECT * FROM users WHERE email = ?", [email], async (err, results) => {
    if (err) {
      if (isAjax(req)) return res.status(500).json({ error: 'Database error.' });
      return res.redirect('/login?msg=' + encodeURIComponent('Database error.'));
    }
    if (!results.length) {
      if (isAjax(req)) return res.status(400).json({ error: 'User not found!' });
      return res.redirect('/login?msg=' + encodeURIComponent('User not found!'));
    }

    const user = results[0];
    if (!user.password && user.google_id) {
      req.session.google_setpass_email = email;
      if (isAjax(req)) return res.status(200).json({ redirect: '/set-password.html' });
      return res.redirect('/set-password.html');
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      if (isAjax(req)) return res.status(400).json({ error: 'Incorrect Password!' });
      return res.redirect('/login?msg=' + encodeURIComponent('Incorrect Password!'));
    }

    const isAdminFromDb = user.is_admin ? (Number(user.is_admin) === 1) : false;
    const isAdmin = isAdminFromDb || emailDomainIsAdmin(user.email);

    req.session.user = {
      id: user.id,
      username: user.username,
      email: user.email,
      is_admin: isAdmin
    };

    if (isAjax(req)) {
      return res.json({ success: true, redirect: isAdmin ? '/admin' : '/testing.html' });
    }
    return res.redirect(isAdmin ? '/admin' : '/testing.html');
  });
});

app.post('/signup', async (req, res) => {
  const { username, email, password, confirm_password } = req.body;
  if (password !== confirm_password) {
    if (isAjax(req)) return res.status(400).json({ error: 'Passwords do not match!' });
    return res.redirect('/signup?msg=' + encodeURIComponent('Passwords do not match!'));
  }
  const hashed = await bcrypt.hash(password, 10);
  db.query("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", [username, email, hashed], (err, result) => {
    if (err) {
      if (isAjax(req)) return res.status(500).json({ error: 'Error creating user.' });
      return res.redirect('/signup?msg=' + encodeURIComponent('Error creating user.'));
    }

    db.query("SELECT id, username, email, is_admin FROM users WHERE id = ?", [result.insertId], (err2, rows) => {
      if (err2 || !rows.length) {
        req.session.user = { id: result.insertId, username, email, is_admin: false };
      } else {
        const u = rows[0];
        const isAdminFromDb = u.is_admin ? (Number(u.is_admin) === 1) : false;
        const isAdmin = isAdminFromDb || emailDomainIsAdmin(u.email);
        req.session.user = { id: u.id, username: u.username, email: u.email, is_admin: isAdmin };
      }
      if (isAjax(req)) return res.json({ success: true, redirect: '/testing.html' });
      res.redirect('/testing.html');
    });
  });
});

// Google OAuth routes
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login?msg=' + encodeURIComponent('Google login failed.') }),
  (req, res) => {
    const u = req.user || {};
    const isAdminFromDb = u.is_admin ? (Number(u.is_admin) === 1) : false;
    const isAdmin = isAdminFromDb || emailDomainIsAdmin(u.email);
    req.session.user = {
      id: u.id,
      username: u.username,
      email: u.email,
      is_admin: isAdmin
    };
    return res.redirect(isAdmin ? '/admin' : '/testing.html');
  });

// Set password for Google users
app.post('/set-password', async (req, res) => {
  const { password, confirmPassword } = req.body;
  const email = req.session.google_setpass_email;
  if (!email) {
    if (isAjax(req)) return res.status(400).json({ error: 'Session expired. Please sign in again.' });
    return res.redirect('/login');
  }
  if (password !== confirmPassword) {
    if (isAjax(req)) return res.status(400).json({ error: 'Passwords do not match!' });
    return res.redirect('/set-password.html?msg=' + encodeURIComponent('Passwords do not match!'));
  }
  const hashed = await bcrypt.hash(password, 10);
  db.query("UPDATE users SET password = ? WHERE email = ?", [hashed, email], (err) => {
    if (err) {
      if (isAjax(req)) return res.status(500).json({ error: 'Error updating password.' });
      return res.redirect('/set-password.html?msg=' + encodeURIComponent('Error updating password.'));
    }
    req.session.google_setpass_email = null;
    if (isAjax(req)) return res.json({ success: true, redirect: '/login?msg=' + encodeURIComponent('Password created successfully! You may now log in.') });
    res.redirect('/login?msg=' + encodeURIComponent('Password created successfully! You may now log in.'));
  });
});

// -----------------------
// Password reset / contact flows
// -----------------------
app.post('/forgot-password', (req, res) => {
  const { email } = req.body;
  db.query("SELECT * FROM users WHERE email = ?", [email], (err, results) => {
    if (err) {
      if (isAjax(req)) return res.status(500).json({ error: 'Database error.' });
      return res.redirect('/index3.html?msg=' + encodeURIComponent('Database error.'));
    }
    if (!results.length) {
      if (isAjax(req)) return res.status(404).json({ error: 'Email is not registered!' });
      return res.redirect('/index3.html?msg=' + encodeURIComponent('Email is not registered!'));
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiry = Date.now() + 5 * 60 * 1000;
    db.query("UPDATE users SET otp = ?, otp_expiry = ? WHERE email = ?", [otp, expiry, email], (err2) => {
      if (err2) {
        if (isAjax(req)) return res.status(500).json({ error: 'Error saving OTP.' });
        return res.redirect('/index3.html?msg=' + encodeURIComponent('Error saving OTP.'));
      }
      const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
      });
      const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: "Your OTP Code",
        html: `<h3>Your OTP Code:</h3><h1>${otp}</h1>`
      };
      transporter.sendMail(mailOptions, (err3) => {
        if (err3) {
          console.error("Error sending email:", err3);
          if (isAjax(req)) return res.status(500).json({ error: 'Failed to send OTP. Please try again later.' });
          return res.redirect('/index3.html?msg=' + encodeURIComponent('Failed to send OTP. Please try again later.'));
        }
        req.session.reset_email = email;
        if (isAjax(req)) return res.json({ success: true, redirect: '/otp.html' });
        res.redirect('/otp.html');
      });
    });
  });
});

app.post('/verify-otp', (req, res) => {
  const { otp } = req.body;
  const email = req.session.reset_email;
  if (!email) {
    if (isAjax(req)) return res.status(400).json({ error: 'Session expired. Start again.' });
    return res.redirect('/index3.html');
  }
  db.query("SELECT * FROM users WHERE email = ?", [email], (err, results) => {
    if (err) {
      if (isAjax(req)) return res.status(500).json({ error: 'Database error.' });
      return res.redirect('/otp.html?msg=' + encodeURIComponent('Database error.'));
    }
    if (!results.length) {
      if (isAjax(req)) return res.status(404).json({ error: 'User not found.' });
      return res.redirect('/otp.html?msg=' + encodeURIComponent('User not found.'));
    }
    const user = results[0];
    if (user.otp !== otp) {
      if (isAjax(req)) return res.status(400).json({ error: 'Incorrect OTP!' });
      return res.redirect('/otp.html?msg=' + encodeURIComponent('Incorrect OTP!'));
    }
    if (Date.now() > user.otp_expiry) {
      if (isAjax(req)) return res.status(400).json({ error: 'OTP expired!' });
      return res.redirect('/index3.html?msg=' + encodeURIComponent('OTP expired!'));
    }
    if (isAjax(req)) return res.json({ success: true, redirect: '/index4.html' });
    res.redirect('/index4.html');
  });
});

app.post('/reset-password', async (req, res) => {
  const { new_password, confirm_password } = req.body;
  const email = req.session.reset_email;
  if (!email) {
    if (isAjax(req)) return res.status(400).json({ error: 'Session expired. Start again.' });
    return res.redirect('/index3.html');
  }
  if (new_password !== confirm_password) {
    if (isAjax(req)) return res.status(400).json({ error: 'Passwords do not match!' });
    return res.redirect('/index4.html?msg=' + encodeURIComponent('Passwords do not match!'));
  }
  const hashed = await bcrypt.hash(new_password, 10);
  db.query("UPDATE users SET password = ?, otp = NULL, otp_expiry = NULL WHERE email = ?", [hashed, email], (err) => {
    if (err) {
      if (isAjax(req)) return res.status(500).json({ error: 'Error updating password.' });
      return res.redirect('/index4.html?msg=' + encodeURIComponent('Error updating password.'));
    }
    req.session.reset_email = null;
    if (isAjax(req)) return res.json({ success: true, redirect: '/login?msg=' + encodeURIComponent('Password reset successfully!') });
    res.redirect('/login?msg=' + encodeURIComponent('Password reset successfully!'));
  });
});

app.post('/contact', (req, res) => {
  const { firstName, lastName, email, mobile, message } = req.body;
  if (!firstName || !lastName || !email || !message) {
    if (isAjax(req)) return res.status(400).json({ error: 'Required Fields are missing!' });
    return res.redirect('/contactus.html?msg=' + encodeURIComponent('Required Fields are missing!'));
  }
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
  });
  const mailOptions = {
    from: email,
    to: process.env.CONTACT_RECEIVER || process.env.EMAIL_USER,
    subject: `Contact Us Message from ${firstName} ${lastName}`,
    html: `
      <h3>New message from Contact Us form</h3>
      <p><strong>Name:</strong> ${firstName} ${lastName}</p>
      <p><strong>Email:</strong> ${email}</p>
      <p><strong>Mobile:</strong> ${mobile}</p>
      <p><strong>Message:</strong><br>${message}</p>
    `
  };
  transporter.sendMail(mailOptions, (err, info) => {
    if (err) {
      console.error('Error sending contact email:', err);
      if (isAjax(req)) return res.status(500).json({ error: 'Failed to send message. Please try again later.' });
      return res.redirect('/contactus.html?msg=' + encodeURIComponent('Failed to send message. Please try again later.'));
    }
    console.log('Contact email sent:', info.response);
    if (isAjax(req)) return res.json({ success: true, message: 'Message Sent Successfully!' });
    return res.redirect('/contactus.html?msg=' + encodeURIComponent('Message Sent Successfully! '));
  });
});

// -----------------------
// Orders API (user)
// -----------------------
app.post('/api/orders', requireLogin, (req, res) => {
  try {
    const userId = req.currentUser && req.currentUser.id;
    const { name, phone, address, pickup_date, pickup_time, notes, items, order_type } = req.body;

    if (!Array.isArray(items) || items.length === 0) {
      return res.status(400).json({ error: 'Cart is empty' });
    }

    const normalizedItems = items.map(it => {
      const tray_type = determineTrayTypeFromItem(it);
      const price = parseFloat(it.price) || 0;
      const quantity = parseInt(it.quantity, 10) || 0;
      const subtotal = Number((price * quantity).toFixed(2));
      return {
        product_name: it.product_name,
        size: it.size,
        tray_type,
        price,
        quantity,
        subtotal
      };
    });

    const total = normalizedItems.reduce((s, it) => s + it.subtotal, 0);
    const sanitizedOrderType = sanitizeOrderType(order_type);
    const pickupDateIso = toISODate(pickup_date);
    const pickupTimeVal = pickup_time ? pickup_time : null;

    const orderSql = `INSERT INTO orders (user_id, total_amount, pickup_date, pickup_time, name, phone, address, notes, order_type, status)
                      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;
    const orderParams = [userId, total, pickupDateIso, pickupTimeVal, name, phone, address, notes || null, sanitizedOrderType, 'pending'];

    db.query(orderSql, orderParams, (err, result) => {
      if (err) {
        console.error('Insert order SQL error:', err);
        return res.status(500).json({ error: 'Failed to create order', detail: err.message });
      }
      const orderId = result.insertId;

      const itemSql = `INSERT INTO order_items (order_id, product_name, size, tray_type, price, quantity, subtotal)
                       VALUES ?`;
      const values = normalizedItems.map(it => [
        orderId,
        it.product_name,
        it.size,
        it.tray_type,
        it.price,
        it.quantity,
        it.subtotal
      ]);

      db.query(itemSql, [values], (err2) => {
        if (err2) {
          console.error('Insert items error', err2);
          db.query('DELETE FROM orders WHERE id = ?', [orderId], () => {
            return res.status(500).json({ error: 'Failed to save order items', detail: err2.message });
          });
        } else {
          return res.json({ success: true, orderId });
        }
      });
    });
  } catch (ex) {
    console.error('Unexpected error in /api/orders:', ex);
    return res.status(500).json({ error: 'Unexpected server error' });
  }
});

app.get('/api/orders', requireLogin, (req, res) => {
  const userId = req.currentUser.id;
  const ordersSql = `SELECT id, total_amount, pickup_date, pickup_time, name, phone, address, notes, status, created_at, order_type
                     FROM orders WHERE user_id = ? ORDER BY created_at DESC`;
  db.query(ordersSql, [userId], (err, orders) => {
    if (err) {
      console.error('Fetch orders error', err);
      return res.status(500).json({ error: 'Failed to fetch orders' });
    }
    if (!orders.length) return res.json({ orders: [] });

    const orderIds = orders.map(o => o.id);
    const itemsSql = `SELECT order_id, product_name, size, tray_type, price, quantity, subtotal FROM order_items WHERE order_id IN (?)`;
    db.query(itemsSql, [orderIds], (err2, items) => {
      if (err2) {
        console.error('Fetch items error', err2);
        return res.status(500).json({ error: 'Failed to fetch order items' });
      }
      const ordersWithItems = orders.map(o => ({
        ...o,
        items: items.filter(it => it.order_id === o.id)
      }));
      return res.json({ orders: ordersWithItems });
    });
  });
});

app.delete('/api/orders/:id', requireLogin, (req, res) => {
  const userId = req.currentUser.id;
  const orderId = req.params.id;
  db.query('SELECT id FROM orders WHERE id = ? AND user_id = ?', [orderId, userId], (err, rows) => {
    if (err) {
      console.error('Check order error', err);
      return res.status(500).json({ error: 'Failed to cancel order' });
    }
    if (!rows.length) return res.status(404).json({ error: 'Order not found' });

    db.query("UPDATE orders SET status = 'cancelled' WHERE id = ?", [orderId], (err2) => {
      if (err2) {
        console.error('Cancel order error', err2);
        return res.status(500).json({ error: 'Failed to cancel order' });
      }
      return res.json({ success: true });
    });
  });
});

app.post('/api/orders/reorder/:id', requireLogin, (req, res) => {
  const userId = req.currentUser.id;
  const oldOrderId = req.params.id;
  const { pickup_date, pickup_time } = req.body;

  db.query('SELECT * FROM orders WHERE id = ? AND user_id = ?', [oldOrderId, userId], (err, orders) => {
    if (err) {
      console.error('Fetch old order error', err);
      return res.status(500).json({ error: 'Failed to reorder' });
    }
    if (!orders.length) return res.status(404).json({ error: 'Order not found' });

    const oldOrder = orders[0];
    db.query('SELECT product_name, size, tray_type, price, quantity, subtotal FROM order_items WHERE order_id = ?', [oldOrderId], (err2, items) => {
      if (err2) {
        console.error('Fetch old items error', err2);
        return res.status(500).json({ error: 'Failed to reorder' });
      }
      const total = items.reduce((s, it) => s + parseFloat(it.subtotal), 0);
      const insertOrderSql = `INSERT INTO orders (user_id, total_amount, pickup_date, pickup_time, name, phone, address, notes, order_type, status)
                              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;
      const oldOrderType = oldOrder.order_type || 'pickup';
      const pickupDateToUse = pickup_date ? toISODate(pickup_date) : (oldOrder.pickup_date ? toISODate(oldOrder.pickup_date) : null);
      const pickupTimeToUse = pickup_time ? pickup_time : (oldOrder.pickup_time || null);

      db.query(insertOrderSql, [userId, total, pickupDateToUse, pickupTimeToUse, oldOrder.name, oldOrder.phone, oldOrder.address, oldOrder.notes, oldOrderType, 'pending'], (err3, result) => {
        if (err3) {
          console.error('Insert reorder error', err3);
          return res.status(500).json({ error: 'Failed to create reorder' });
        }
        const newOrderId = result.insertId;
        const values = items.map(it => [newOrderId, it.product_name, it.size, it.tray_type || 'full', it.price, it.quantity, it.subtotal]);
        db.query(`INSERT INTO order_items (order_id, product_name, size, tray_type, price, quantity, subtotal) VALUES ?`, [values], (err4) => {
          if (err4) {
            console.error('Insert reorder items error', err4);
            db.query('DELETE FROM orders WHERE id = ?', [newOrderId], () => {
              return res.status(500).json({ error: 'Failed to save reorder items' });
            });
          } else {
            return res.json({ success: true, orderId: newOrderId });
          }
        });
      });
    });
  });
});

// -----------------------
// Admin APIs (orders, inventory, users, reports)
// -----------------------
app.get('/admin/api/orders', requireLogin, requireAdmin, (req, res) => {
  const ordersSql = `SELECT o.id, o.user_id, o.total_amount, o.pickup_date, o.pickup_time, o.name, o.phone, o.address, o.notes, o.status, o.created_at, o.order_type,
                     u.username, u.email
                     FROM orders o
                     LEFT JOIN users u ON u.id = o.user_id
                     ORDER BY o.created_at DESC`;
  db.query(ordersSql, [], (err, orders) => {
    if (err) {
      console.error('Fetch admin orders error', err);
      return res.status(500).json({ error: 'Failed to fetch orders' });
    }
    if (!orders.length) return res.json({ orders: [] });
    const orderIds = orders.map(o => o.id);
    const itemsSql = `SELECT order_id, product_name, size, tray_type, price, quantity, subtotal FROM order_items WHERE order_id IN (?)`;
    db.query(itemsSql, [orderIds], (err2, items) => {
      if (err2) {
        console.error('Fetch admin items error', err2);
        return res.status(500).json({ error: 'Failed to fetch order items' });
      }
      const ordersWithItems = orders.map(o => ({
        ...o,
        items: items.filter(it => it.order_id === o.id)
      }));
      return res.json({ orders: ordersWithItems });
    });
  });
});

// Admin API: aggregated egg_orders data for reports
app.get('/admin/api/egg_orders', requireLogin, requireAdmin, (req, res) => {
  // last 30 days sales by day
  const salesByDaySql = `
  SELECT order_date AS date,
         COALESCE(SUM(amount),0) AS sales,
         COALESCE(SUM(quantity),0) AS qty,
         COALESCE(COUNT(DISTINCT id),0) AS orders_count
  FROM egg_orders
  WHERE order_date >= DATE_SUB(CURDATE(), INTERVAL 29 DAY)
  GROUP BY order_date
  ORDER BY order_date ASC
`;

  // top items in last 30 days
  const topItemsSql = `
    SELECT item,
           COALESCE(SUM(quantity),0) AS qty,
           COALESCE(SUM(amount),0) AS sales
    FROM egg_orders
    WHERE order_date >= DATE_SUB(CURDATE(), INTERVAL 29 DAY)
    GROUP BY item
    ORDER BY sales DESC
    LIMIT 10
  `;

  db.query(salesByDaySql, (err, salesRows) => {
    if (err) {
      console.error('Fetch egg_orders salesByDay error', err);
      return res.status(500).json({ error: 'Failed to fetch egg orders sales by day' });
    }
    db.query(topItemsSql, (err2, topRows) => {
      if (err2) {
        console.error('Fetch egg_orders topItems error', err2);
        return res.status(500).json({ error: 'Failed to fetch egg orders top items' });
      }
      // Normalize dates to YYYY-MM-DD strings
     const salesByDay = (salesRows || []).map(r => ({
      order_date: r.date ? (new Date(r.date)).toISOString().slice(0,10) : null,
      sales: Number(r.sales) || 0,
      qty: Number(r.qty) || 0,
      orders: Number(r.orders_count) || 0
    }));
      const topItems = (topRows || []).map(r => ({
        item: r.item,
        qty: Number(r.qty) || 0,
        sales: Number(r.sales) || 0
      }));
      return res.json({ salesByDay, topItems });
    });
  });
});

// Updated status handler: accept new statuses and keep backward compatibility
app.put('/admin/api/orders/:id/status', requireLogin, requireAdmin, (req, res) => {
  const orderId = req.params.id;
  const status = req.body && req.body.status;

  console.log('Admin status update request', { adminId: req.currentUser && req.currentUser.id, orderId, status });

  // allowed statuses (include 'placed' for backward compatibility)
  const allowed = ['pending', 'ongoing', 'completed', 'cancelled', 'placed'];

  if (!status || typeof status !== 'string' || !allowed.includes(status)) {
    console.warn('Invalid status value', { orderId, status });
    return res.status(400).json({ error: 'Invalid status' });
  }

  db.query('UPDATE orders SET status = ? WHERE id = ?', [status, orderId], (err, result) => {
    if (err) {
      console.error('Admin update status error', { orderId, status, err: err.message });
      return res.status(500).json({ error: 'Failed to update status', detail: err.message });
    }
    if (!result || result.affectedRows === 0) {
      console.warn('No order updated', { orderId });
      return res.status(404).json({ error: 'Order not found' });
    }
    console.log('Order status updated', { orderId, status, adminId: req.currentUser && req.currentUser.id });
    return res.json({ success: true, status });
  });
});

app.get('/admin/api/users', requireLogin, requireAdmin, (req, res) => {
  db.query('SELECT id, username, email, is_admin, created_at FROM users ORDER BY id ASC', [], (err, users) => {
    if (err) {
      console.error('Admin fetch users error', err);
      return res.status(500).json({ error: 'Failed to fetch users' });
    }
    return res.json({ users });
  });
});

// Inventory CRUD (admin) - basic endpoints (create, update, delete, list)
app.get('/admin/api/inventory', requireLogin, requireAdmin, (req, res) => {
  db.query('SELECT id, product_name, sku, size, price, stock FROM inventory ORDER BY id ASC', [], (err, rows) => {
    if (err) {
      console.error('Fetch inventory error', err);
      return res.status(500).json({ error: 'Failed to fetch inventory' });
    }
    return res.json({ inventory: rows });
  });
});

app.post('/admin/api/inventory', requireLogin, requireAdmin, (req, res) => {
  const { product_name, sku, size, price, stock } = req.body;
  if (!product_name) return res.status(400).json({ error: 'Product name required' });
  db.query('INSERT INTO inventory (product_name, sku, size, price, stock) VALUES (?, ?, ?, ?, ?)', [product_name, sku || null, size || null, Number(price) || 0, Number(stock) || 0], (err, result) => {
    if (err) {
      console.error('Create inventory error', err);
      return res.status(500).json({ error: 'Failed to create inventory item' });
    }
    return res.json({ success: true, id: result.insertId });
  });
});

app.put('/admin/api/inventory/:id', requireLogin, requireAdmin, (req, res) => {
  const id = req.params.id;
  const { product_name, sku, size, price, stock } = req.body;
  db.query('UPDATE inventory SET product_name = ?, sku = ?, size = ?, price = ?, stock = ? WHERE id = ?', [product_name, sku || null, size || null, Number(price) || 0, Number(stock) || 0, id], (err, result) => {
    if (err) {
      console.error('Update inventory error', err);
      return res.status(500).json({ error: 'Failed to update inventory item' });
    }
    return res.json({ success: true, affectedRows: result.affectedRows });
  });
});

app.delete('/admin/api/inventory/:id', requireLogin, requireAdmin, (req, res) => {
  const id = req.params.id;
  db.query('DELETE FROM inventory WHERE id = ?', [id], (err, result) => {
    if (err) {
      console.error('Delete inventory error', err);
      return res.status(500).json({ error: 'Failed to delete inventory item' });
    }
    return res.json({ success: true, affectedRows: result.affectedRows });
  });
});

// Reports endpoint (basic sales report)
app.get('/admin/api/reports/sales', requireLogin, requireAdmin, (req, res) => {
  const totalsSql = `SELECT COUNT(*) AS orders_count, COALESCE(SUM(total_amount),0) AS total_sales FROM orders`;
  const byDaySql = `SELECT DATE(created_at) AS day, COUNT(*) AS orders, COALESCE(SUM(total_amount),0) AS sales
                    FROM orders GROUP BY DATE(created_at) ORDER BY DATE(created_at) DESC LIMIT 30`;
  const byProductSql = `SELECT oi.product_name, SUM(oi.quantity) AS qty_sold, COALESCE(SUM(oi.subtotal),0) AS sales
                        FROM order_items oi GROUP BY oi.product_name ORDER BY sales DESC LIMIT 10`;

  db.query(totalsSql, [], (err, totalsRows) => {
    if (err) {
      console.error('Reports totals error', err);
      return res.status(500).json({ error: 'Failed to fetch reports' });
    }
    db.query(byDaySql, [], (err2, byDayRows) => {
      if (err2) {
        console.error('Reports byDay error', err2);
        return res.status(500).json({ error: 'Failed to fetch reports' });
      }
      db.query(byProductSql, [], (err3, byProductRows) => {
        if (err3) {
          console.error('Reports byProduct error', err3);
          return res.status(500).json({ error: 'Failed to fetch reports' });
        }
        return res.json({
          totals: totalsRows[0] || { orders_count: 0, total_sales: 0 },
          byDay: byDayRows || [],
          byProduct: byProductRows || []
        });
      });
    });
  });
});

// -----------------------
// Start server
// -----------------------
app.listen(PORT, () => console.log(`✅ Server running on http://localhost:${PORT}`));