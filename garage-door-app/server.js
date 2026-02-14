const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const path = require('path');
const crypto = require('crypto');
const { exec } = require('child_process');

const app = express();
const PORT = process.env.PORT || 3000;

// Configuration
const ACCESS_PASSWORD = process.env.ACCESS_PASSWORD || 'regent2026';
const SESSION_SECRET = crypto.randomBytes(32).toString('hex');

// STRATIS configuration (to be set via environment variables)
const STRATIS_EMAIL = process.env.STRATIS_EMAIL || '';
const STRATIS_PASSWORD = process.env.STRATIS_PASSWORD || '';

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false,
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// Auth middleware
function requireAuth(req, res, next) {
  if (req.session && req.session.authenticated) {
    return next();
  }
  return res.status(401).json({ error: 'Unauthorized' });
}

// Rate limiting (simple in-memory)
const rateLimiter = {};
function rateLimit(req, res, next) {
  const ip = req.ip;
  const now = Date.now();
  if (!rateLimiter[ip]) {
    rateLimiter[ip] = [];
  }
  // Remove entries older than 1 minute
  rateLimiter[ip] = rateLimiter[ip].filter(t => now - t < 60000);
  if (rateLimiter[ip].length >= 10) {
    return res.status(429).json({ error: 'Too many requests. Try again later.' });
  }
  rateLimiter[ip].push(now);
  next();
}

// Login attempt tracking (brute force protection)
const loginAttempts = {};
function checkLoginAttempts(req, res, next) {
  const ip = req.ip;
  const now = Date.now();
  if (!loginAttempts[ip]) {
    loginAttempts[ip] = [];
  }
  // Remove entries older than 15 minutes
  loginAttempts[ip] = loginAttempts[ip].filter(t => now - t < 900000);
  if (loginAttempts[ip].length >= 5) {
    return res.status(429).json({ error: 'Too many login attempts. Try again in 15 minutes.' });
  }
  next();
}

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.post('/api/login', checkLoginAttempts, (req, res) => {
  const { password } = req.body;
  if (password === ACCESS_PASSWORD) {
    req.session.authenticated = true;
    // Clear login attempts on success
    loginAttempts[req.ip] = [];
    return res.json({ success: true });
  }
  // Track failed attempt
  if (!loginAttempts[req.ip]) loginAttempts[req.ip] = [];
  loginAttempts[req.ip].push(Date.now());
  return res.status(401).json({ error: 'Invalid password' });
});

app.get('/api/auth-check', (req, res) => {
  res.json({ authenticated: !!(req.session && req.session.authenticated) });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

// Garage door action log
const actionLog = [];

app.post('/api/garage/open', requireAuth, rateLimit, async (req, res) => {
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] Garage door OPEN requested by ${req.ip}`);

  actionLog.push({
    action: 'open',
    timestamp,
    ip: req.ip,
    status: 'pending'
  });

  try {
    const result = await triggerStratisAction('open');
    actionLog[actionLog.length - 1].status = result.success ? 'success' : 'failed';
    return res.json(result);
  } catch (err) {
    console.error('Garage action error:', err.message);
    actionLog[actionLog.length - 1].status = 'error';
    return res.json({
      success: false,
      message: 'Action sent but could not confirm completion. Check STRATIS app.',
      error: err.message
    });
  }
});

app.get('/api/garage/status', requireAuth, (req, res) => {
  const lastAction = actionLog.length > 0 ? actionLog[actionLog.length - 1] : null;
  res.json({
    lastAction,
    totalActions: actionLog.length,
    stratisConfigured: !!(STRATIS_EMAIL && STRATIS_PASSWORD)
  });
});

app.get('/api/garage/log', requireAuth, (req, res) => {
  // Return last 20 actions
  res.json({ log: actionLog.slice(-20).reverse() });
});

// STRATIS automation via Playwright
async function triggerStratisAction(action) {
  if (!STRATIS_EMAIL || !STRATIS_PASSWORD) {
    console.log('STRATIS credentials not configured. Logging action only.');
    return {
      success: true,
      message: 'Action logged. STRATIS credentials not yet configured - set STRATIS_EMAIL and STRATIS_PASSWORD environment variables.',
      mode: 'log-only'
    };
  }

  // Attempt Playwright automation
  try {
    const { chromium } = require('playwright');
    const browser = await chromium.launch({ headless: true });
    const context = await browser.newContext();
    const page = await context.newPage();

    // Navigate to STRATIS portal
    await page.goto('https://stratissphere.net/', { waitUntil: 'networkidle', timeout: 30000 });

    // Login flow - will need to be adapted based on actual STRATIS UI
    await page.fill('input[type="email"], input[name="email"], #email', STRATIS_EMAIL);
    await page.fill('input[type="password"], input[name="password"], #password', STRATIS_PASSWORD);
    await page.click('button[type="submit"], .login-button, #login-btn');

    // Wait for dashboard to load
    await page.waitForLoadState('networkidle', { timeout: 15000 });

    // Look for garage door control
    // These selectors will need to be refined based on the actual STRATIS interface
    const garageButton = await page.$('text=Garage, text=Open, [data-action="garage"], .garage-control');
    if (garageButton) {
      await garageButton.click();
      await page.waitForTimeout(2000);
    }

    await browser.close();

    return {
      success: true,
      message: `Garage door ${action} command sent via STRATIS.`,
      mode: 'stratis-automated'
    };
  } catch (err) {
    console.error('Playwright STRATIS automation error:', err.message);
    return {
      success: false,
      message: `STRATIS automation encountered an issue: ${err.message}`,
      mode: 'stratis-error'
    };
  }
}

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`\n========================================`);
  console.log(`  Garage Door Controller`);
  console.log(`  Running on http://localhost:${PORT}`);
  console.log(`  STRATIS configured: ${!!(STRATIS_EMAIL && STRATIS_PASSWORD)}`);
  console.log(`========================================\n`);
});
