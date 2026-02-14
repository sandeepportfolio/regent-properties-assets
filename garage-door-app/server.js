const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// ===== CONFIGURATION =====
const ACCESS_PASSWORD = process.env.ACCESS_PASSWORD || 'regent2026';
const SESSION_SECRET = crypto.randomBytes(32).toString('hex');
const LOG_DIR = path.join(__dirname, 'logs');
const SCREENSHOT_DIR = path.join(__dirname, 'logs', 'screenshots');

// STRATIS configuration
const STRATIS_EMAIL = process.env.STRATIS_EMAIL || '';
const STRATIS_PASSWORD = process.env.STRATIS_PASSWORD || '';

// Ensure log directories exist
if (!fs.existsSync(LOG_DIR)) fs.mkdirSync(LOG_DIR, { recursive: true });
if (!fs.existsSync(SCREENSHOT_DIR)) fs.mkdirSync(SCREENSHOT_DIR, { recursive: true });

// ===== LOGGING SYSTEM =====
const systemLog = [];
const MAX_LOG_ENTRIES = 500;

function log(level, category, message, meta = {}) {
  const entry = {
    id: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    level,     // info, warn, error, debug, action
    category,  // auth, garage, system, stratis
    message,
    meta
  };
  systemLog.unshift(entry);
  if (systemLog.length > MAX_LOG_ENTRIES) systemLog.length = MAX_LOG_ENTRIES;

  // Console output with color
  const colors = { info: '\x1b[36m', warn: '\x1b[33m', error: '\x1b[31m', debug: '\x1b[90m', action: '\x1b[32m' };
  const c = colors[level] || '\x1b[0m';
  console.log(`${c}[${entry.timestamp}] [${level.toUpperCase()}] [${category}] ${message}\x1b[0m`, Object.keys(meta).length ? meta : '');

  // Append to log file
  const logLine = JSON.stringify(entry) + '\n';
  fs.appendFileSync(path.join(LOG_DIR, 'server.log'), logLine);

  return entry;
}

// ===== MIDDLEWARE =====
app.set('trust proxy', true);
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
    maxAge: 24 * 60 * 60 * 1000
  }
}));

// Request logger
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    if (!req.path.startsWith('/api/health')) {
      log('debug', 'system', `${req.method} ${req.path} ${res.statusCode} (${duration}ms)`, {
        ip: req.ip,
        userAgent: req.get('User-Agent')?.substring(0, 80)
      });
    }
  });
  next();
});

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));
// Serve screenshots
app.use('/screenshots', express.static(SCREENSHOT_DIR));

// ===== AUTH SYSTEM =====
const loginAttempts = {};  // ip -> [{time, success}]
const activeSessions = {}; // sessionId -> {ip, loginTime, lastActive, fingerprint}

function requireAuth(req, res, next) {
  if (req.session && req.session.authenticated) {
    // Update last active
    if (activeSessions[req.session.id]) {
      activeSessions[req.session.id].lastActive = new Date().toISOString();
    }
    return next();
  }
  log('warn', 'auth', 'Unauthorized API access attempt', { ip: req.ip, path: req.path });
  return res.status(401).json({
    error: 'Unauthorized',
    hint: 'Session expired or not authenticated. Please log in again.'
  });
}

function checkBruteForce(req, res, next) {
  const ip = req.ip;
  const now = Date.now();
  if (!loginAttempts[ip]) loginAttempts[ip] = [];

  // Clean old entries (15 min window)
  loginAttempts[ip] = loginAttempts[ip].filter(a => now - a.time < 900000);

  const failures = loginAttempts[ip].filter(a => !a.success).length;
  if (failures >= 5) {
    const oldestFail = loginAttempts[ip].find(a => !a.success);
    const unlockAt = new Date(oldestFail.time + 900000).toISOString();
    log('warn', 'auth', 'Login blocked - too many failures', { ip, failures, unlockAt });
    return res.status(429).json({
      error: 'Too many failed attempts. Account temporarily locked.',
      unlockAt,
      remainingMinutes: Math.ceil((oldestFail.time + 900000 - now) / 60000)
    });
  }
  next();
}

function rateLimit(req, res, next) {
  const ip = req.ip;
  const now = Date.now();
  const key = `${ip}:${req.path}`;
  if (!rateLimits[key]) rateLimits[key] = [];
  rateLimits[key] = rateLimits[key].filter(t => now - t < 60000);
  if (rateLimits[key].length >= 10) {
    log('warn', 'system', 'Rate limit exceeded', { ip, path: req.path });
    return res.status(429).json({ error: 'Rate limit exceeded. Max 10 requests per minute.' });
  }
  rateLimits[key].push(now);
  next();
}
const rateLimits = {};

// ===== API ROUTES =====

// Health check (no auth needed)
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    uptime: Math.floor(process.uptime()),
    timestamp: new Date().toISOString(),
    stratisConfigured: !!(STRATIS_EMAIL && STRATIS_PASSWORD),
    version: '2.0.0'
  });
});

// Login
app.post('/api/login', checkBruteForce, (req, res) => {
  const { password, fingerprint } = req.body;
  const ip = req.ip;
  const userAgent = req.get('User-Agent') || 'unknown';

  if (!password) {
    return res.status(400).json({ error: 'Password is required' });
  }

  if (password === ACCESS_PASSWORD) {
    req.session.authenticated = true;
    req.session.loginTime = new Date().toISOString();
    req.session.ip = ip;

    // Track login attempt (success)
    if (!loginAttempts[ip]) loginAttempts[ip] = [];
    loginAttempts[ip].push({ time: Date.now(), success: true });

    // Track active session
    activeSessions[req.session.id] = {
      ip,
      loginTime: req.session.loginTime,
      lastActive: req.session.loginTime,
      userAgent: userAgent.substring(0, 100),
      fingerprint: fingerprint || 'none'
    };

    log('action', 'auth', 'Login successful', { ip, userAgent: userAgent.substring(0, 60) });
    return res.json({
      success: true,
      session: {
        expiresIn: '24 hours',
        loginTime: req.session.loginTime
      }
    });
  }

  // Failed login
  if (!loginAttempts[ip]) loginAttempts[ip] = [];
  loginAttempts[ip].push({ time: Date.now(), success: false });
  const failures = loginAttempts[ip].filter(a => !a.success).length;
  const remaining = 5 - failures;

  log('warn', 'auth', 'Login failed', { ip, attemptsRemaining: remaining });
  return res.status(401).json({
    error: 'Invalid access code',
    attemptsRemaining: Math.max(0, remaining),
    hint: remaining <= 2 ? `${remaining} attempts remaining before temporary lockout` : undefined
  });
});

// Auth check
app.get('/api/auth-check', (req, res) => {
  const authed = !!(req.session && req.session.authenticated);
  res.json({
    authenticated: authed,
    session: authed ? {
      loginTime: req.session.loginTime,
      ip: req.session.ip
    } : null
  });
});

// Identity verification - proves who you are
app.get('/api/identity', requireAuth, (req, res) => {
  const sessionInfo = activeSessions[req.session.id] || {};
  res.json({
    verified: true,
    session: {
      id: req.session.id.substring(0, 8) + '...',
      loginTime: req.session.loginTime,
      loginIP: req.session.ip,
      currentIP: req.ip,
      ipMatch: req.session.ip === req.ip,
      userAgent: sessionInfo.userAgent,
      lastActive: sessionInfo.lastActive
    },
    security: {
      ipChanged: req.session.ip !== req.ip,
      warning: req.session.ip !== req.ip ? 'IP address changed since login. This could indicate session hijacking.' : null
    }
  });
});

// Logout
app.post('/api/logout', (req, res) => {
  const sid = req.session.id;
  delete activeSessions[sid];
  req.session.destroy();
  log('info', 'auth', 'User logged out', { ip: req.ip });
  res.json({ success: true });
});

// Active sessions (admin visibility)
app.get('/api/sessions', requireAuth, (req, res) => {
  const sessions = Object.entries(activeSessions).map(([id, s]) => ({
    id: id.substring(0, 8) + '...',
    ...s,
    isCurrent: id === req.session.id
  }));
  res.json({ sessions, total: sessions.length });
});

// ===== GARAGE CONTROL =====
const actionLog = [];

app.post('/api/garage/open', requireAuth, rateLimit, async (req, res) => {
  const actionId = crypto.randomUUID().substring(0, 8);
  const entry = {
    id: actionId,
    action: 'open',
    timestamp: new Date().toISOString(),
    ip: req.ip,
    sessionId: req.session.id.substring(0, 8),
    status: 'pending',
    steps: [],
    screenshots: [],
    duration: 0
  };

  actionLog.unshift(entry);
  log('action', 'garage', `Garage OPEN requested [${actionId}]`, { ip: req.ip });

  const startTime = Date.now();

  try {
    // Step tracking
    entry.steps.push({ step: 'request_received', time: new Date().toISOString(), status: 'ok' });

    const result = await triggerStratisAction(actionId, entry);
    entry.status = result.success ? 'success' : 'failed';
    entry.duration = Date.now() - startTime;
    entry.result = result;

    log(result.success ? 'action' : 'error', 'garage',
      `Garage action [${actionId}] ${result.success ? 'completed' : 'failed'} in ${entry.duration}ms`,
      { mode: result.mode }
    );

    return res.json({
      ...result,
      actionId,
      duration: entry.duration,
      steps: entry.steps,
      screenshots: entry.screenshots
    });
  } catch (err) {
    entry.status = 'error';
    entry.duration = Date.now() - startTime;
    entry.error = err.message;
    entry.steps.push({ step: 'error', time: new Date().toISOString(), error: err.message });

    log('error', 'garage', `Garage action [${actionId}] error: ${err.message}`, { stack: err.stack?.substring(0, 200) });

    return res.json({
      success: false,
      message: 'Action failed. See debug dashboard for details.',
      actionId,
      error: err.message,
      steps: entry.steps,
      screenshots: entry.screenshots
    });
  }
});

app.get('/api/garage/log', requireAuth, (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 20, 100);
  res.json({ log: actionLog.slice(0, limit) });
});

app.get('/api/garage/action/:id', requireAuth, (req, res) => {
  const action = actionLog.find(a => a.id === req.params.id);
  if (!action) return res.status(404).json({ error: 'Action not found' });
  res.json(action);
});

// ===== DEBUG DASHBOARD =====
app.get('/api/debug/logs', requireAuth, (req, res) => {
  const level = req.query.level;
  const category = req.query.category;
  const limit = Math.min(parseInt(req.query.limit) || 50, 200);

  let filtered = systemLog;
  if (level) filtered = filtered.filter(e => e.level === level);
  if (category) filtered = filtered.filter(e => e.category === category);

  res.json({
    logs: filtered.slice(0, limit),
    total: filtered.length,
    filters: { level, category, limit }
  });
});

app.get('/api/debug/system', requireAuth, (req, res) => {
  res.json({
    uptime: Math.floor(process.uptime()),
    memory: process.memoryUsage(),
    nodeVersion: process.version,
    platform: process.platform,
    env: {
      stratisConfigured: !!(STRATIS_EMAIL && STRATIS_PASSWORD),
      port: PORT,
      logEntries: systemLog.length,
      actionCount: actionLog.length,
      activeSessions: Object.keys(activeSessions).length
    },
    loginAttempts: Object.entries(loginAttempts).map(([ip, attempts]) => ({
      ip: ip.substring(0, ip.lastIndexOf('.')) + '.*',
      total: attempts.length,
      failures: attempts.filter(a => !a.success).length,
      lastAttempt: attempts.length > 0 ? new Date(Math.max(...attempts.map(a => a.time))).toISOString() : null
    }))
  });
});

// ===== STRATIS AUTOMATION =====
async function triggerStratisAction(actionId, entry) {
  entry.steps.push({ step: 'checking_config', time: new Date().toISOString(), status: 'ok' });

  if (!STRATIS_EMAIL || !STRATIS_PASSWORD) {
    entry.steps.push({
      step: 'stratis_not_configured',
      time: new Date().toISOString(),
      status: 'skipped',
      note: 'STRATIS_EMAIL and STRATIS_PASSWORD env vars not set'
    });
    log('info', 'stratis', `Action [${actionId}] logged (STRATIS not configured)`);
    return {
      success: true,
      message: 'Action logged successfully. STRATIS automation not yet configured. Set STRATIS_EMAIL and STRATIS_PASSWORD environment variables to enable.',
      mode: 'log-only'
    };
  }

  // Playwright automation with full step tracking and screenshots
  entry.steps.push({ step: 'launching_browser', time: new Date().toISOString(), status: 'ok' });

  let browser;
  try {
    const { chromium } = require('playwright');
    browser = await chromium.launch({ headless: true });
    const context = await browser.newContext({
      viewport: { width: 1280, height: 720 },
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    });
    const page = await context.newPage();

    entry.steps.push({ step: 'browser_launched', time: new Date().toISOString(), status: 'ok' });

    // Screenshot helper
    const takeScreenshot = async (name) => {
      try {
        const filename = `${actionId}-${name}-${Date.now()}.png`;
        const filepath = path.join(SCREENSHOT_DIR, filename);
        await page.screenshot({ path: filepath, fullPage: true });
        entry.screenshots.push({ name, filename, url: `/screenshots/${filename}`, time: new Date().toISOString() });
        log('debug', 'stratis', `Screenshot taken: ${name}`, { actionId });
      } catch (e) {
        log('warn', 'stratis', `Screenshot failed: ${name}: ${e.message}`);
      }
    };

    // Navigate to STRATIS
    entry.steps.push({ step: 'navigating_to_stratis', time: new Date().toISOString(), status: 'ok' });
    await page.goto('https://stratissphere.net/', { waitUntil: 'networkidle', timeout: 30000 });
    await takeScreenshot('01-login-page');

    entry.steps.push({ step: 'page_loaded', time: new Date().toISOString(), status: 'ok', url: page.url() });

    // Fill login credentials
    entry.steps.push({ step: 'entering_credentials', time: new Date().toISOString(), status: 'ok' });
    await page.fill('input[type="email"], input[name="email"], #email, input[name="username"]', STRATIS_EMAIL);
    await page.fill('input[type="password"], input[name="password"], #password', STRATIS_PASSWORD);
    await takeScreenshot('02-credentials-entered');

    // Submit login
    entry.steps.push({ step: 'submitting_login', time: new Date().toISOString(), status: 'ok' });
    await page.click('button[type="submit"], .login-button, #login-btn, button:has-text("Sign In"), button:has-text("Log In")');

    // Wait for navigation
    await page.waitForLoadState('networkidle', { timeout: 15000 });
    await takeScreenshot('03-after-login');

    entry.steps.push({ step: 'login_submitted', time: new Date().toISOString(), status: 'ok', url: page.url() });

    // Check for login errors
    const errorEl = await page.$('.error, .alert-error, .error-message, [class*="error"]');
    if (errorEl) {
      const errorText = await errorEl.textContent();
      entry.steps.push({ step: 'login_error_detected', time: new Date().toISOString(), status: 'error', error: errorText });
      await takeScreenshot('03b-login-error');
      await browser.close();
      return {
        success: false,
        message: `STRATIS login failed: ${errorText}`,
        mode: 'stratis-login-error'
      };
    }

    // Look for garage door control
    entry.steps.push({ step: 'finding_garage_control', time: new Date().toISOString(), status: 'ok' });

    const garageSelectors = [
      'text=Garage', 'text=garage', 'text=GARAGE',
      'text=Open', 'text=Unlock',
      '[data-action="garage"]', '.garage-control', '.door-control',
      'button:has-text("Garage")', 'a:has-text("Garage")',
      'button:has-text("Open")', 'button:has-text("Access")'
    ];

    let garageButton = null;
    for (const selector of garageSelectors) {
      try {
        garageButton = await page.$(selector);
        if (garageButton) {
          entry.steps.push({ step: 'garage_button_found', time: new Date().toISOString(), status: 'ok', selector });
          break;
        }
      } catch (e) { /* try next selector */ }
    }

    if (garageButton) {
      await takeScreenshot('04-before-click');
      await garageButton.click();
      await page.waitForTimeout(3000);
      await takeScreenshot('05-after-click');
      entry.steps.push({ step: 'garage_button_clicked', time: new Date().toISOString(), status: 'ok' });
    } else {
      await takeScreenshot('04-no-button-found');
      entry.steps.push({ step: 'garage_button_not_found', time: new Date().toISOString(), status: 'warn', note: 'Could not find garage control button on page' });

      // Log page content for debugging
      const pageTitle = await page.title();
      const bodyText = await page.evaluate(() => document.body.innerText.substring(0, 500));
      entry.steps.push({ step: 'page_content_logged', time: new Date().toISOString(), pageTitle, bodyPreview: bodyText });
    }

    await browser.close();
    entry.steps.push({ step: 'browser_closed', time: new Date().toISOString(), status: 'ok' });

    return {
      success: true,
      message: garageButton ? 'Garage door open command sent via STRATIS.' : 'Logged in to STRATIS but could not find garage button. Check screenshots.',
      mode: garageButton ? 'stratis-automated' : 'stratis-partial',
      screenshots: entry.screenshots
    };

  } catch (err) {
    if (browser) {
      try { await browser.close(); } catch (e) {}
    }
    entry.steps.push({ step: 'automation_error', time: new Date().toISOString(), status: 'error', error: err.message });
    log('error', 'stratis', `Automation error [${actionId}]: ${err.message}`);
    return {
      success: false,
      message: `STRATIS automation error: ${err.message}`,
      mode: 'stratis-error',
      screenshots: entry.screenshots
    };
  }
}

// ===== START SERVER =====
app.listen(PORT, '0.0.0.0', () => {
  log('info', 'system', `Server started on port ${PORT}`);
  log('info', 'system', `STRATIS configured: ${!!(STRATIS_EMAIL && STRATIS_PASSWORD)}`);
  console.log(`\n${'='.repeat(50)}`);
  console.log(`  Regent Properties - Garage Door Controller v2.0`);
  console.log(`  http://localhost:${PORT}`);
  console.log(`  STRATIS: ${STRATIS_EMAIL ? 'Configured' : 'Not configured'}`);
  console.log(`${'='.repeat(50)}\n`);
});
