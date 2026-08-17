const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const admin = require('firebase-admin');
const { getDatabase } = require('firebase-admin/database');

const app = express();
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
const PUBLIC_DIR = path.join(__dirname, 'public');

// If you deploy behind a reverse proxy (nginx, caddy, etc.) this makes
// req.ip / rate limiting see the real client IP instead of the proxy's.
app.set('trust proxy', 1);

// ============ SECURITY HARDENING ============
app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: true,
    directives: {
      'default-src': ["'self'"],
      'script-src': ["'self'", "'unsafe-inline'", 'https://cdnjs.cloudflare.com'],
      'style-src': ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      'font-src': ["'self'", 'https://fonts.gstatic.com', 'data:'],
      'img-src': ["'self'", 'data:', 'blob:'],
      'media-src': ["'self'", 'blob:'],
      'connect-src': ["'self'"],
      'frame-ancestors': ["'none'"],
      'form-action': ["'self'"],
      'base-uri': ["'self'"],
      'object-src': ["'none'"],
      // Keep plain-HTTP local dev working; production should be HTTPS.
      'upgrade-insecure-requests': null
    }
  },
  crossOriginEmbedderPolicy: false
}));
app.use(compression()); // gzip text responses — big win for page/API payloads at scale

// ============ RATE LIMITING ============
// Per-IP. Window = 15 minutes. Tuned so thousands of *distinct* users are
// fine (each IP gets its own bucket) while a single abuser gets throttled.
const PUBLIC_API_LIMIT = 600;
const ADMIN_API_LIMIT = 300;
const LOGIN_LIMIT = 10;

const publicApiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: PUBLIC_API_LIMIT,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: 'Too many requests. Please try again later.' }
});
const adminApiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: ADMIN_API_LIMIT,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: 'Too many requests. Please try again later.' }
});
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: LOGIN_LIMIT,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: 'Too many login attempts. Please wait a few minutes and try again.' }
});

app.use(cookieParser());
app.use(express.json({ limit: '200kb' }));

// ============ FILE UPLOADS (course videos + thumbnails) ============
const UPLOAD_ROOT = path.join(PUBLIC_DIR, 'uploads');
const VIDEO_DIR = path.join(UPLOAD_ROOT, 'videos');
const THUMB_DIR = path.join(UPLOAD_ROOT, 'thumbnails');
fs.mkdirSync(VIDEO_DIR, { recursive: true });
fs.mkdirSync(THUMB_DIR, { recursive: true });

const MAX_VIDEO_BYTES = 500 * 1024 * 1024;  // 500 MB per course video
const MAX_THUMB_BYTES = 2 * 1024 * 1024;    // 2 MB per thumbnail
const VIDEO_EXTS = ['.mp4', '.webm', '.ogv', '.mov'];
const IMAGE_EXTS = ['.jpg', '.jpeg', '.png', '.webp'];
const VIDEO_MIME_TO_EXT = { 'video/mp4': '.mp4', 'video/webm': '.webm', 'video/ogg': '.ogv', 'video/quicktime': '.mov' };
const IMAGE_MIME_TO_EXT = { 'image/jpeg': '.jpg', 'image/png': '.png', 'image/webp': '.webp' };

function safeExtFor(file) {
  if (file.fieldname === 'video') {
    if (VIDEO_MIME_TO_EXT[file.mimetype]) return VIDEO_MIME_TO_EXT[file.mimetype];
    const ext = path.extname(file.originalname || '').toLowerCase();
    return VIDEO_EXTS.includes(ext) ? ext : '.mp4';
  }
  if (file.fieldname === 'thumbnail') {
    if (IMAGE_MIME_TO_EXT[file.mimetype]) return IMAGE_MIME_TO_EXT[file.mimetype];
    const ext = path.extname(file.originalname || '').toLowerCase();
    return IMAGE_EXTS.includes(ext) ? ext : '.jpg';
  }
  return '';
}

const upload = multer({
  storage: multer.diskStorage({
    destination: function (req, file, cb) {
      cb(null, file.fieldname === 'thumbnail' ? THUMB_DIR : VIDEO_DIR);
    },
    // Random 128-bit hex filename — no user-supplied names, so no path
    // traversal and no collisions. (Also makes the files non-guessable.)
    filename: function (req, file, cb) {
      cb(null, crypto.randomBytes(16).toString('hex') + safeExtFor(file));
    }
  }),
  fileFilter: function (req, file, cb) {
    const ext = path.extname(file.originalname || '').toLowerCase();
    if (file.fieldname === 'video' && (VIDEO_MIME_TO_EXT[file.mimetype] || VIDEO_EXTS.includes(ext))) {
      return cb(null, true);
    }
    if (file.fieldname === 'thumbnail' && (IMAGE_MIME_TO_EXT[file.mimetype] || IMAGE_EXTS.includes(ext))) {
      return cb(null, true);
    }
    return cb(new Error('Unsupported file type for field "' + file.fieldname + '"'));
  },
  limits: { fileSize: MAX_VIDEO_BYTES, files: 2 }
});

// Remove files multer already wrote when a later validation step fails.
function removeUploadedFiles(req) {
  if (!req.files) return;
  Object.keys(req.files).forEach(function (key) {
    (req.files[key] || []).forEach(function (f) {
      fs.unlink(f.path, function () { /* best-effort */ });
    });
  });
}

// Delete a stored file referenced by a public URL (only ever inside uploads/).
function deleteFileForUrl(url) {
  if (typeof url !== 'string' || !url.startsWith('/uploads/')) return;
  const full = path.resolve(PUBLIC_DIR, url.replace(/^\//, ''));
  if (!full.startsWith(path.resolve(UPLOAD_ROOT) + path.sep)) return; // no escaping uploads
  fs.unlink(full, function () { /* best-effort */ });
}

// ============ ADMIN CREDENTIALS ============
// Plaintext password is NEVER stored. admin-auth.json holds only the salted
// scrypt hash + signing secret, generated by `node _setup_admin.js`.
let adminCreds;
try {
  adminCreds = require('./admin-auth.json');
} catch (err) {
  console.error('❌ admin-auth.json is missing.');
  console.error('   Run `node _setup_admin.js` once to create the admin login.');
  process.exit(1);
}
if (!adminCreds.username || !adminCreds.passwordHash || !adminCreds.salt || !adminCreds.cookieSecret) {
  console.error('❌ admin-auth.json is incomplete. Delete it and run `node _setup_admin.js` again.');
  process.exit(1);
}

function verifyPassword(password) {
  if (typeof password !== 'string' || password.length === 0) return false;
  try {
    const hash = crypto.scryptSync(password, Buffer.from(adminCreds.salt, 'hex'), adminCreds.keylen, {
      N: adminCreds.cost || 16384,
      r: adminCreds.blockSize || 8,
      p: adminCreds.parallelization || 1
    });
    const expected = Buffer.from(adminCreds.passwordHash, 'hex');
    return hash.length === expected.length && crypto.timingSafeEqual(hash, expected);
  } catch (err) {
    return false;
  }
}

const ADMIN_SESSION_HOURS = 12;

// Stateless HMAC-signed admin session token: base64url(payload).base64url(sig)
function signAdminToken() {
  const payloadB64 = Buffer.from(JSON.stringify({ exp: Date.now() + ADMIN_SESSION_HOURS * 3600 * 1000 }), 'utf8').toString('base64url');
  const sig = crypto.createHmac('sha256', adminCreds.cookieSecret).update(payloadB64).digest('base64url');
  return payloadB64 + '.' + sig;
}

function verifyAdminToken(token) {
  if (typeof token !== 'string' || token.indexOf('.') === -1) return false;
  const parts = token.split('.');
  if (parts.length !== 2) return false;
  const payloadB64 = parts[0];
  const sigB64 = parts[1];
  const expected = crypto.createHmac('sha256', adminCreds.cookieSecret).update(payloadB64).digest('base64url');
  const a = Buffer.from(sigB64);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return false;
  try {
    const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
    return typeof payload.exp === 'number' && Date.now() < payload.exp;
  } catch (err) {
    return false;
  }
}

function adminCookieOptions(req) {
  return {
    httpOnly: true,                        // not readable by JS — kills XSS cookie theft
    secure: req.secure || req.headers['x-forwarded-proto'] === 'https',
    sameSite: 'lax',                       // blocks cross-site CSRF sends
    maxAge: ADMIN_SESSION_HOURS * 3600 * 1000,
    path: '/'
  };
}

// ============ FIREBASE INITIALIZATION ============
let db;
try {
  const serviceAccount = require('./firebase-service-account.json');
  admin.initializeApp({
    credential: admin.cert(serviceAccount),
    databaseURL: process.env.FIREBASE_DATABASE_URL || 'https://dtvs-65da4-default-rtdb.europe-west1.firebasedatabase.app'
  });
  db = getDatabase();
  console.log('Connected to Firebase Realtime Database');
} catch (err) {
  console.error('❌ Firebase initialization failed.');
  console.error('   Please replace firebase-service-account.json with your real Firebase service account key.');
  console.error('   Error:', err.message);
  process.exit(1);
}

// Helper: get current timestamp
function getTimestamp() {
  return new Date().toISOString().replace('T', ' ').substring(0, 19);
}

// Sessions stay alive on a sliding 30-day window.
const THIRTY_DAYS_MS = 30 * 24 * 60 * 60 * 1000;

// Helper: generate a formatted access code (XXXX-XXXX)
function generateFormattedCode() {
  const code = crypto.randomBytes(4).toString('hex').toUpperCase();
  return `${code.slice(0, 4)}-${code.slice(4, 8)}`;
}

// Helper: generate a session token — 256 bits of entropy
function generateSessionToken() {
  return crypto.randomBytes(32).toString('hex');
}

// A valid session token is always exactly 64 lowercase hex chars (32 random bytes).
function isValidTokenFormat(token) {
  return typeof token === 'string' && /^[a-f0-9]{64}$/.test(token);
}

// Firebase push keys look like -Nxxxxxxxxxxxxxx. Validate before use in paths.
function isValidCourseId(id) {
  return typeof id === 'string' && /^[A-Za-z0-9_-]{1,40}$/.test(id);
}

// Helper: get all access codes
async function getAllCodes() {
  const snapshot = await db.ref('access_codes').once('value');
  const codes = [];
  snapshot.forEach(function (child) {
    const data = child.val();
    codes.push({
      id: child.key,
      code: data.code,
      created_at: data.created_at,
      used_at: data.used_at,
      used_by: data.used_by,
      is_used: data.is_used
    });
  });
  return codes;
}

// Helper: get all sessions
async function getAllSessions() {
  const snapshot = await db.ref('sessions').once('value');
  const sessions = [];
  snapshot.forEach(function (child) {
    const data = child.val();
    sessions.push({
      token: child.key,
      code: data.code,
      createdAt: data.createdAt,
      lastSeenAt: data.lastSeenAt,
      expiresAtMs: data.expiresAtMs,
      revoked: !!data.revoked
    });
  });
  return sessions;
}

function courseRecord(id, data) {
  return {
    id,
    title: data.title,
    description: data.description,
    video_url: data.video_url,
    thumbnail_url: data.thumbnail_url || null,
    duration: data.duration,
    level: data.level,
    created_at: data.created_at
  };
}

// Helper: get all courses
async function getAllCourses() {
  const snapshot = await db.ref('courses').once('value');
  const courses = [];
  snapshot.forEach(function (child) {
    courses.push(courseRecord(child.key, child.val()));
  });
  return courses;
}


// Helper: seed initial courses if database is empty
async function seedCourses() {
  const snapshot = await db.ref('courses').once('value');
  if (snapshot.empty) {
    const seedCourses = [
      {
        title: 'Getting Started with SheIn Reselling',
        description: 'Learn the fundamentals of sourcing, pricing, and managing SheIn resale orders in Lebanon.',
        video_url: '/videos/course1.mp4',
        thumbnail_url: null,
        duration: '45 min',
        level: 'Beginner',
        created_at: getTimestamp()
      },
      {
        title: 'Pricing & Profit Margins',
        description: 'Master the numbers — how to price orders, calculate margins, and maximize your profit per shipment.',
        video_url: '/videos/course2.mp4',
        thumbnail_url: null,
        duration: '35 min',
        level: 'Intermediate',
        created_at: getTimestamp()
      },
      {
        title: 'Scaling Your Agent Business',
        description: 'Advanced strategies for growing your client base, streamlining operations, and scaling with DTV.',
        video_url: '/videos/course3.mp4',
        thumbnail_url: null,
        duration: '50 min',
        level: 'Advanced',
        created_at: getTimestamp()
      }
    ];

    const updates = {};
    seedCourses.forEach(function (course) {
      const newId = db.ref('courses').push().key;
      updates['courses/' + newId] = course;
    });
    await db.ref().update(updates);
    console.log('Seeded initial courses');
  }
}

// Initialize database with seed data
seedCourses().catch(err => {
  console.error('Failed to seed courses:', err);
});

// ============ AUTH MIDDLEWARE ============

// Admin API endpoints: 401 JSON when the admin session cookie is invalid.
function requireAdminApi(req, res, next) {
  if (verifyAdminToken(req.cookies.dtv_admin_session)) return next();
  return res.status(401).json({ success: false, error: 'ADMIN_AUTH_REQUIRED' });
}

// Admin pages: redirect to the login page when not authenticated.
function requireAdminPage(req, res, next) {
  if (verifyAdminToken(req.cookies.dtv_admin_session)) return next();
  return res.redirect('/admin/login');
}

// Agent sessions are stored in Firebase and presented as a Bearer token by
// the courses page. Admins are recognized via their session cookie. Either
// one passes. Prevents anonymous scraping of the course list / video paths.
async function requireAgentOrAdmin(req, res, next) {
  if (verifyAdminToken(req.cookies.dtv_admin_session)) return next();

  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7).trim() : '';
  if (!token) {
    return res.status(401).json({ success: false, error: 'ACCESS_DENIED' });
  }
  if (!isValidTokenFormat(token)) {
    return res.status(401).json({ success: false, error: 'ACCESS_DENIED' });
  }
  try {
    const snap = await db.ref('sessions/' + token).once('value');
    const s = snap.val();
    if (s && !s.revoked && typeof s.expiresAtMs === 'number' && Date.now() < s.expiresAtMs) {
      return next();
    }
  } catch (err) { /* fall through to denied */ }
  return res.status(401).json({ success: false, error: 'ACCESS_DENIED' });
}

// ============ PUBLIC PAGES ============
app.get('/', (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'dtv-website.html'));
});

app.get('/courses', (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'courses.html'));
});

// Never let the raw admin.html be served by express.static — always require auth.
app.get('/admin.html', (req, res) => res.redirect('/admin'));

app.get('/admin/login', (req, res) => {
  // Already logged in? Skip the login form.
  if (verifyAdminToken(req.cookies.dtv_admin_session)) return res.redirect('/admin');
  res.sendFile(path.join(PUBLIC_DIR, 'admin-login.html'));
});

app.get('/admin', requireAdminPage, (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'admin.html'));
});

// ============ ADMIN AUTH ROUTES ============
app.post('/api/admin/login', loginLimiter, (req, res) => {
  const { username, password } = req.body || {};
  if (typeof username !== 'string' || typeof password !== 'string' || !username || !password) {
    return res.status(400).json({ success: false, error: 'Username and password are required' });
  }
  const userOk = username === adminCreds.username;
  const passOk = verifyPassword(password);
  if (!userOk || !passOk) {
    return res.status(401).json({ success: false, error: 'Invalid username or password' });
  }
  res.cookie('dtv_admin_session', signAdminToken(), adminCookieOptions(req));
  res.json({ success: true, message: 'Welcome, ' + adminCreds.username });
});

app.post('/api/admin/logout', (req, res) => {
  res.clearCookie('dtv_admin_session', { path: '/' });
  res.json({ success: true });
});

// ============ ADMIN API (auth + rate limited) ============
app.use('/api/admin', adminApiLimiter, requireAdminApi);

// Helper: get a single course by ID
async function getCourseById(id) {
  const snapshot = await db.ref('courses/' + id).once('value');
  const data = snapshot.val();
  if (!data) return null;
  return courseRecord(snapshot.key, data);
}


// Generate a new access code
app.post('/api/admin/generate-code', async (req, res) => {
  const formatted = generateFormattedCode();
  try {
    const newRef = db.ref('access_codes').push();
    await newRef.set({
      code: formatted,
      created_at: getTimestamp(),
      used_at: null,
      used_by: null,
      is_used: 0
    });
    res.json({ success: true, code: formatted });
  } catch (err) {
    console.error('Failed to generate code:', err);
    res.status(500).json({ success: false, error: 'Failed to generate code' });
  }
});

// Admin: list all access codes
app.get('/api/admin/codes', async (req, res) => {
  try {
    const codes = await getAllCodes();
    res.json({ success: true, codes });
  } catch (err) {
    console.error('Failed to load codes:', err);
    res.status(500).json({ success: false, error: 'Failed to load codes' });
  }
});

// Admin: list all sessions
app.get('/api/admin/sessions', async (req, res) => {
  try {
    const sessions = await getAllSessions();
    res.json({ success: true, sessions });
  } catch (err) {
    console.error('Failed to load sessions:', err);
    res.status(500).json({ success: false, error: 'Failed to load sessions' });
  }
});

// Admin: revoke a session (e.g. a leaked link, or an agent who's left)
app.post('/api/admin/sessions/:token/revoke', async (req, res) => {
  if (!isValidTokenFormat(req.params.token)) {
    return res.status(400).json({ success: false, error: 'Invalid session token' });
  }
  try {
    await db.ref('sessions/' + req.params.token).update({ revoked: true });
    res.json({ success: true });
  } catch (err) {
    console.error('Failed to revoke session:', err);
    res.status(500).json({ success: false, error: 'Failed to revoke session' });
  }
});


// Admin: Add a new course (multipart: fields + optional thumbnail + video file)
app.post('/api/admin/courses',
  upload.fields([{ name: 'video', maxCount: 1 }, { name: 'thumbnail', maxCount: 1 }]),
  async (req, res) => {
    try {
      const { title, description, duration, level } = req.body || {};
      if (typeof title !== 'string' || !title.trim()) {
        removeUploadedFiles(req);
        return res.status(400).json({ success: false, error: 'Course title is required' });
      }
      if (title.trim().length > 200) {
        removeUploadedFiles(req);
        return res.status(400).json({ success: false, error: 'Course title is too long (max 200 characters)' });
      }
      if (!req.files || !req.files.video || !req.files.video[0]) {
        return res.status(400).json({ success: false, error: 'A video file is required' });
      }
      const video = req.files.video[0];
      if (video.size > MAX_VIDEO_BYTES) {
        removeUploadedFiles(req);
        return res.status(413).json({ success: false, error: 'Video is too large (max 500 MB)' });
      }

      let thumbnail = null;
      if (req.files.thumbnail && req.files.thumbnail[0]) {
        thumbnail = req.files.thumbnail[0];
        if (thumbnail.size > MAX_THUMB_BYTES) {
          removeUploadedFiles(req);
          return res.status(413).json({ success: false, error: 'Thumbnail is too large (max 2 MB)' });
        }
      }

      const levelClean = ['Beginner', 'Intermediate', 'Advanced'].includes(level) ? level : 'Beginner';
      const record = {
        title: title.trim(),
        description: typeof description === 'string' ? description.slice(0, 2000) : '',
        video_url: '/uploads/videos/' + video.filename,
        thumbnail_url: thumbnail ? '/uploads/thumbnails/' + thumbnail.filename : null,
        duration: typeof duration === 'string' && duration.trim() ? duration.trim().slice(0, 50) : '30 min',
        level: levelClean,
        created_at: getTimestamp()
      };

      const newRef = db.ref('courses').push();
      await newRef.set(record);
      res.json({ success: true, id: newRef.key, course: record });
    } catch (err) {
      console.error('Failed to add course:', err);
      removeUploadedFiles(req);
      res.status(500).json({ success: false, error: 'Failed to add course' });
    }
  }
);

// Admin: Update a course (multipart — files optional, existing ones kept)
app.put('/api/admin/courses/:id',
  upload.fields([{ name: 'video', maxCount: 1 }, { name: 'thumbnail', maxCount: 1 }]),
  async (req, res) => {
    const id = req.params.id;
    if (!isValidCourseId(id)) {
      removeUploadedFiles(req);
      return res.status(400).json({ success: false, error: 'Invalid course id' });
    }
    try {
      const snap = await db.ref('courses/' + id).once('value');
      const existing = snap.val();
      if (!existing) {
        removeUploadedFiles(req);
        return res.status(404).json({ success: false, error: 'Course not found' });
      }

      const { title, description, duration, level } = req.body || {};
      const update = {};
      if (typeof title === 'string' && title.trim()) update.title = title.trim().slice(0, 200);
      if (typeof description === 'string') update.description = description.slice(0, 2000);
      if (typeof duration === 'string' && duration.trim()) update.duration = duration.trim().slice(0, 50);
      if (['Beginner', 'Intermediate', 'Advanced'].includes(level)) update.level = level;

      if (req.files && req.files.video && req.files.video[0]) {
        const v = req.files.video[0];
        if (v.size > MAX_VIDEO_BYTES) {
          removeUploadedFiles(req);
          return res.status(413).json({ success: false, error: 'Video is too large (max 500 MB)' });
        }
        update.video_url = '/uploads/videos/' + v.filename;
      }
      if (req.files && req.files.thumbnail && req.files.thumbnail[0]) {
        const t = req.files.thumbnail[0];
        if (t.size > MAX_THUMB_BYTES) {
          removeUploadedFiles(req);
          return res.status(413).json({ success: false, error: 'Thumbnail is too large (max 2 MB)' });
        }
        update.thumbnail_url = '/uploads/thumbnails/' + t.filename;
      }

      if (Object.keys(update).length === 0) {
        removeUploadedFiles(req);
        return res.status(400).json({ success: false, error: 'Nothing to update' });
      }

      await db.ref('courses/' + id).update(update);

      // Delete the replaced files only after the DB write succeeded.
      if (update.video_url && existing.video_url && update.video_url !== existing.video_url) {
        deleteFileForUrl(existing.video_url);
      }
      if (update.thumbnail_url && existing.thumbnail_url && update.thumbnail_url !== existing.thumbnail_url) {
        deleteFileForUrl(existing.thumbnail_url);
      }
      res.json({ success: true });
    } catch (err) {
      console.error('Failed to update course:', err);
      removeUploadedFiles(req);
      res.status(500).json({ success: false, error: 'Failed to update course' });
    }
  }
);

// Admin: Delete a course (and its uploaded files)
app.delete('/api/admin/courses/:id', async (req, res) => {
  const id = req.params.id;
  if (!isValidCourseId(id)) {
    return res.status(400).json({ success: false, error: 'Invalid course id' });
  }
  try {
    const snap = await db.ref('courses/' + id).once('value');
    const data = snap.val();
    await db.ref('courses/' + id).remove();
    if (data) {
      deleteFileForUrl(data.video_url);
      deleteFileForUrl(data.thumbnail_url);
    }
    res.json({ success: true });
  } catch (err) {
    console.error('Failed to delete course:', err);
    res.status(500).json({ success: false, error: 'Failed to delete course' });
  }
});

// ============ PUBLIC API ============

// Health check for load balancers / uptime monitors
app.get('/api/health', (req, res) => {
  res.json({ success: true, status: 'ok', uptime: process.uptime() });
});

// Validate an access code
app.post('/api/validate-code', publicApiLimiter, async (req, res) => {
  const { code } = req.body;

  if (!code || typeof code !== 'string') {
    return res.status(400).json({ success: false, error: 'Code is required' });
  }

  const normalizedCode = code.trim().toUpperCase();

  try {
    // Find the code in Firebase
    const snapshot = await db.ref('access_codes').orderByChild('code').equalTo(normalizedCode).once('value');

    if (snapshot.empty) {
      return res.status(404).json({ success: false, error: 'Invalid access code. Please check and try again.' });
    }

    let codeId = null;
    snapshot.forEach(function (child) {
      codeId = child.key;
    });

    // Atomic check-and-mark: two simultaneous redemptions can't both win.
    const txResult = await db.ref('access_codes/' + codeId).transaction(function (current) {
      if (current === null) return current;
      if (current.is_used) return;
      return Object.assign({}, current, { is_used: 1, used_at: getTimestamp() });
    });

    if (!txResult.committed) {
      return res.status(403).json({ success: false, error: 'This code has already been used. Please contact the admin for a new code.' });
    }

    const sessionToken = generateSessionToken();
    const now = Date.now();
    await db.ref('sessions/' + sessionToken).set({
      codeId,
      code: normalizedCode,
      createdAt: getTimestamp(),
      lastSeenAt: getTimestamp(),
      expiresAtMs: now + THIRTY_DAYS_MS,
      revoked: false
    });

    res.json({ success: true, message: 'Access granted', sessionToken, expiresIn: THIRTY_DAYS_MS / 1000 });
  } catch (err) {
    console.error('Validation error:', err);
    res.status(500).json({ success: false, error: 'Server error during validation' });
  }
});

// Check whether a stored/shared session token is still valid, and slide its expiry.
app.post('/api/validate-session', publicApiLimiter, async (req, res) => {
  const { sessionToken } = req.body;

  if (!isValidTokenFormat(sessionToken)) {
    return res.status(400).json({ success: false, error: 'SESSION_TOKEN_REQUIRED' });
  }

  try {
    const snap = await db.ref('sessions/' + sessionToken).once('value');
    const session = snap.val();

    if (!session) return res.status(404).json({ success: false, error: 'SESSION_NOT_FOUND' });
    if (session.revoked) return res.status(403).json({ success: false, error: 'SESSION_REVOKED' });
    if (Date.now() > session.expiresAtMs) return res.status(403).json({ success: false, error: 'SESSION_EXPIRED' });

    const now = Date.now();
    await db.ref('sessions/' + sessionToken).update({
      lastSeenAt: getTimestamp(),
      expiresAtMs: now + THIRTY_DAYS_MS
    });

    res.json({ success: true });
  } catch (err) {
    console.error('Session validation error:', err);
    res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

// One-time bridge for agents who redeemed their code before session support existed.
app.post('/api/migrate-legacy-code', publicApiLimiter, async (req, res) => {
  const { code } = req.body;

  if (!code || typeof code !== 'string') {
    return res.status(400).json({ success: false, error: 'CODE_REQUIRED' });
  }

  const normalizedCode = code.trim().toUpperCase();

  try {
    const snapshot = await db.ref('access_codes').orderByChild('code').equalTo(normalizedCode).once('value');

    if (snapshot.empty) return res.status(404).json({ success: false, error: 'CODE_INVALID' });

    let codeData = null;
    let codeId = null;
    snapshot.forEach(function (child) {
      codeData = child.val();
      codeId = child.key;
    });

    if (!codeData.is_used) return res.status(400).json({ success: false, error: 'CODE_NOT_USED' });
    if (codeData.migrated) return res.status(403).json({ success: false, error: 'ALREADY_MIGRATED' });

    // Atomically claim the migration so this bridge can't be replayed.
    const txResult = await db.ref('access_codes/' + codeId).transaction(function (current) {
      if (current === null) return current;
      if (current.migrated) return;
      return Object.assign({}, current, { migrated: true });
    });

    if (!txResult.committed) return res.status(403).json({ success: false, error: 'ALREADY_MIGRATED' });

    const sessionToken = generateSessionToken();
    const now = Date.now();
    await db.ref('sessions/' + sessionToken).set({
      codeId,
      code: normalizedCode,
      createdAt: getTimestamp(),
      lastSeenAt: getTimestamp(),
      expiresAtMs: now + THIRTY_DAYS_MS,
      revoked: false
    });

    res.json({ success: true, sessionToken });
  } catch (err) {
    console.error('Legacy migration error:', err);
    res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

// Get all courses (requires valid agent session or admin)
app.get('/api/courses', publicApiLimiter, requireAgentOrAdmin, async (req, res) => {
  try {
    const courses = await getAllCourses();
    res.json({ success: true, courses });
  } catch (err) {
    console.error('Failed to load courses:', err);
    res.status(500).json({ success: false, error: 'Failed to load courses' });
  }
});

// Get a single course by ID (requires valid agent session or admin)
app.get('/api/courses/:id', publicApiLimiter, requireAgentOrAdmin, async (req, res) => {
  const id = req.params.id;
  if (!isValidCourseId(id)) return res.status(400).json({ success: false, error: 'Invalid course id' });
  try {
    const course = await getCourseById(id);
    if (!course) return res.status(404).json({ success: false, error: 'Course not found' });
    res.json({ success: true, course });
  } catch (err) {
    console.error('Failed to load course:', err);
    res.status(500).json({ success: false, error: 'Failed to load course' });
  }
});

// ============ STATIC FILES ============
// Uploaded media: cached for a year — filenames are random and never reused,
// so `immutable` is safe and cuts server load dramatically for repeat viewers.
app.use('/uploads', express.static(UPLOAD_ROOT, { maxAge: '1y', immutable: true, fallthrough: false, index: false }));
// Everything else, straight from public/. admin.html is explicitly redirected above.
app.use(express.static(PUBLIC_DIR, { index: false }));

// ============ 404 / ERROR HANDLERS ============
app.use('/api', (req, res) => {
  res.status(404).json({ success: false, error: 'API route not found' });
});

app.use((err, req, res, next) => {
  // Not-found style errors from middleware (e.g. missing file in /uploads)
  if (err && (err.status === 404 || err.statusCode === 404)) {
    if (req.path.startsWith('/api/')) return res.status(404).json({ success: false, error: 'Not found' });
    return res.status(404).send('Not found');
  }
  if (err && err.name === 'MulterError') {
    const msg = err.code === 'LIMIT_FILE_SIZE' ? 'File too large (max 500 MB for video, 2 MB for thumbnail)' : err.message;
    return res.status(400).json({ success: false, error: msg });
  }
  if (err && err.message && err.message.indexOf('Unsupported file type') !== -1) {
    return res.status(400).json({ success: false, error: err.message });
  }
  if (err && err.type === 'entity.too.large') {
    return res.status(413).json({ success: false, error: 'Request body too large' });
  }
  if (err && err.type === 'entity.parse.failed') {
    return res.status(400).json({ success: false, error: 'Invalid JSON body' });
  }
  console.error('Unhandled error:', err);
  if (req.path.startsWith('/api/')) return res.status(500).json({ success: false, error: 'Internal server error' });
  res.status(500).send('Internal server error');
});

// ============ START ============
app.listen(PORT, () => {
  console.log(`DTV server running on http://localhost:${PORT}`);
  console.log(`- Main site: http://localhost:${PORT}/`);
  console.log(`- Courses: http://localhost:${PORT}/courses`);
  console.log(`- Admin Login: http://localhost:${PORT}/admin/login`);
  console.log(`- Admin Panel: http://localhost:${PORT}/admin`);
  console.log(`- API: http://localhost:${PORT}/api`);
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  try {
    await admin.app().delete();
    process.exit(0);
  } catch (err) {
    process.exit(1);
  }
});

process.on('SIGINT', async () => {
  try {
    await admin.app().delete();
    process.exit(0);
  } catch (err) {
    process.exit(1);
  }
});

