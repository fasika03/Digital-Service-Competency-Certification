const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const PDFDocument = require('pdfkit');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;
const SECRET = process.env.JWT_SECRET || (console.warn('WARNING: JWT_SECRET not set; using a random one (logins reset on restart).'), crypto.randomBytes(32).toString('hex'));
const UPLOADS = path.join(__dirname, 'uploads');
fs.mkdirSync(UPLOADS, { recursive: true });

// ---------- Database ----------
const db = new Database(process.env.DB_FILE || path.join(__dirname, 'data.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, password TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'company', created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS applications(
  id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),
  company TEXT NOT NULL, sector TEXT, trade_license_no TEXT, tin TEXT, website TEXT, description TEXT,
  status TEXT NOT NULL DEFAULT 'draft', note TEXT, cert_no TEXT UNIQUE,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP, submitted_at TEXT, decided_at TEXT);
CREATE TABLE IF NOT EXISTS documents(
  id INTEGER PRIMARY KEY, app_id INTEGER NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  kind TEXT NOT NULL, original_name TEXT NOT NULL, stored_name TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS news(
  id INTEGER PRIMARY KEY, title TEXT NOT NULL, body TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
`);
try { db.exec('ALTER TABLE applications ADD COLUMN expires_at TEXT'); } catch {}

// Seed first admin from environment variables
if (process.env.ADMIN_EMAIL && process.env.ADMIN_PASSWORD) {
  const exists = db.prepare('SELECT id FROM users WHERE email=?').get(process.env.ADMIN_EMAIL.toLowerCase());
  if (!exists) {
    db.prepare("INSERT INTO users(email,password,role) VALUES(?,?,'admin')")
      .run(process.env.ADMIN_EMAIL.toLowerCase(), bcrypt.hashSync(process.env.ADMIN_PASSWORD, 10));
    console.log('Admin account created:', process.env.ADMIN_EMAIL);
  }
}

// ---------- App setup ----------
const app = express();
app.set('trust proxy', 1);
app.use(helmet({
  contentSecurityPolicy: { directives: {
    defaultSrc: ["'self'"], scriptSrc: ["'self'", "'unsafe-inline'"],
    styleSrc: ["'self'", "'unsafe-inline'"], imgSrc: ["'self'", 'data:'], connectSrc: ["'self'"],
  } },
}));
app.use(express.json({ limit: '100kb' }));
app.use(express.static(path.join(__dirname, 'public')));

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 20, message: { error: 'Too many attempts, try again later.' } });

const upload = multer({
  storage: multer.diskStorage({
    destination: UPLOADS,
    filename: (_req, _file, cb) => cb(null, crypto.randomBytes(16).toString('hex')),
  }),
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (_req, file, cb) =>
    ['application/pdf', 'image/png', 'image/jpeg'].includes(file.mimetype) ? cb(null, true) : cb(new Error('Only PDF, PNG or JPG files are allowed.')),
});

// ---------- Helpers ----------
const str = (v, max = 200) => (typeof v === 'string' ? v.trim().slice(0, max) : '');
const bad = (res, msg, code = 400) => res.status(code).json({ error: msg });
const certNo = id => `DSC-${new Date().getFullYear()}-${String(id).padStart(4, '0')}`;
const sign = u => jwt.sign({ id: u.id, email: u.email, role: u.role }, SECRET, { expiresIn: '7d' });

const auth = role => (req, res, next) => {
  try {
    req.user = jwt.verify((req.headers.authorization || '').replace('Bearer ', ''), SECRET);
  } catch { return bad(res, 'Please sign in.', 401); }
  if (role && req.user.role !== role) return bad(res, 'Not allowed.', 403);
  next();
};

// Returns the application if the user owns it (or is admin)
function getApp(req, res) {
  const a = db.prepare('SELECT * FROM applications WHERE id=?').get(req.params.id);
  if (!a || (req.user.role !== 'admin' && a.user_id !== req.user.id)) { bad(res, 'Application not found.', 404); return null; }
  return a;
}
const editable = a => a.status === 'draft' || a.status === 'rejected';

// ---------- Auth ----------
app.post('/api/auth/register', authLimiter, (req, res) => {
  const email = str(req.body.email).toLowerCase(), password = str(req.body.password, 100);
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return bad(res, 'Enter a valid email.');
  if (password.length < 8) return bad(res, 'Password must be at least 8 characters.');
  if (db.prepare('SELECT 1 FROM users WHERE email=?').get(email)) return bad(res, 'Email already registered.', 409);
  const r = db.prepare("INSERT INTO users(email,password) VALUES(?,?)").run(email, bcrypt.hashSync(password, 10));
  const u = { id: r.lastInsertRowid, email, role: 'company' };
  res.status(201).json({ token: sign(u), user: u });
});

app.post('/api/auth/login', authLimiter, (req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE email=?').get(str(req.body.email).toLowerCase());
  if (!u || !bcrypt.compareSync(str(req.body.password, 100), u.password)) return bad(res, 'Wrong email or password.', 401);
  res.json({ token: sign(u), user: { id: u.id, email: u.email, role: u.role } });
});

app.get('/api/me', auth(), (req, res) => res.json({ user: req.user }));

// ---------- Company: applications ----------
function fields(b) {
  return [str(b.company), str(b.sector, 80), str(b.trade_license_no, 80), str(b.tin, 80), str(b.website), str(b.description, 1000)];
}

app.post('/api/applications', auth('company'), (req, res) => {
  const f = fields(req.body);
  if (!f[0]) return bad(res, 'Company name is required.');
  const r = db.prepare('INSERT INTO applications(user_id,company,sector,trade_license_no,tin,website,description) VALUES(?,?,?,?,?,?,?)')
    .run(req.user.id, ...f);
  res.status(201).json({ id: r.lastInsertRowid });
});

app.put('/api/applications/:id', auth('company'), (req, res) => {
  const a = getApp(req, res); if (!a) return;
  if (!editable(a)) return bad(res, 'This application can no longer be edited.', 409);
  const f = fields(req.body);
  if (!f[0]) return bad(res, 'Company name is required.');
  db.prepare('UPDATE applications SET company=?,sector=?,trade_license_no=?,tin=?,website=?,description=? WHERE id=?').run(...f, a.id);
  res.json({ ok: true });
});

app.get('/api/applications/mine', auth('company'), (req, res) => {
  const apps = db.prepare('SELECT * FROM applications WHERE user_id=? ORDER BY id DESC').all(req.user.id);
  const docs = db.prepare('SELECT id,app_id,kind,original_name FROM documents WHERE app_id IN (SELECT id FROM applications WHERE user_id=?)').all(req.user.id);
  res.json(apps.map(a => ({ ...a, documents: docs.filter(d => d.app_id === a.id) })));
});

app.post('/api/applications/:id/documents', auth('company'), (req, res, next) => {
  const a = getApp(req, res); if (!a) return;
  if (!editable(a)) return bad(res, 'Documents can no longer be changed.', 409);
  req.app_row = a; next();
}, upload.single('file'), (req, res) => {
  const kind = str(req.body.kind, 40) || 'other';
  if (!req.file) return bad(res, 'Choose a file.');
  const r = db.prepare('INSERT INTO documents(app_id,kind,original_name,stored_name) VALUES(?,?,?,?)')
    .run(req.app_row.id, kind, path.basename(req.file.originalname).slice(0, 150), req.file.filename);
  res.status(201).json({ id: r.lastInsertRowid });
});

app.delete('/api/documents/:id', auth('company'), (req, res) => {
  const d = db.prepare('SELECT d.*, a.user_id, a.status FROM documents d JOIN applications a ON a.id=d.app_id WHERE d.id=?').get(req.params.id);
  if (!d || d.user_id !== req.user.id) return bad(res, 'Not found.', 404);
  if (d.status !== 'draft' && d.status !== 'rejected') return bad(res, 'Documents can no longer be changed.', 409);
  fs.unlink(path.join(UPLOADS, d.stored_name), () => {});
  db.prepare('DELETE FROM documents WHERE id=?').run(d.id);
  res.json({ ok: true });
});

app.post('/api/applications/:id/submit', auth('company'), (req, res) => {
  const a = getApp(req, res); if (!a) return;
  if (!editable(a)) return bad(res, 'Already submitted.', 409);
  if (!a.trade_license_no || !a.tin) return bad(res, 'Trade license number and TIN are required.');
  if (!db.prepare('SELECT 1 FROM documents WHERE app_id=?').get(a.id)) return bad(res, 'Upload at least one document first.');
  db.prepare("UPDATE applications SET status='submitted', submitted_at=CURRENT_TIMESTAMP, note=NULL WHERE id=?").run(a.id);
  res.json({ ok: true });
});

// Download a document (owner or admin)
app.get('/api/documents/:id/file', auth(), (req, res) => {
  const d = db.prepare('SELECT d.*, a.user_id FROM documents d JOIN applications a ON a.id=d.app_id WHERE d.id=?').get(req.params.id);
  if (!d || (req.user.role !== 'admin' && d.user_id !== req.user.id)) return bad(res, 'Not found.', 404);
  res.download(path.join(UPLOADS, d.stored_name), d.original_name);
});

// Certificate PDF (owner or admin, approved only)
app.get('/api/applications/:id/certificate', auth(), (req, res) => {
  const a = getApp(req, res); if (!a) return;
  if (a.status !== 'approved') return bad(res, 'Certificate is available after approval.', 409);
  const doc = new PDFDocument({ size: 'A4', layout: 'landscape', margin: 50 });
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `attachment; filename="${a.cert_no}.pdf"`);
  doc.pipe(res);
  const W = doc.page.width, H = doc.page.height;
  doc.lineWidth(4).strokeColor('#2563eb').rect(30, 30, W - 60, H - 60).stroke();
  doc.lineWidth(1).rect(40, 40, W - 80, H - 80).stroke();
  doc.fillColor('#2563eb').fontSize(30).font('Helvetica-Bold').text('Digital Service Competency Certificate', 0, 100, { align: 'center' });
  doc.fillColor('#333').fontSize(14).font('Helvetica').text('This certifies that', 0, 170, { align: 'center' });
  doc.fillColor('#000').fontSize(28).font('Helvetica-Bold').text(a.company, 60, 200, { align: 'center', width: W - 120 });
  doc.fillColor('#333').fontSize(14).font('Helvetica')
    .text('has met the competency requirements for operating as a digital business in Ethiopia.', 0, 270, { align: 'center' });
  doc.fontSize(12).text(`Certificate No: ${a.cert_no}`, 0, 340, { align: 'center' });
  doc.text(`Issued: ${String(a.decided_at).slice(0, 10)}`, 0, 360, { align: 'center' });
  doc.text(`Valid until: ${a.expires_at || ''}`, 0, 378, { align: 'center' });
  doc.fontSize(10).fillColor('#666').text(`Verify: ${BASE_URL}/?verify=${a.cert_no}`, 0, 400, { align: 'center' });
  doc.end();
});

// ---------- Admin ----------
app.get('/api/admin/applications', auth('admin'), (req, res) => {
  const status = str(req.query.status, 20);
  const apps = status
    ? db.prepare('SELECT a.*, u.email FROM applications a JOIN users u ON u.id=a.user_id WHERE a.status=? ORDER BY a.id DESC').all(status)
    : db.prepare("SELECT a.*, u.email FROM applications a JOIN users u ON u.id=a.user_id WHERE a.status!='draft' ORDER BY a.id DESC").all();
  const docs = db.prepare('SELECT id,app_id,kind,original_name FROM documents').all();
  res.json(apps.map(a => ({ ...a, documents: docs.filter(d => d.app_id === a.id) })));
});

app.post('/api/admin/applications/:id/decision', auth('admin'), (req, res) => {
  const a = db.prepare('SELECT * FROM applications WHERE id=?').get(req.params.id);
  if (!a) return bad(res, 'Not found.', 404);
  if (a.status !== 'submitted') return bad(res, 'Only submitted applications can be decided.', 409);
  const decision = req.body.decision, note = str(req.body.note, 500);
  if (decision === 'approve') {
    db.prepare("UPDATE applications SET status='approved', cert_no=?, note=?, decided_at=CURRENT_TIMESTAMP, expires_at=date('now','+1 year') WHERE id=?").run(certNo(a.id), note || null, a.id);
  } else if (decision === 'reject') {
    if (!note) return bad(res, 'Give a reason for rejection.');
    db.prepare("UPDATE applications SET status='rejected', note=?, decided_at=CURRENT_TIMESTAMP WHERE id=?").run(note, a.id);
  } else return bad(res, 'Decision must be approve or reject.');
  res.json({ ok: true });
});

app.post('/api/admin/news', auth('admin'), (req, res) => {
  const title = str(req.body.title), body = str(req.body.body, 3000);
  if (!title || !body) return bad(res, 'Title and body are required.');
  const r = db.prepare('INSERT INTO news(title,body) VALUES(?,?)').run(title, body);
  res.status(201).json({ id: r.lastInsertRowid });
});

app.delete('/api/admin/news/:id', auth('admin'), (req, res) => {
  db.prepare('DELETE FROM news WHERE id=?').run(req.params.id);
  res.json({ ok: true });
});

// ---------- Public ----------
app.get('/api/registry', (req, res) => {
  const q = `%${str(req.query.q, 60)}%`;
  const w = ["status='approved'", '(company LIKE ? OR sector LIKE ? OR cert_no LIKE ?)'], p = [q, q, q];
  if (req.query.status === 'active') w.push("(expires_at IS NULL OR expires_at>=date('now'))");
  if (req.query.status === 'expired') w.push("expires_at<date('now')");
  for (const [k, c] of [['issueFrom', 'date(decided_at)>=?'], ['issueTo', 'date(decided_at)<=?'], ['expFrom', 'expires_at>=?'], ['expTo', 'expires_at<=?']]) {
    const v = str(req.query[k], 10);
    if (/^\d{4}-\d{2}-\d{2}$/.test(v)) { w.push(c); p.push(v); }
  }
  res.json(db.prepare(`SELECT company, sector, cert_no, date(decided_at) issue_date, expires_at,
    CASE WHEN expires_at<date('now') THEN 'expired' ELSE 'active' END status
    FROM applications WHERE ${w.join(' AND ')} ORDER BY decided_at DESC LIMIT 200`).all(...p));
});

app.get('/api/verify/:certNo', (req, res) => {
  const a = db.prepare("SELECT company, sector, cert_no, date(decided_at) issue_date, expires_at, CASE WHEN expires_at<date('now') THEN 'expired' ELSE 'active' END status FROM applications WHERE status='approved' AND cert_no=?").get(req.params.certNo);
  a ? res.json({ valid: true, ...a }) : res.status(404).json({ valid: false });
});

app.get('/api/stats', (_req, res) => {
  const c = s => db.prepare('SELECT COUNT(*) n FROM applications WHERE ' + s).get().n;
  const avg = db.prepare("SELECT AVG(julianday(decided_at)-julianday(submitted_at)) d FROM applications WHERE status='approved' AND submitted_at IS NOT NULL").get().d;
  res.json({ certified: c("status='approved'"), applications: c("status!='draft'"), pending: c("status='submitted'"), avgDays: avg ? Math.round(avg) : 0 });
});

app.get('/api/news', (_req, res) => res.json(db.prepare('SELECT * FROM news ORDER BY id DESC LIMIT 20').all()));

// ---------- Errors ----------
app.use('/api', (_req, res) => bad(res, 'Not found.', 404));
app.use((err, _req, res, _next) => {
  if (err instanceof multer.MulterError || /Only PDF/.test(err.message)) return bad(res, err.message);
  console.error(err);
  bad(res, 'Server error.', 500);
});

app.listen(PORT, () => console.log(`Portal running at ${BASE_URL}`));
