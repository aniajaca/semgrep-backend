// src/server.js
const express   = require('express');
const multer    = require('multer');
const { spawn } = require('child_process');
const fs        = require('fs');
const path      = require('path');

const app   = express();
const PORT  = process.env.PORT || 3000;
const FRONT = process.env.ALLOWED_ORIGIN || 'http://localhost:3000';

// ── 1️⃣ Simple CORS middleware ───────────────────────────────────────────────
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', FRONT);
  res.header('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});

// ── 2️⃣ Health endpoints ─────────────────────────────────────────────────────
app.get('/', (_req, res) => {
  console.log('🟢 GET / → 200');
  res.sendStatus(200);
});
app.get('/healthz', (_req, res) => {
  console.log('🟢 GET /healthz → 200');
  res.sendStatus(200);
});

// ── 3️⃣ Ensure uploads folder exists ─────────────────────────────────────────
const UPLOAD_DIR = path.resolve(__dirname, '../uploads');
if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
  console.log(`📂 Created uploads dir at ${UPLOAD_DIR}`);
}

// ── 4️⃣ Multer config ────────────────────────────────────────────────────────
const storage = multer.diskStorage({
  destination: UPLOAD_DIR,
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, `file-${Date.now()}${ext}`);
  },
});
const upload = multer({ storage });

// ── 5️⃣ POST /scan handler ──────────────────────────────────────────────────
app.post('/scan', upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded.' });
  }

  const toScan = req.file.path;
  console.log('📂 Saved file:', toScan);

  const configs = [
    'p/python','p/javascript','p/java','p/go',
    'p/cpp','p/php','p/ruby','p/sql',
    path.resolve(__dirname, '../config/custom-rules.yaml'),
  ];
  const args = [
    'scan', '--quiet', '--json',
    ...configs.flatMap(c => ['--config', c]),
    toScan,
  ];

  const semgrep = spawn('semgrep', args, { timeout: 20000 });
  let stdout = '', stderr = '';

  semgrep.on('error', err => {
    console.error('🛑 Spawn error:', err.message);
    fs.unlink(toScan, () => {});
    return res.status(500).json({ error: 'Failed to start Semgrep.' });
  });

  semgrep.stdout.on('data', chunk => { stdout += chunk; });
  semgrep.stderr.on('data', chunk => { stderr += chunk; });

  semgrep.on('close', code => {
    // Always clean up the uploaded file
    fs.unlink(toScan, err => {
      if (err) console.error('🗑️ Delete failed:', err);
      else     console.log('🗑️ Deleted:', toScan);
    });

    // Semgrep exit codes: 0 = no findings, 1 = findings, >1 = runtime error
    if (code > 1) {
      console.error('❌ Semgrep runtime error:', stderr.trim());
      return res.status(500).json({ error: stderr.trim() });
    }

    // code 0 or 1: valid JSON output
    try {
      const result = JSON.parse(stdout.trim());
      console.log(`✅ Semgrep exit ${code}, found ${result.results.length} issue(s)`);
      return res.json(result);
    } catch (e) {
      console.error('❌ JSON parse failed:', e.message);
      return res.status(500).json({ error: 'Invalid Semgrep output.' });
    }
  });
});

// ── 6️⃣ Catch-all for any other GET (ensures no 404) ───────────────────────────
app.use((req, res) => {
  console.log(`🟢 Fallback ${req.method} ${req.path} → 200`);
  res.sendStatus(200);
});

// ── 7️⃣ Start server ─────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`🚀 API listening on port ${PORT}`);
  console.log(`🌍 CORS allowed origin: ${FRONT}`);
});
