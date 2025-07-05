// src/server.js
const express   = require('express');
const cors      = require('cors');
const multer    = require('multer');
const { spawn } = require('child_process');
const fs        = require('fs');
const path      = require('path');

const app   = express();
const PORT  = process.env.PORT || 3000;
const FRONT = process.env.ALLOWED_ORIGIN || 'http://localhost:3000';

// 1️⃣ CORS — only allow your front-end’s origin
app.use(
  cors({
    origin: FRONT,
    methods: ['GET', 'POST', 'OPTIONS'],
  })
);

// 2️⃣ Health endpoints
// Railway’s default probe hits `/`
app.get('/', (_req, res) => {
  console.log('🟢 Received GET /');
  return res.sendStatus(200);
});

// Explicit health check
app.get('/healthz', (_req, res) => {
  console.log('🟢 Received GET /healthz');
  return res.sendStatus(200);
});

// 3️⃣ Ensure uploads folder exists
const UPLOAD_DIR = path.resolve(__dirname, '../uploads');
if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
  console.log(`📂 Created upload dir at ${UPLOAD_DIR}`);
}

// 4️⃣ Configure Multer for file uploads
const storage = multer.diskStorage({
  destination: UPLOAD_DIR,
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, `file-${Date.now()}${ext}`);
  },
});
const upload = multer({ storage });

// 5️⃣ POST /scan handler
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
    'scan',
    '--quiet',
    '--json',
    ...configs.flatMap(cfg => ['--config', cfg]),
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
    // Clean up uploaded file
    fs.unlink(toScan, err => {
      if (err) console.error('🗑️ Delete failed:', err);
      else     console.log('🗑️ Deleted:', toScan);
    });

    if (code > 1) {
      console.error('❌ Semgrep runtime error:', stderr.trim());
      return res.status(500).json({ error: stderr.trim() });
    }

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

// 6️⃣ Start server
app.listen(PORT, () => {
  console.log(`🚀 API listening on port ${PORT}`);
  console.log(`🌍 CORS allowed origin: ${FRONT}`);
});

// ##### at the bottom of src/server.js, just before app.listen(...)
  
// Catch-all GET so Railway’s health probes never 404
app.get('*', (_req, res) => {
  console.log('🟢 Caught GET', _req.path);
  return res.sendStatus(200);
});

// 7️⃣ Start server
app.listen(PORT, () => {
  console.log(`🚀 API listening on port ${PORT}`);
  console.log(`🌍 CORS allowed origin: ${FRONT}`);
});

