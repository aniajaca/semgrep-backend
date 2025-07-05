// src/server.js
const express   = require('express');
const cors      = require('cors');
const multer    = require('multer');
const { spawn } = require('child_process');
const fs        = require('fs');
const path      = require('path');

const app = express();

// 1️⃣ Pick up the platform-assigned port
const PORT = process.env.PORT || 3000;

// 2️⃣ CORS: only allow your front-end’s origin
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || 'http://localhost:3000';
app.use(
  cors({
    origin: ALLOWED_ORIGIN,
    methods: ['GET', 'POST', 'OPTIONS'],
  })
);

// 3️⃣ Health-check endpoints
// Railway’s default check hits `/`
app.get('/', (_req, res) => res.sendStatus(200));
// Your explicit healthz endpoint
app.get('/healthz', (_req, res) => res.sendStatus(200));

// 4️⃣ Ensure uploads folder exists
const UPLOAD_DIR = path.resolve(__dirname, '../uploads');
if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

// 5️⃣ Configure Multer for file uploads
const storage = multer.diskStorage({
  destination: UPLOAD_DIR,
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, `file-${Date.now()}${ext}`);
  },
});
const upload = multer({ storage });

// 6️⃣ POST /scan handler
app.post('/scan', upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded.' });
  }

  const toScan = req.file.path;
  console.log('📂 Saved file:', toScan);

  // Semgrep configurations
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

  // Spawn semgrep with a 20-second timeout
  const semgrep = spawn('semgrep', args, { timeout: 20000 });
  let stdout = '', stderr = '';

  // Handle spawn errors (e.g. semgrep not found)
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

    // code 0 or 1: valid JSON output with or without findings
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

// 7️⃣ Start server
app.listen(PORT, () => {
  console.log(`🚀 API listening on port ${PORT}`);
  console.log(`🌍 CORS allowed origin: ${ALLOWED_ORIGIN}`);
});
