// src/server.js
const express   = require('express');
const cors      = require('cors');
const multer    = require('multer');
const { spawn } = require('child_process');
const fs        = require('fs');
const path      = require('path');

const app  = express();
// Use PORT from env (Railway/Cloud) or 3000 locally
const PORT = process.env.PORT || 3000;

// Teach CORS to only allow our front-end URL
const FRONTEND = process.env.REACT_APP_API_URL || 'http://localhost:3000';
app.use(
  cors({
    origin: FRONTEND,
    methods: ['GET', 'POST', 'OPTIONS'],
  })
);

// Make sure uploads directory exists
const UPLOAD_DIR = path.resolve(__dirname, '../uploads');
if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

// Multer: save into ./uploads, keep original extension
const storage = multer.diskStorage({
  destination: UPLOAD_DIR,
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, `file-${Date.now()}${ext}`);
  },
});
const upload = multer({ storage });

// POST /scan → accept one file field named "file"
app.post('/scan', upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded.' });
  }

  const toScan = req.file.path;
  console.log('📂 Saved file:', toScan);

  // Semgrep configs (registry + custom)
  const configs = [
    'p/python',
    'p/javascript',
    'p/java',
    'p/go',
    'p/cpp',
    'p/php',
    'p/ruby',
    'p/sql',
    path.resolve(__dirname, '../config/custom-rules.yaml'),
  ];

  // Build semgrep args
  const args = [
    'scan',
    '--quiet',
    '--json',
    ...configs.flatMap(cfg => ['--config', cfg]),
    toScan,
  ];

  const semgrep = spawn('semgrep', args);
  let stdout = '', stderr = '';

  semgrep.stdout.on('data', d => (stdout += d));
  semgrep.stderr.on('data', d => (stderr += d));

  semgrep.on('close', code => {
    // Always cleanup the uploaded file
    fs.unlink(toScan, err => {
      if (err) console.error('🗑️ Delete failed:', err);
      else     console.log('🗑️ Deleted:', toScan);
    });

    if (code !== 0) {
      console.error('❌ Semgrep error:', stderr.trim());
      return res.status(500).json({ error: stderr.trim() });
    }

    try {
      const result = JSON.parse(stdout);
      console.log(`✅ Semgrep found ${result.results.length} issue(s)`);
      return res.json(result);
    } catch (e) {
      console.error('❌ JSON parse failed:', e.message);
      return res.status(500).json({ error: 'Invalid Semgrep output.' });
    }
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 API listening on port ${PORT}`);
});
