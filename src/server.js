// src/server.js
const express = require('express');
const cors    = require('cors');
const multer  = require('multer');
const { spawn } = require('child_process');
const fs      = require('fs');
const path    = require('path');

const app  = express();
const PORT = 3000;

// Multer: save into ./uploads, keep original extension
const storage = multer.diskStorage({
  destination: path.resolve(__dirname, '../uploads'),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, `file-${Date.now()}${ext}`);
  }
});
const upload = multer({ storage });

app.use(cors());

app.post('/scan', upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded.' });
  }

  const toScan = req.file.path;
  console.log('📂 Saved file:', toScan);

  // 1) Registry rulesets you want
  // 2) Your local custom rule file (config/custom-rules.yaml)
  const configs = [
    'p/python',
    'p/javascript',
    'p/java',
    'p/go',
    'p/cpp',
    'p/php',
    'p/ruby',
    'p/sql',
    path.resolve(__dirname, '../config/custom-rules.yaml')
  ];

  // build args: semgrep scan --quiet --json --config X --config Y <file>
  const args = [
    'scan',
    '--quiet',
    '--json',
    ...configs.flatMap(cfg => ['--config', cfg]),
    toScan
  ];

  const semgrep = spawn('semgrep', args);

  let stdout = '';
  let stderr = '';
  semgrep.stdout.on('data', d => (stdout += d));
  semgrep.stderr.on('data', d => (stderr += d));

  semgrep.on('close', code => {
    // clean up
    fs.unlink(toScan, err => {
      if (err) console.error('🗑️ Failed to delete upload:', err);
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

app.listen(PORT, () => {
  console.log(`🚀 API listening on http://localhost:${PORT}`);
});
