const express = require('express');
const cors    = require('cors');
const multer  = require('multer');
const { spawn } = require('child_process');
const fs      = require('fs');
const path    = require('path');

const app  = express();
const PORT = process.env.PORT || 3000;
const FRONT = process.env.ALLOWED_ORIGIN || 'http://localhost:3000';

// 1) CORS
app.use(cors({ origin: FRONT, methods: ['GET','POST','OPTIONS'] }));

// 2) Health endpoints
// Railway’s default probe on `/`
app.get('/', (_req,res) => res.sendStatus(200));
// Our explicit health check
app.get('/healthz', (_req,res) => res.sendStatus(200));

// 3) Ensure uploads folder
const UPLOAD_DIR = path.join(__dirname,'../uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR,{ recursive:true });

// 4) Multer setup
const upload = multer({
  storage: multer.diskStorage({
    destination: UPLOAD_DIR,
    filename: (_req,file,cb) => cb(null, `f-${Date.now()}${path.extname(file.originalname)}`)
  })
});

// 5) Scan endpoint
app.post('/scan', upload.single('file'), (req,res) => {
  if (!req.file) return res.status(400).json({ error:'No file.' });
  const file = req.file.path;
  const configs = [
    'p/python','p/javascript','p/java','p/go','p/cpp','p/php','p/ruby','p/sql',
    path.join(__dirname,'../config/custom-rules.yaml'),
  ];
  const args = ['scan','--quiet','--json', ...configs.flatMap(c=>['--config',c]), file];
  const semgrep = spawn('semgrep', args, { timeout:20000 });

  let out='', err='';
  semgrep.stdout.on('data', c=>out+=c);
  semgrep.stderr.on('data', c=>err+=c);

  semgrep.on('error', e => {
    console.error('Spawn error', e);
    fs.unlink(file,()=>{});
    res.status(500).json({ error:'Semgrep failed to start.' });
  });

  semgrep.on('close', code => {
    fs.unlink(file,()=>{});
    if (code>1) return res.status(500).json({ error:err.trim() });
    try {
      const result = JSON.parse(out);
      return res.json(result);
    } catch (e) {
      console.error('Parse error', e);
      return res.status(500).json({ error:'Bad output.' });
    }
  });
});

// 6) Start
app.listen(PORT, () => {
  console.log(`🚀 Listening on ${PORT}`);
  console.log(`🌍 CORS: ${FRONT}`);
});
