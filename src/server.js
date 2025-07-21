// server.js

const express = require('express');
const multer  = require('multer');
const { spawn, exec } = require('child_process');
const fs      = require('fs');
const path    = require('path');
const os      = require('os');

const { deduplicateFindings }             = require('./findingDeduplicator');
const { calculateRiskScore }              = require('./riskCalculator');
const { SecurityClassificationSystem }    = require('./SecurityClassificationSystem.js');
const classifier = new SecurityClassificationSystem();

const app  = express();
const PORT = process.env.PORT || 3000;

/** GLOBAL ERROR HANDLERS **/
process.on('uncaughtException', err => {
  console.error('Uncaught Exception:', err);
  console.error(err.stack);
  if (process.env.NODE_ENV !== 'production') process.exit(1);
});
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
  if (process.env.NODE_ENV !== 'production') process.exit(1);
});

/** STARTUP LOGS **/
console.log('=== SERVER STARTUP ===');
console.log('Node:', process.version);
console.log('Platform:', process.platform);
console.log('Env:', process.env.NODE_ENV || 'development');
console.log('Port:', PORT);
console.log('Temp dir:', os.tmpdir());

/** CORS MIDDLEWARE **/
const customCors = (req, res, next) => {
  try {
    const origin = req.headers.origin;
    const allowList = [
      'https://preview--neperia-code-guardian.lovable.app',
      'https://neperia-code-guardian.lovable.app',
      'https://lovable.app',
      'http://localhost:3000',
      'http://localhost:5173'
    ];
    const allowed = allowList.includes(origin) || (origin && origin.includes('.lovable.app'));
    res.setHeader('Access-Control-Allow-Origin', allowed || !origin ? (origin||'*') : allowList[0]);
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization,X-Requested-With,Accept,Origin');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Max-Age', '86400');
    if (req.method === 'OPTIONS') return res.status(200).end();
    next();
  } catch (e) {
    console.error('CORS error:', e);
    next(e);
  }
};

/** REQUEST LOGGING + BODY PARSING **/
app.use(customCors);
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} ${req.method} ${req.path} Origin:${req.headers.origin||'none'}`);
  next();
});

/** MULTER CONFIG **/
const storage = multer.diskStorage({
  destination: (_req, _file, cb) => {
    const dir = path.join(os.tmpdir(), 'uploads');
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (_req, file, cb) => cb(null, `${Date.now()}-${file.originalname}`)
});
const upload = multer({ storage, limits: { fileSize: 10 * 1024 * 1024 } });

/** HEALTH & ROOT **/
app.get('/', (_req, res) => {
  res.json({
    message: 'Cybersecurity Scanner API running',
    endpoints: {
      GET___: '/',
      HEALTHZ: '/healthz',
      SEMGREP_STATUS: '/semgrep-status',
      SCAN_FILE: '/scan',
      SCAN_CODE: '/scan-code'
    }
  });
});

app.get('/healthz', (_req, res) => {
  res.set({ 'Content-Type':'application/json','Cache-Control':'no-cache' })
     .json({ status:'healthy', uptime:process.uptime(), timestamp:new Date().toISOString() });
});

app.get('/health', (_req, res) => {
  res.json({ status:'healthy', service:'semgrep-scanner', timestamp:new Date().toISOString() });
});

/** DEBUG ENDPOINT **/
app.get('/debug', (req, res) => {
  res.json({
    headers: req.headers,
    ip:      req.ip,
    ips:     req.ips,
    method:  req.method,
    path:    req.path,
    query:   req.query,
    timestamp: new Date().toISOString(),
    port:      PORT,
    env:       process.env.NODE_ENV,
    railway: {
      deploymentId: process.env.RAILWAY_DEPLOYMENT_ID,
      projectId:    process.env.RAILWAY_PROJECT_ID,
      serviceId:    process.env.RAILWAY_SERVICE_ID,
      environment:  process.env.RAILWAY_ENVIRONMENT,
    }
  });
});

/** SEMGREP AVAILABILITY **/
function checkSemgrepAvailability() {
  return new Promise(resolve => {
    exec('semgrep --version', (err, stdout, stderr) => {
      if (err) return resolve({ available:false, error:err.message, stderr });
      resolve({ available:true, version:stdout.trim() });
    });
  });
}

app.get('/semgrep-status', async (_req, res) => {
  try {
    const status = await checkSemgrepAvailability();
    res.json({ status:'success', semgrep:status, timestamp:new Date().toISOString() });
  } catch (e) {
    res.status(500).json({ status:'error', message:'Semgrep check failed', error:e.message });
  }
});

/** RUN SEMGREP & EXTRACT CODE **/
function runSemgrepScanWithCodeExtraction(filePath, originalCode) {
  return new Promise((resolve, reject) => {
    if (!fs.existsSync(filePath)) return reject(new Error('File not found: '+filePath));
    const args = ['--json','--config=auto','--skip-unknown-extensions','--timeout=30','--verbose',filePath];
    const proc = spawn('semgrep', args, { env:{...process.env, PATH:process.env.PATH} });
    let out='', errOut='';
    proc.stdout.on('data', d => out += d);
    proc.stderr.on('data', d => errOut += d);
    proc.on('close', code => {
      if (code!==0 && code!==1) return reject(new Error(`Semgrep failed (${code}): ${errOut}`));
      try {
        const parsed = out ? JSON.parse(out) : { results: [] };
        const results = parsed.results||[];
        const lines = originalCode.split('\n');
        results.forEach(f => {
          const ln = f.start?.line||1;
          const snippet = lines[ln-1]||'';
          f.extra = f.extra||{};
          f.extra.lines = snippet.trim();
          f.extractedCode = snippet.trim();
          const start = Math.max(0,ln-3), end = Math.min(lines.length,ln+2);
          f.extra.context = lines.slice(start,end).join('\n');
        });
        resolve({ results, performance: parsed.performance||{} });
      } catch (e) {
        resolve({ results:[], performance:{}, parseError:e.message });
      }
    });
    setTimeout(() => { proc.kill('SIGTERM'); reject(new Error('Semgrep timeout')); }, 45000);
  });
}

/** SCAN-CODE ENDPOINT **/
app.post('/scan-code', async (req, res) => {
  try {
    const { code, filename='code.js' } = req.body;
    if (!code) return res.status(400).json({ error:'No code provided' });

    const semStat = await checkSemgrepAvailability();
    if (!semStat.available) return res.status(503).json({ error:'Semgrep unavailable', details:semStat.error });

    const tmpDir = path.join(os.tmpdir(),'scan-temp');
    if (!fs.existsSync(tmpDir)) fs.mkdirSync(tmpDir,{recursive:true});
    const fp = path.join(tmpDir, `${Date.now()}-${filename}`);
    fs.writeFileSync(fp, code, 'utf8');

    const semRes = await runSemgrepScanWithCodeExtraction(fp, code);
    fs.unlinkSync(fp);

    const rawFindings = semRes.results;
    const deduped      = deduplicateFindings(rawFindings);
    const classified   = classifier.classifyFindings(deduped);
    const riskSummary  = calculateRiskScore(deduped);

    res.json({
      findings:      classified,
      riskSummary,
      metadata: {
        scanTime:       new Date().toISOString(),
        findingsCount:  deduped.length,
        originalCount:  rawFindings.length,
        performance:    semRes.performance
      }
    });
  } catch (e) {
    console.error('scan-code error:', e);
    res.status(500).json({ error:e.message });
  }
});

/** SCAN (FILE UPLOAD) ENDPOINT **/
app.post('/scan', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error:'No file uploaded' });

    const semStat = await checkSemgrepAvailability();
    if (!semStat.available) {
      fs.unlinkSync(req.file.path);
      return res.status(503).json({ error:'Semgrep unavailable', details:semStat.error });
    }

    const content = fs.readFileSync(req.file.path,'utf8');
    const semRes  = await runSemgrepScanWithCodeExtraction(req.file.path, content);
    fs.unlinkSync(req.file.path);

    const rawFindings = semRes.results;
    const deduped      = deduplicateFindings(rawFindings);
    const classified   = classifier.classifyFindings(deduped);
    const riskSummary  = calculateRiskScore(deduped);

    res.json({
      findings:      classified,
      riskSummary,
      metadata: {
        scanTime:      new Date().toISOString(),
        findingsCount: deduped.length,
        originalCount: rawFindings.length,
        performance:   semRes.performance
      }
    });
  } catch (e) {
    console.error('scan error:', e);
    if (req.file?.path && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
    res.status(500).json({ error:e.message });
  }
});

/** 404 HANDLER **/
app.use('*', (req, res) => {
  res.status(404).json({ error:'Route not found', path:req.originalUrl });
});

/** ERROR MIDDLEWARE **/
app.use((err, _req, res, _next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error:'Internal server error', message:err.message });
});

/** START SERVER **/
app.listen(PORT, () => {
  console.log(`Server listening on 0.0.0.0:${PORT}`);
});
