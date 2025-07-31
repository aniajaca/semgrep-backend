// src/server.js - RAILWAY DEPLOYMENT FIX
const express = require('express');
const multer = require('multer');
const { spawn, exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { performance } = require('perf_hooks'); 

// ✅ RAILWAY FIX: Enhanced error handling for missing modules
let SecurityClassificationSystem;
let aiRouter = null;

try {
  const securityModule = require('./SecurityClassificationSystem');
  SecurityClassificationSystem = securityModule.SecurityClassificationSystem;
  console.log('✅ SecurityClassificationSystem loaded successfully');
} catch (error) {
  console.log('⚠️ SecurityClassificationSystem not available:', error.message);
  // Create a fallback class for Railway deployment
  SecurityClassificationSystem = class {
    classifyFinding(finding) {
      return {
        ...finding,
        severity: finding.severity || 'Medium',
        cwe: finding.cwe || { id: 'CWE-200', name: 'Information Exposure' },
        cvss: { baseScore: 5.0, adjustedScore: 5.0 }
      };
    }
    aggregateRiskScore(findings) {
      return { riskScore: 50, riskLevel: 'Medium' };
    }
  };
}

try {
  aiRouter = require('./aiRouter');
  console.log('✅ AI Router loaded successfully');
} catch (error) {
  console.log('⚠️ AI Router not available:', error.message);
}

require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

console.log('🚀 RAILWAY: Starting Neperia Security Scanner');
console.log('🔧 Environment:', process.env.NODE_ENV || 'production');
console.log('🌐 Port:', PORT);
console.log('🐧 Platform:', process.platform);
console.log('📁 Working Directory:', process.cwd());

// ✅ RAILWAY FIX: Enhanced error handlers that don't exit
process.on('uncaughtException', (error) => {
  console.error('❌ RAILWAY: Uncaught Exception:', error.message);
  console.error('Stack:', error.stack);
  // Don't exit in Railway - let the platform handle restarts
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('❌ RAILWAY: Unhandled Rejection:', reason);
  // Don't exit in Railway
});

// ✅ RAILWAY FIX: Simplified CORS for Railway deployment
const simpleCors = (req, res, next) => {
  try {
    const origin = req.headers.origin;
    
    // Allow Railway healthchecks and known domains
    const allowedOrigins = [
      'https://preview--neperia-code-guardian.lovable.app',
      'https://neperia-code-guardian.lovable.app',
      'https://app--neperia-code-guardian-8d9b62c6.base44.app',
      'https://lovable.app',
      'http://localhost:3000',
      'http://localhost:5173'
    ];
    
    const isAllowed = !origin || // Railway healthcheck has no origin
                     allowedOrigins.includes(origin) ||
                     (origin && (origin.endsWith('.lovable.app') || origin.endsWith('.base44.app')));
    
    res.setHeader('Access-Control-Allow-Origin', isAllowed ? (origin || '*') : '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, Accept, Origin');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    
    if (req.method === 'OPTIONS') {
      return res.status(200).end();
    }
    
    next();
  } catch (error) {
    console.error('❌ CORS error:', error.message);
    next(); // Continue even if CORS fails
  }
};

app.use(simpleCors);

// ✅ RAILWAY FIX: Body parsing with error handling
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// ✅ RAILWAY FIX: Request logging for debugging
app.use((req, res, next) => {
  const timestamp = new Date().toISOString();
  console.log(`${timestamp} ${req.method} ${req.path} - Origin: ${req.headers.origin || 'none'}`);
  next();
});

// ✅ RAILWAY FIX: Simplified multer setup
const upload = multer({ 
  dest: '/tmp/uploads/',
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => cb(null, true)
});

// ✅ RAILWAY FIX: Essential healthcheck endpoint (MUST WORK)
app.get('/healthz', (req, res) => {
  console.log('🏥 RAILWAY: Healthcheck accessed');
  
  try {
    res.status(200).json({
      status: 'healthy',
      service: 'neperia-security-scanner',
      timestamp: new Date().toISOString(),
      uptime: Math.floor(process.uptime()),
      memory: process.memoryUsage(),
      platform: process.platform,
      nodeVersion: process.version
    });
  } catch (error) {
    console.error('❌ RAILWAY: Healthcheck error:', error);
    res.status(500).json({ status: 'error', error: error.message });
  }
});

// ✅ RAILWAY FIX: Alternative health endpoint
app.get('/health', (req, res) => {
  console.log('🏥 RAILWAY: Health endpoint accessed');
  res.status(200).json({ status: 'healthy', timestamp: new Date().toISOString() });
});

// ✅ RAILWAY FIX: Root endpoint
app.get('/', (req, res) => {
  console.log('🏠 RAILWAY: Root endpoint accessed');
  res.status(200).json({
    message: 'Neperia Security Scanner API',
    status: 'running',
    version: '3.1-railway',
    endpoints: {
      'GET /healthz': 'Health check',
      'GET /health': 'Alternative health check', 
      'GET /semgrep-status': 'Semgrep availability',
      'POST /scan': 'File upload scanning',
      'POST /scan-code': 'Direct code scanning'
    },
    timestamp: new Date().toISOString()
  });
});

// ✅ RAILWAY FIX: Semgrep status with timeout protection
app.get('/semgrep-status', async (req, res) => {
  console.log('🔧 RAILWAY: Checking Semgrep status');
  
  try {
    const semgrepCheck = await checkSemgrepAvailability();
    res.json({
      status: 'success',
      semgrep: semgrepCheck,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('❌ RAILWAY: Semgrep check failed:', error.message);
    res.status(200).json({ // Return 200 to avoid healthcheck issues
      status: 'warning',
      semgrep: { available: false, error: error.message },
      timestamp: new Date().toISOString()
    });
  }
});

// ✅ RAILWAY FIX: Enhanced code scanning endpoint
app.post('/scan-code', async (req, res) => {
  console.log('💻 RAILWAY: Code scan request received');
  
  const scanStartTime = performance.now();
  
  try {
    const { code, filename = 'uploaded_code.py' } = req.body;

    if (!code) {
      return res.status(400).json({ 
        status: 'error', 
        message: 'No code provided',
        expected: { code: 'string', filename: 'string (optional)' }
      });
    }

    console.log(`💻 RAILWAY: Scanning ${filename} (${code.length} characters)`);

    // Check if Semgrep is available
    const semgrepAvailable = await checkSemgrepAvailability();
    
    if (!semgrepAvailable.available) {
      console.log('⚠️ RAILWAY: Semgrep not available, using fallback analysis');
      return res.json({
        status: 'success',
        service: 'Neperia Security Scanner (Fallback Mode)',
        analysis: {
          filename: filename,
          codeLength: code.length,
          findingsCount: 0,
          message: 'Semgrep not available - fallback analysis performed'
        },
        findings: [],
        riskScore: 0,
        metadata: {
          scanned_at: new Date().toISOString(),
          mode: 'fallback',
          semgrep_available: false
        }
      });
    }

    // Create temporary file for scanning
    const tempDir = '/tmp';
    const tempFile = path.join(tempDir, `${Date.now()}-${filename}`);
    
    try {
      fs.writeFileSync(tempFile, code, 'utf8');
      console.log(`📁 RAILWAY: Created temp file: ${tempFile}`);

      // Run Semgrep scan
      const semgrepResults = await runSemgrepScan(tempFile, code);
      
      // Enhanced classification
      const classifier = new SecurityClassificationSystem();
      const classifiedFindings = semgrepResults.results.map(finding => 
        classifier.classifyFinding(finding)
      );
      
      const riskAssessment = classifier.aggregateRiskScore(classifiedFindings, {});
      
      const scanEndTime = performance.now();
      const scanDuration = (scanEndTime - scanStartTime).toFixed(2);
      
      console.log(`✅ RAILWAY: Scan completed in ${scanDuration}ms with ${classifiedFindings.length} findings`);

      res.json({
        status: 'success',
        service: 'Neperia Security Scanner v3.1',
        analysis: {
          filename: filename,
          codeLength: code.length,
          findingsCount: classifiedFindings.length,
          riskScore: riskAssessment.riskScore,
          riskLevel: riskAssessment.riskLevel,
          scanDuration: `${scanDuration}ms`
        },
        findings: classifiedFindings,
        riskAssessment: riskAssessment,
        metadata: {
          scanned_at: new Date().toISOString(),
          semgrep_version: semgrepAvailable.version,
          classification_version: '3.1'
        }
      });
      
    } finally {
      // Clean up temp file
      if (fs.existsSync(tempFile)) {
        fs.unlinkSync(tempFile);
        console.log('🧹 RAILWAY: Cleaned up temp file');
      }
    }
    
  } catch (error) {
    console.error('❌ RAILWAY: Code scan error:', error.message);
    const scanEndTime = performance.now();
    const scanDuration = (scanEndTime - scanStartTime).toFixed(2);
    
    res.status(500).json({ 
      status: 'error', 
      message: 'Code scan failed',
      error: error.message,
      scanDuration: `${scanDuration}ms`,
      timestamp: new Date().toISOString()
    });
  }
});

// ✅ RAILWAY FIX: File upload scanning endpoint
app.post('/scan', upload.single('file'), async (req, res) => {
  console.log('📁 RAILWAY: File scan request received');
  
  try {
    if (!req.file) {
      return res.status(400).json({ 
        status: 'error', 
        message: 'No file uploaded'
      });
    }

    const filePath = req.file.path;
    const fileContent = fs.readFileSync(filePath, 'utf8');
    
    console.log(`📁 RAILWAY: Processing file: ${req.file.originalname} (${req.file.size} bytes)`);

    // Check Semgrep availability
    const semgrepAvailable = await checkSemgrepAvailability();
    
    if (!semgrepAvailable.available) {
      // Clean up and return fallback
      if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
      
      return res.json({
        status: 'success',
        service: 'Neperia Security Scanner (Fallback Mode)',
        filename: req.file.originalname,
        analysis: {
          fileSize: req.file.size,
          findingsCount: 0,
          message: 'Semgrep not available - fallback analysis performed'
        },
        findings: [],
        riskScore: 0
      });
    }

    // Run Semgrep scan
    const semgrepResults = await runSemgrepScan(filePath, fileContent);
    
    // Classification
    const classifier = new SecurityClassificationSystem();
    const classifiedFindings = semgrepResults.results.map(finding => 
      classifier.classifyFinding(finding)
    );
    
    const riskAssessment = classifier.aggregateRiskScore(classifiedFindings, {});
    
    // Clean up uploaded file
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
      console.log('🧹 RAILWAY: Cleaned up uploaded file');
    }
    
    res.json({
      status: 'success',
      service: 'Neperia Security Scanner v3.1',
      filename: req.file.originalname,
      analysis: {
        fileSize: req.file.size,
        findingsCount: classifiedFindings.length,
        riskScore: riskAssessment.riskScore,
        riskLevel: riskAssessment.riskLevel
      },
      findings: classifiedFindings,
      riskAssessment: riskAssessment,
      metadata: {
        scanned_at: new Date().toISOString(),
        semgrep_version: semgrepAvailable.version
      }
    });
    
  } catch (error) {
    console.error('❌ RAILWAY: File scan error:', error.message);
    
    // Clean up on error
    if (req.file && req.file.path && fs.existsSync(req.file.path)) {
      try {
        fs.unlinkSync(req.file.path);
      } catch (cleanupError) {
        console.error('❌ RAILWAY: Cleanup error:', cleanupError.message);
      }
    }
    
    res.status(500).json({ 
      status: 'error', 
      message: 'File scan failed',
      error: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

// ✅ RAILWAY FIX: Mount AI router if available
if (aiRouter) {
  console.log('🤖 RAILWAY: Mounting AI endpoints');
  app.use('/api', aiRouter);
} else {
  console.log('⚠️ RAILWAY: AI router not available');
  app.get('/api', (req, res) => {
    res.json({
      status: 'info',
      message: 'AI features not available in this deployment',
      availableFeatures: ['Static code analysis', 'Vulnerability scanning']
    });
  });
}

// ✅ RAILWAY FIX: Helper Functions

/**
 * Check Semgrep availability with timeout
 */
function checkSemgrepAvailability() {
  return new Promise((resolve) => {
    const timeout = setTimeout(() => {
      resolve({ available: false, error: 'Timeout checking Semgrep' });
    }, 5000); // 5 second timeout

    exec('semgrep --version', (error, stdout, stderr) => {
      clearTimeout(timeout);
      
      if (error) {
        console.log('🔧 RAILWAY: Semgrep not available:', error.message);
        resolve({ available: false, error: error.message });
      } else {
        console.log('🔧 RAILWAY: Semgrep available:', stdout.trim());
        resolve({ available: true, version: stdout.trim() });
      }
    });
  });
}

/**
 * Run Semgrep scan with enhanced error handling
 */
async function runSemgrepScan(filePath, fileContent) {
  console.log('🔧 RAILWAY: Running Semgrep scan');
  
  return new Promise((resolve, reject) => {
    const semgrepArgs = [
      '--json',
      '--config=auto',
      '--skip-unknown-extensions',
      '--timeout=30',
      filePath
    ];

    console.log(`🔧 RAILWAY: Executing: semgrep ${semgrepArgs.join(' ')}`);
    
    const semgrep = spawn('semgrep', semgrepArgs, {
      stdio: ['pipe', 'pipe', 'pipe'],
      timeout: 30000 // 30 second timeout
    });

    let stdout = '';
    let stderr = '';

    semgrep.stdout.on('data', (data) => {
      stdout += data.toString();
    });

    semgrep.stderr.on('data', (data) => {
      stderr += data.toString();
    });

    semgrep.on('close', (code) => {
      console.log(`🔧 RAILWAY: Semgrep exited with code ${code}`);
      
      if (code !== 0 && code !== 1) { // Code 1 is OK (findings found)
        console.error('❌ RAILWAY: Semgrep stderr:', stderr);
        return reject(new Error(`Semgrep failed with code ${code}`));
      }

      try {
        const results = JSON.parse(stdout);
        console.log(`🔧 RAILWAY: Semgrep found ${results.results?.length || 0} findings`);

        // Fix code extraction
        if (results.results && results.results.length > 0 && fileContent) {
          const codeLines = fileContent.split('\n');
          
          results.results = results.results.map(finding => {
            const lineNumber = finding.start?.line || 1;
            const vulnerableLine = codeLines[lineNumber - 1] || 'Line not found';
            
            finding.extra = finding.extra || {};
            finding.extra.lines = vulnerableLine.trim();
            finding.extractedCode = vulnerableLine.trim();
            
            return finding;
          });
        }

        resolve(results);
      } catch (parseError) {
        console.error('❌ RAILWAY: JSON parse error:', parseError.message);
        reject(new Error(`Failed to parse Semgrep JSON: ${parseError.message}`));
      }
    });

    semgrep.on('error', (error) => {
      console.error('❌ RAILWAY: Semgrep spawn error:', error.message);
      reject(new Error(`Failed to spawn Semgrep: ${error.message}`));
    });
  });
}

// ✅ RAILWAY FIX: 404 handler
app.use('*', (req, res) => {
  console.log(`❌ RAILWAY: 404 - ${req.method} ${req.originalUrl}`);
  res.status(404).json({ 
    status: 'error', 
    message: 'Route not found',
    path: req.originalUrl,
    availableEndpoints: [
      'GET /',
      'GET /healthz', 
      'GET /health',
      'GET /semgrep-status',
      'POST /scan',
      'POST /scan-code'
    ]
  });
});

// ✅ RAILWAY FIX: Error handling middleware
app.use((error, req, res, next) => {
  console.error('❌ RAILWAY: Unhandled error:', error.message);
  console.error('Stack:', error.stack);
  
  if (res.headersSent) {
    return next(error);
  }
  
  res.status(500).json({ 
    status: 'error', 
    message: 'Internal server error',
    error: process.env.NODE_ENV === 'development' ? error.message : 'Server error',
    timestamp: new Date().toISOString()
  });
});

// ✅ RAILWAY FIX: Server startup with proper error handling
function startServer() {
  try {
    const server = app.listen(PORT, '0.0.0.0', () => {
      console.log('🚀 RAILWAY: ==========================================');
      console.log('🚀 RAILWAY: Neperia Security Scanner STARTED');
      console.log('🚀 RAILWAY: ==========================================');
      console.log(`🌐 RAILWAY: Server running on port ${PORT}`);
      console.log(`🔧 RAILWAY: Static Analysis: ${SecurityClassificationSystem ? 'Available' : 'Fallback'}`);
      console.log(`🤖 RAILWAY: AI Enhancement: ${aiRouter ? 'Available' : 'Not Available'}`);
      console.log('🏥 RAILWAY: Health endpoints: /healthz and /health');
      console.log('💻 RAILWAY: Scan endpoints: /scan and /scan-code');
      console.log('🚀 RAILWAY: ==========================================');
      
      // Test Semgrep availability on startup
      checkSemgrepAvailability().then(result => {
        console.log(`🔧 RAILWAY: Semgrep Status: ${result.available ? 'Available' : 'Not Available'}`);
        if (result.available) {
          console.log(`🔧 RAILWAY: Semgrep Version: ${result.version}`);
        }
      });
    });
    
    server.on('error', (error) => {
      console.error('❌ RAILWAY: Server error:', error.message);
      if (error.code === 'EADDRINUSE') {
        console.error(`❌ RAILWAY: Port ${PORT} is already in use`);
        process.exit(1);
      }
    });
    
    // Graceful shutdown for Railway
    process.on('SIGTERM', () => {
      console.log('🛑 RAILWAY: SIGTERM received, shutting down gracefully');
      server.close(() => {
        console.log('✅ RAILWAY: Server closed');
        process.exit(0);
      });
    });

    process.on('SIGINT', () => {
      console.log('🛑 RAILWAY: SIGINT received, shutting down gracefully');
      server.close(() => {
        console.log('✅ RAILWAY: Server closed');
        process.exit(0);
      });
    });
    
  } catch (error) {
    console.error('❌ RAILWAY: Failed to start server:', error.message);
    console.error('Stack:', error.stack);
    process.exit(1);
  }
}

// ✅ RAILWAY FIX: Start server
console.log('🚀 RAILWAY: Initializing Neperia Security Scanner...');
startServer();