const express = require('express');
const multer = require('multer');
const { spawn, exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { performance } = require('perf_hooks');

// Import your custom modules
const { deduplicateFindings } = require('./findingDeduplicator');
const { calculateRiskScore } = require('./riskCalculator');

// Optional: Import SecurityClassificationSystem if you have it
// const { SecurityClassificationSystem } = require('./SecurityClassificationSystem');
// const classifier = new SecurityClassificationSystem();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Global error handlers to prevent crashes
process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error);
  console.error('Stack:', error.stack);
  if (process.env.NODE_ENV !== 'production') {
    process.exit(1);
  }
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
  if (process.env.NODE_ENV !== 'production') {
    process.exit(1);
  }
});

// Enhanced startup logging
console.log('=== SERVER STARTUP ===');
console.log('Node version:', process.version);
console.log('Platform:', process.platform);
console.log('Environment:', process.env.NODE_ENV || 'development');
console.log('Port:', PORT);
console.log('Current working directory:', process.cwd());
console.log('Temp directory:', os.tmpdir());

// FIXED CORS middleware - properly configured for Base44 and Lovable frontends
const customCors = (req, res, next) => {
  try {
    const origin = req.headers.origin;
    
    // List of allowed origins (fixed syntax)
    const allowedOrigins = [
      'https://preview--neperia-code-guardian.lovable.app',
      'http://app--neperia-code-guardian-8d9b62c6.base44.app',
      'https://app--neperia-code-guardian-8d9b62c6.base44.app',
      'https://app.base44.com',
      'https://neperia-code-guardian.lovable.app',
      'https://lovable.app',
      'http://localhost:3000',
      'http://localhost:5173'
    ];
    
    // Check if origin is allowed
    const isAllowed = allowedOrigins.includes(origin) || 
                     (origin && (origin.includes('.lovable.app') || origin.includes('.base44.app')));
    
    if (isAllowed || !origin) {
      res.setHeader('Access-Control-Allow-Origin', origin || '*');
    } else {
      res.setHeader('Access-Control-Allow-Origin', 'https://preview--neperia-code-guardian.lovable.app');
    }
    
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, Accept, Origin');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Max-Age', '86400');
    
    if (req.method === 'OPTIONS') {
      return res.sendStatus(204);
    }
    
    next();
  } catch (error) {
    console.error('CORS error:', error);
    next(error);
  }
};

app.use(customCors);

// Helper function to check Semgrep availability
async function checkSemgrepAvailability() {
  return new Promise((resolve) => {
    exec('semgrep --version', (error, stdout, stderr) => {
      if (error) {
        resolve({ available: false, error: error.message });
      } else {
        resolve({ available: true, version: stdout.trim() });
      }
    });
  });
}

// Helper function to parse Semgrep results
function parseSemgrepResults(results) {
  if (!results || !results.results) {
    return [];
  }
  
  return results.results.map(finding => ({
    // Basic info
    severity: finding.extra?.severity || 'info',
    title: finding.extra?.message || finding.check_id,
    description: finding.extra?.metadata?.cwe || finding.check_id,
    
    // Location info
    path: finding.path,
    file: finding.path,
    start: { line: finding.start?.line || 0 },
    end: { line: finding.end?.line || 0 },
    
    // Security metadata
    cwe: finding.extra?.metadata?.cwe ? { id: finding.extra.metadata.cwe } : { id: 'UNKNOWN' },
    owasp: { category: finding.extra?.metadata?.owasp || 'UNKNOWN' },
    cvss: { baseScore: finding.extra?.metadata?.impact === 'HIGH' ? 7.5 : 
            finding.extra?.metadata?.impact === 'MEDIUM' ? 5.0 : 3.0 },
    
    // Original data
    check_id: finding.check_id,
    code_snippet: finding.extra?.lines || ''
  }));
}

// Enhanced Semgrep scanning function
async function runSemgrepScanWithCodeExtraction(filePath, originalCode) {
  return new Promise((resolve, reject) => {
    const semgrepProcess = spawn('semgrep', [
      '--config=auto',
      '--json',
      '--no-git-ignore',
      filePath
    ]);

    let stdout = '';
    let stderr = '';

    semgrepProcess.stdout.on('data', (data) => {
      stdout += data.toString();
    });

    semgrepProcess.stderr.on('data', (data) => {
      stderr += data.toString();
    });

    semgrepProcess.on('close', (code) => {
      console.log('Semgrep process exited with code:', code);
      
      try {
        const results = JSON.parse(stdout);
        resolve(results);
      } catch (error) {
        console.error('Failed to parse Semgrep output:', error);
        resolve({ results: [] });
      }
    });

    semgrepProcess.on('error', (error) => {
      console.error('Semgrep process error:', error);
      reject(error);
    });
  });
}

// 🔧 ENHANCED: Code scanning endpoint with deduplication and risk calculation
app.post('/scan-code', async (req, res) => {
  console.log('=== CODE SCAN REQUEST RECEIVED ===');
  console.log('Headers:', req.headers);
  console.log('Origin:', req.headers.origin);
  
  // Performance monitoring
  const scanStartTime = performance.now();
  const memBefore = process.memoryUsage();
  
  try {
    const { code, language = 'javascript', filename = 'code.js' } = req.body;
    
    if (!code || typeof code !== 'string' || code.trim() === '') {
      return res.status(400).json({ 
        status: 'error', 
        message: 'No code provided' 
      });
    }

    console.log('Code length:', code.length);
    console.log('Language:', language);
    console.log('Filename:', filename);

    // Check if Semgrep is available
    const semgrepAvailable = await checkSemgrepAvailability();
    if (!semgrepAvailable.available) {
      return res.status(503).json({
        status: 'error',
        message: 'Semgrep is not available',
        details: semgrepAvailable.error
      });
    }

    // Create temporary file with the code
    const tempDir = path.join(os.tmpdir(), 'scan-temp');
    if (!fs.existsSync(tempDir)) {
      fs.mkdirSync(tempDir, { recursive: true });
    }
    
    const tempFilePath = path.join(tempDir, `${Date.now()}-${filename}`);
    fs.writeFileSync(tempFilePath, code, 'utf8');
    
    console.log('Created temp file:', tempFilePath);

    // Run Semgrep scan
    const semgrepStartTime = performance.now();
    const semgrepResults = await runSemgrepScanWithCodeExtraction(tempFilePath, code);
    const semgrepEndTime = performance.now();
    
    // Parse and process findings
    const parsedFindings = parseSemgrepResults(semgrepResults);
    console.log(`Parsed ${parsedFindings.length} findings from Semgrep`);
    
    // Apply deduplication
    const deduplicationStartTime = performance.now();
    const deduplicatedFindings = deduplicateFindings(parsedFindings);
    const deduplicationEndTime = performance.now();
    console.log(`Deduplicated to ${deduplicatedFindings.length} unique findings`);
    
    // Calculate risk score
    const riskStartTime = performance.now();
    const riskAssessment = calculateRiskScore(deduplicatedFindings);
    const riskEndTime = performance.now();
    
    // Clean up temp file
    if (fs.existsSync(tempFilePath)) {
      fs.unlinkSync(tempFilePath);
      console.log('Cleaned up temp file');
    }
    
    // Calculate performance metrics
    const scanEndTime = performance.now();
    const memAfter = process.memoryUsage();
    
    const performanceMetrics = {
      totalScanTime: `${(scanEndTime - scanStartTime).toFixed(2)}ms`,
      semgrepTime: `${(semgrepEndTime - semgrepStartTime).toFixed(2)}ms`,
      deduplicationTime: `${(deduplicationEndTime - deduplicationStartTime).toFixed(2)}ms`,
      riskCalculationTime: `${(riskEndTime - riskStartTime).toFixed(2)}ms`,
      memoryUsed: `${Math.round((memAfter.heapUsed - memBefore.heapUsed) / 1024 / 1024)}MB`,
      totalMemory: `${Math.round(memAfter.heapTotal / 1024 / 1024)}MB`
    };
    
    console.log('🔧 PERFORMANCE METRICS:', performanceMetrics);
    
    // Send response with all the analysis
    res.json({
      status: 'success',
      language: language,
      findings: deduplicatedFindings,
      riskAssessment: riskAssessment,
      metadata: {
        scanned_at: new Date().toISOString(),
        code_length: code.length,
        semgrep_version: semgrepAvailable.version,
        original_findings_count: parsedFindings.length,
        deduplicated_findings_count: deduplicatedFindings.length,
        reduction_percentage: parsedFindings.length > 0 
          ? Math.round(((parsedFindings.length - deduplicatedFindings.length) / parsedFindings.length) * 100)
          : 0,
        performance: performanceMetrics
      }
    });
    
  } catch (error) {
    console.error('Code scan error:', error);
    console.error('Stack trace:', error.stack);
    
    const errorEndTime = performance.now();
    const errorResponseTime = `${(errorEndTime - scanStartTime).toFixed(2)}ms`;
    
    res.status(500).json({ 
      status: 'error', 
      message: 'Code scan failed',
      error: error.message,
      timestamp: new Date().toISOString(),
      performance: {
        errorResponseTime: errorResponseTime
      }
    });
  }
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memory: process.memoryUsage()
  });
});

// Simple test endpoint - no Semgrep needed
app.post('/test-scan', (req, res) => {
  const { code } = req.body;
  
  // Fake findings for testing
  const testFindings = [
    {
      severity: 'high',
      title: 'Hardcoded Password',
      description: 'Password found in code',
      path: 'test.js',
      file: 'test.js',
      start: { line: 10 },
      cwe: { id: 'CWE-798' },
      owasp: { category: 'A07:2021' },
      cvss: { baseScore: 7.5 }
    },
    {
      severity: 'medium',
      title: 'SQL Injection Risk',
      description: 'Potential SQL injection',
      path: 'test.js',
      file: 'test.js',
      start: { line: 25 },
      cwe: { id: 'CWE-89' },
      owasp: { category: 'A03:2021' },
      cvss: { baseScore: 5.0 }
    }
  ];
  
  // Test deduplication
  const deduplicatedFindings = deduplicateFindings(testFindings);
  
  // Test risk calculation
  const riskAssessment = calculateRiskScore(deduplicatedFindings);
  
  res.json({
    status: 'success',
    message: 'Test scan completed',
    findings: deduplicatedFindings,
    riskAssessment: riskAssessment,
    metadata: {
      original_count: testFindings.length,
      deduplicated_count: deduplicatedFindings.length
    }
  });
});

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    name: 'Neperia Cybersecurity Analysis Tool',
    version: '3.0',
    status: 'operational',
    endpoints: {
      '/scan-code': 'POST - Scan code for vulnerabilities',
      '/health': 'GET - Health check'
    },
    features: [
      'Semgrep static analysis',
      'Finding deduplication',
      'Risk score calculation',
      'OWASP/CWE mapping'
    ]
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
  console.log(`🌐 Accepting requests from Base44 and Lovable frontends`);
  console.log(`🔧 Features enabled:`);
  console.log(`   - Semgrep static analysis`);
  console.log(`   - Finding deduplication`);
  console.log(`   - Risk calculation with multipliers`);
  console.log(`   - Performance monitoring`);
  
  // Check system readiness
  checkSemgrepAvailability().then(status => {
    if (status.available) {
      console.log(`✅ Semgrep available: ${status.version}`);
    } else {
      console.log(`❌ Semgrep not available: ${status.error}`);
      console.log(`   Install with: pip install semgrep`);
    }
  });
});

module.exports = app;