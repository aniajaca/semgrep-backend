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
const { SecurityClassificationSystem } = require('./SecurityClassificationSystem');

// Initialize the classification system
const classifier = new SecurityClassificationSystem();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Global error handlers
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

// Startup logging
console.log('=== SERVER STARTUP ===');
console.log('Node version:', process.version);
console.log('Platform:', process.platform);
console.log('Environment:', process.env.NODE_ENV || 'development');
console.log('Port:', PORT);
console.log('Current working directory:', process.cwd());
console.log('Temp directory:', os.tmpdir());

// CORS middleware
const customCors = (req, res, next) => {
  try {
    const origin = req.headers.origin;

    // 1. Add your deployed domain here!
    const allowedOrigins = [
      'https://preview--neperia-code-guardian.lovable.app',
      'http://app--neperia-code-guardian-8d9b62c6.base44.app',
      'https://app--neperia-code-guardian-8d9b62c6.base44.app',
      'https://app.base44.com',
      'https://neperia-code-guardian.lovable.app',
      'https://lovable.app',
      'http://localhost:3000',
      'http://localhost:5173',
      // Your LovableProject deploy:
      'https://356d1a6f-4978-4c1f-974e-f19cf43a8d1c.lovableproject.com'
    ];

    // 2. Wildcard for *.lovableproject.com, *.lovable.app, *.base44.app
    const isAllowed =
      allowedOrigins.includes(origin) ||
      (origin &&
        (
          origin.endsWith('.lovableproject.com') ||
          origin.includes('.lovable.app') ||
          origin.includes('.base44.app')
        )
      );

    if (isAllowed || !origin) {
      res.setHeader('Access-Control-Allow-Origin', origin || '*');
    } else {
      // Default fallback (optional)
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
        console.log('Semgrep not available, using mock data');
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
    check_id: finding.check_id,
    path: finding.path,
    start: finding.start || { line: 0, col: 0 },
    end: finding.end || finding.start || { line: 0, col: 0 },
    message: finding.extra?.message || finding.check_id,
    severity: finding.extra?.severity || 'info',
    extra: finding.extra || {},
    code: finding.extra?.lines || ''
  }));
}

// Mock findings for when Semgrep isn't available
function getMockFindings(code) {
  const findings = [];
  const lines = code.split('\n');
  
  lines.forEach((line, index) => {
    if (line.includes('password') && (line.includes('"') || line.includes("'"))) {
      findings.push({
        check_id: 'security.hardcoded-password',
        path: 'code.js',
        start: { line: index + 1, col: 1 },
        message: 'Hardcoded password detected',
        severity: 'high',
        extra: {
          metadata: { cwe: 'CWE-798' },
          lines: line.trim()
        }
      });
    }
    
    if (line.includes('SELECT') && line.includes('+')) {
      findings.push({
        check_id: 'security.sql-injection',
        path: 'code.js',
        start: { line: index + 1, col: 1 },
        message: 'Potential SQL injection vulnerability',
        severity: 'high',
        extra: {
          metadata: { cwe: 'CWE-89' },
          lines: line.trim()
        }
      });
    }
    
    if (line.includes('eval(')) {
      findings.push({
        check_id: 'security.code-injection',
        path: 'code.js',
        start: { line: index + 1, col: 1 },
        message: 'Use of eval() can lead to code injection',
        severity: 'critical',
        extra: {
          metadata: { cwe: 'CWE-94' },
          lines: line.trim()
        }
      });
    }
    
    if (line.toLowerCase().includes('md5')) {
      findings.push({
        check_id: 'security.weak-crypto',
        path: 'code.js',
        start: { line: index + 1, col: 1 },
        message: 'Use of weak cryptographic algorithm MD5',
        severity: 'medium',
        extra: {
          metadata: { cwe: 'CWE-327' },
          lines: line.trim()
        }
      });
    }
  });
  
  return findings;
}

// Run Semgrep scan
async function runSemgrepScan(filePath) {
  return new Promise((resolve, reject) => {
    const semgrepProcess = spawn('semgrep', [
      '--json',
      '--config=auto',
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

// Main code scanning endpoint
app.post('/scan-code', async (req, res) => {
  console.log('=== CODE SCAN REQUEST RECEIVED ===');
  console.log('Headers:', req.headers);
  console.log('Origin:', req.headers.origin);
  
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
    
    let parsedFindings = [];
    let semgrepStartTime = performance.now();
    let semgrepEndTime = performance.now();
    
    if (!semgrepAvailable.available) {
      // Use mock findings
      console.log('Using mock vulnerability detection');
      parsedFindings = getMockFindings(code);
    } else {
      // Create temp file
      const tempDir = path.join(os.tmpdir(), 'scan-temp');
      if (!fs.existsSync(tempDir)) {
        fs.mkdirSync(tempDir, { recursive: true });
      }
      
      const timestamp = Date.now().toString();
      const safeFilename = filename.replace(/[^a-zA-Z0-9.-]/g, '_');
      const tempFilePath = path.join(tempDir, timestamp + '-' + safeFilename);
      
      fs.writeFileSync(tempFilePath, code, 'utf8');
      console.log('Created temp file:', tempFilePath);

      // Run Semgrep
      semgrepStartTime = performance.now();
      try {
        const semgrepResults = await runSemgrepScan(tempFilePath);
        parsedFindings = parseSemgrepResults(semgrepResults);
      } catch (error) {
        console.error('Semgrep scan error:', error);
        parsedFindings = getMockFindings(code);
      }
      semgrepEndTime = performance.now();
      
      // Clean up
      try {
        if (fs.existsSync(tempFilePath)) {
          fs.unlinkSync(tempFilePath);
          console.log('Cleaned up temp file');
        }
      } catch (cleanupError) {
        console.error('Cleanup error:', cleanupError);
      }
    }
    
    console.log('Found', parsedFindings.length, 'raw findings');
    
    // Classify findings
    const classificationStartTime = performance.now();
    const classifiedFindings = parsedFindings.map(finding => 
      classifier.classifyFinding(finding, {
        environment: 'production',
        deployment: 'internet-facing',
        dataHandling: { personalData: true },
        regulatoryRequirements: ['GDPR', 'PCI-DSS']
      })
    );
    const classificationEndTime = performance.now();
    console.log('Classified', classifiedFindings.length, 'findings');
    
    // Deduplicate findings
    const deduplicationStartTime = performance.now();
    const deduplicatedFindings = deduplicateFindings(classifiedFindings);
    const deduplicationEndTime = performance.now();
    console.log('Deduplicated to', deduplicatedFindings.length, 'unique findings');
    
    // Calculate risk score
    const riskStartTime = performance.now();
    const riskAssessment = classifier.aggregateRiskScore(deduplicatedFindings, {
      environment: 'production',
      deployment: 'internet-facing',
      dataHandling: { personalData: true }
    });
    const riskEndTime = performance.now();
    
    // Calculate performance metrics
    const scanEndTime = performance.now();
    const memAfter = process.memoryUsage();
    
    const performanceMetrics = {
      totalScanTime: (scanEndTime - scanStartTime).toFixed(2) + 'ms',
      semgrepTime: (semgrepEndTime - semgrepStartTime).toFixed(2) + 'ms',
      classificationTime: (classificationEndTime - classificationStartTime).toFixed(2) + 'ms',
      deduplicationTime: (deduplicationEndTime - deduplicationStartTime).toFixed(2) + 'ms',
      riskCalculationTime: (riskEndTime - riskStartTime).toFixed(2) + 'ms',
      memoryUsed: Math.round((memAfter.heapUsed - memBefore.heapUsed) / 1024 / 1024) + 'MB',
      totalMemory: Math.round(memAfter.heapTotal / 1024 / 1024) + 'MB'
    };
    
    console.log('Performance metrics:', performanceMetrics);
    
    // Send response
    res.json({
      status: 'success',
      language: language,
      findings: deduplicatedFindings,
      riskAssessment: riskAssessment,
      metadata: {
        scanned_at: new Date().toISOString(),
        code_length: code.length,
        semgrep_version: semgrepAvailable.version || 'mock',
        original_findings_count: parsedFindings.length,
        classified_findings_count: classifiedFindings.length,
        deduplicated_findings_count: deduplicatedFindings.length,
        reduction_percentage: parsedFindings.length > 0 
          ? Math.round(((parsedFindings.length - deduplicatedFindings.length) / parsedFindings.length) * 100)
          : 0,
        performance: performanceMetrics
      },
      summary: {
        totalVulnerabilities: deduplicatedFindings.length,
        criticalCount: riskAssessment.severityDistribution.critical || 0,
        highCount: riskAssessment.severityDistribution.high || 0,
        mediumCount: riskAssessment.severityDistribution.medium || 0,
        lowCount: riskAssessment.severityDistribution.low || 0,
        riskLevel: riskAssessment.riskLevel,
        businessPriority: riskAssessment.businessPriority,
        topRisks: riskAssessment.topRisks || []
      }
    });
    
  } catch (error) {
    console.error('Code scan error:', error);
    console.error('Stack trace:', error.stack);
    
    const errorEndTime = performance.now();
    const errorResponseTime = (errorEndTime - scanStartTime).toFixed(2) + 'ms';
    
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

// Health check endpoints
app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memory: process.memoryUsage()
  });
});

app.get('/healthz', (req, res) => {
  res.status(200).send('OK');
});

// Test endpoint
app.post('/test-scan', (req, res) => {
  const { code } = req.body;
  
  const testFindings = [
    {
      check_id: 'hardcoded-password',
      path: 'test.js',
      start: { line: 10, col: 5 },
      message: 'Hardcoded password detected',
      severity: 'high',
      extra: {
        metadata: { cwe: 'CWE-798' },
        lines: 'const password = "admin123";'
      }
    },
    {
      check_id: 'sql-injection',
      path: 'test.js',
      start: { line: 25, col: 10 },
      message: 'SQL injection vulnerability',
      severity: 'high',
      extra: {
        metadata: { cwe: 'CWE-89' },
        lines: 'query = "SELECT * FROM users WHERE id = " + id;'
      }
    }
  ];
  
  // Classify test findings
  const classifiedFindings = testFindings.map(finding => 
    classifier.classifyFinding(finding, {
      environment: 'production',
      deployment: 'internet-facing',
      dataHandling: { personalData: true }
    })
  );
  
  const deduplicatedFindings = deduplicateFindings(classifiedFindings);
  const riskAssessment = classifier.aggregateRiskScore(deduplicatedFindings);
  
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
      '/test-scan': 'POST - Test scan with mock data',
      '/health': 'GET - Health check',
      '/healthz': 'GET - Railway health check'
    },
    features: [
      'Semgrep static analysis',
      'SecurityClassificationSystem with CWE/OWASP/CVSS',
      'Finding deduplication',
      'Risk score calculation',
      'Business impact assessment',
      'Remediation strategies'
    ]
  });
});

// Start server
app.listen(PORT, () => {
  console.log('Server running on port', PORT);
  console.log('Accepting requests from Base44 and Lovable frontends');
  console.log('Features enabled:');
  console.log('  - Semgrep static analysis');
  console.log('  - SecurityClassificationSystem');
  console.log('  - Finding deduplication');
  console.log('  - Risk calculation');
  console.log('  - Business impact assessment');
  
  // Check system readiness
  checkSemgrepAvailability().then(status => {
    if (status.available) {
      console.log('Semgrep available:', status.version);
    } else {
      console.log('Semgrep not available:', status.error);
      console.log('Using mock vulnerability detection');
    }
  });
});

module.exports = app;