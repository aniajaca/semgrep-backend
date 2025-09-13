// server.js - Enhanced with user configuration and context support (PROPERLY FIXED)
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const os = require('os');

// Import the enhanced risk calculator
const EnhancedRiskCalculator = require('./enhancedRiskCalculator');

// Import the AST vulnerability scanner
const { ASTVulnerabilityScanner } = require('./astScanner');
const classifier = new ASTVulnerabilityScanner();

// Import dependency scanner
const { DependencyScanner } = require('./dependencyScanner');
const depScanner = new DependencyScanner();

// Import and configure rate limiting
const rateLimit = require('express-rate-limit');

// Helper function for creating rate limiters
function rateLimiter(max, windowMs) {
  return rateLimit({
    windowMs: windowMs,
    max: max,
    standardHeaders: true,
    legacyHeaders: false,
    message: 'Too many requests from this IP, please try again later.'
  });
}

const app = express();
const PORT = process.env.PORT || 3000;

// Security middleware - Helmet with proper CSP
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
}));

// CORS middleware
app.use(cors({
  origin: true,
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Body parsing middleware
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

/**
 * Sanitize and validate risk configuration
 */
function sanitizeRiskConfig(cfg = {}) {
  const config = JSON.parse(JSON.stringify(cfg)); // Deep clone
  
  // Sanitize severity points
  const points = config.severityPoints || config.fileLevel?.severityPoints;
  if (points) {
    ['critical', 'high', 'medium', 'low', 'info'].forEach(k => {
      if (points[k] != null) {
        points[k] = Math.max(0, Math.min(100, Number(points[k]) || 0));
      }
    });
  }
  
  // Sanitize risk thresholds
  const thresholds = config.riskThresholds || config.fileLevel?.riskThresholds;
  if (thresholds) {
    Object.keys(thresholds).forEach(k => {
      if (thresholds[k] != null) {
        thresholds[k] = Math.max(0, Math.min(100, Number(thresholds[k]) || 0));
      }
    });
    
    // Ensure proper ordering
    if (thresholds.critical != null && thresholds.high != null) {
      thresholds.high = Math.min(thresholds.high, thresholds.critical);
    }
    if (thresholds.high != null && thresholds.medium != null) {
      thresholds.medium = Math.min(thresholds.medium, thresholds.high);
    }
    if (thresholds.medium != null && thresholds.low != null) {
      thresholds.low = Math.min(thresholds.low, thresholds.medium);
    }
    if (thresholds.low != null && thresholds.minimal != null) {
      thresholds.minimal = Math.min(thresholds.minimal, thresholds.low);
    }
  }
  
  // Sanitize normalization settings
  if (config.normalization) {
    if (config.normalization.minScore != null) {
      config.normalization.minScore = Math.max(0, Math.min(100, Number(config.normalization.minScore) || 0));
    }
    if (config.normalization.maxScore != null) {
      config.normalization.maxScore = Math.max(0, Math.min(1000, Number(config.normalization.maxScore) || 100));
    }
    if (config.normalization.targetMin != null) {
      config.normalization.targetMin = Math.max(0, Math.min(100, Number(config.normalization.targetMin) || 0));
    }
    if (config.normalization.targetMax != null) {
      config.normalization.targetMax = Math.max(0, Math.min(100, Number(config.normalization.targetMax) || 100));
    }
  }
  
  return config;
}

/**
 * Sanitize context factors
 */
function sanitizeContextFactors(context = {}) {
  const sanitized = { ...context };
  
  if (sanitized.factors) {
    Object.keys(sanitized.factors).forEach(factorName => {
      const factor = sanitized.factors[factorName];
      if (factor && factor.weight != null) {
        factor.weight = Math.max(0.5, Math.min(3.0, Number(factor.weight) || 1.0));
      }
    });
  }
  
  return sanitized;
}

/**
 * Helper function to normalize severity strings
 */
function normalizeSeverity(severity) {
  return (severity || 'info').toString().toLowerCase();
}

/**
 * Enhanced code scanning endpoint
 */
app.post('/scan-code', rateLimiter(50, 60000), async (req, res) => {
  console.log('=== CODE SCAN REQUEST RECEIVED ===');
  console.log('Origin:', req.headers.origin);
  
  const startTime = Date.now();
  
  try {
    const { 
      code, 
      language = 'javascript', 
      filename = 'code.js',
      riskConfig = {},
      context = {}
    } = req.body;
    
    if (!code || typeof code !== 'string' || code.trim() === '') {
      return res.status(400).json({ 
        status: 'error', 
        message: 'No code provided' 
      });
    }

    console.log('Code length:', code.length);
    console.log('Language:', language);
    console.log('Risk config provided:', Object.keys(riskConfig).length > 0);
    console.log('Context provided:', Object.keys(context).length > 0);
    
    // Scan for vulnerabilities
    const findings = classifier.scan(code, filename, language);
    console.log(`Found ${findings.length} vulnerabilities`);
    
    // Sanitize configurations
    const sanitizedConfig = sanitizeRiskConfig(riskConfig);
    const sanitizedContext = sanitizeContextFactors(context);
    
    // Create risk calculator instance
    const calc = new EnhancedRiskCalculator(sanitizedConfig);
    
    // Calculate risk scores
    const { score, risk } = calc.calculateFileRisk(findings, sanitizedContext);
    
    // Build severity distribution
    const severityDistribution = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0
    };
    
    findings.forEach(f => {
      const severity = normalizeSeverity(f.severity);
      if (severityDistribution.hasOwnProperty(severity)) {
        severityDistribution[severity]++;
      }
    });
    
    // Build top risks
    const topRisks = findings
      .filter(f => {
        const sev = normalizeSeverity(f.severity);
        return sev === 'critical' || sev === 'high';
      })
      .slice(0, 3)
      .map(f => ({
        title: f.title || f.check_id || 'Security Issue',
        severity: normalizeSeverity(f.severity),
        category: f.owasp?.category || 'OWASP A06'
      }));
    
    const businessPriority = risk.priority;
    
    // Generate recommendation
    let recommendation = '';
    if (risk.level === 'critical') {
      recommendation = 'Immediate action required. Deploy fixes to production ASAP.';
    } else if (risk.level === 'high') {
      recommendation = 'High priority remediation needed. Address within 48 hours.';
    } else if (risk.level === 'medium') {
      recommendation = 'Schedule remediation in next sprint.';
    } else if (risk.level === 'low') {
      recommendation = 'Include in regular maintenance cycle.';
    } else {
      recommendation = 'Maintain current security posture.';
    }
    
    const endTime = Date.now();
    
    // Response
    res.json({
      status: 'success',
      language,
      findings,
      score,
      risk,
      riskScore: score.final,
      riskAssessment: {
        riskScore: score.final,
        riskLevel: risk.level.charAt(0).toUpperCase() + risk.level.slice(1),
        severityDistribution,
        topRisks,
        businessPriority,
        confidence: risk.confidence,
        recommendation,
        factorImpacts: score.factorImpacts || {}
      },
      vulnerabilities: {
        total: findings.length,
        distribution: severityDistribution,
        categories: [...new Set(findings.map(f => f.owasp?.category || 'Unknown'))]
      },
      metadata: {
        scanned_at: new Date().toISOString(),
        code_length: code.length,
        findings_count: findings.length,
        scan_time: `${endTime - startTime}ms`,
        configuration: {
          customConfig: Object.keys(riskConfig).length > 0,
          contextProvided: Object.keys(context).length > 0
        }
      }
    });
    
  } catch (error) {
    console.error('Scan error:', error);
    res.status(500).json({ 
      status: 'error', 
      message: 'Code scan failed',
      error: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

/**
 * Enhanced dependency scanning endpoint - PROPERLY FIXED
 */
app.post('/scan-dependencies', async (req, res) => {
  console.log('=== DEPENDENCY SCAN REQUEST RECEIVED ===');
  
  try {
    const {
      packageJson,
      packageLock,
      lockFile,
      lockFileType = 'npm',
      includeDevDependencies = false,
      riskConfig = {},
      context = {}
    } = req.body;
    
    if (!packageJson) {
      return res.status(400).json({
        status: 'error',
        message: 'No package.json provided'
      });
    }
    
    console.log('Risk config provided:', Object.keys(riskConfig).length > 0);
    console.log('Context provided:', Object.keys(context).length > 0);
    
    // Parse packageJson if string
    const pkgJson = typeof packageJson === 'string' ? JSON.parse(packageJson) : packageJson;
    
    // Scan dependencies
    const scanResults = await depScanner.scanDependencies(pkgJson, {
      includeDevDependencies
    });
    
    // Process lock file if provided - WITH PROPER DEDUPLICATION
    if (lockFile || packageLock) {
      try {
        const lockVulns = await depScanner.scanLockFile(
          lockFile || packageLock, 
          lockFileType
        );
        if (lockVulns && lockVulns.length > 0) {
          scanResults.vulnerabilities.push(...lockVulns);
          // CRITICAL FIX: Deduplicate after merging
          scanResults.vulnerabilities = depScanner.deduplicateVulnerabilities(scanResults.vulnerabilities);
          // Update count with deduplicated length
          scanResults.summary.totalVulnerabilities = scanResults.vulnerabilities.length;
        }
      } catch (lockError) {
        console.warn('Lock file scan failed:', lockError.message);
      }
    }
    
    // Calculate risk scores
    const sanitizedConfig = sanitizeRiskConfig(riskConfig);
    const sanitizedContext = sanitizeContextFactors(context);
    const calc = new EnhancedRiskCalculator(sanitizedConfig);
    
    // Get severity distribution
    const dist = scanResults.summary?.severityDistribution || {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0
    };
    
    // Calculate risk
    const { score, risk } = calc.calculateFromSeverityDistribution(dist, sanitizedContext);
    
    // Enhance results
    const enhancedResults = {
      ...scanResults,
      score,
      risk,
      summary: {
        ...scanResults.summary,
        riskScore: score.final,
        riskLevel: risk.level.charAt(0).toUpperCase() + risk.level.slice(1),
        confidence: risk.confidence,
        priority: risk.priority
      }
    };
    
    res.json({
      status: 'success',
      ...enhancedResults,
      metadata: {
        scanned_at: new Date().toISOString(),
        configuration: {
          customConfig: Object.keys(riskConfig).length > 0,
          contextProvided: Object.keys(context).length > 0,
          includeDevDependencies,
          lockFileScanned: !!(lockFile || packageLock)
        }
      }
    });
    
  } catch (error) {
    console.error('Dependency scan error:', error);
    res.status(500).json({
      status: 'error',
      message: 'Dependency scan failed',
      error: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

/**
 * File upload scanning endpoint
 */
app.post('/scan-file', async (req, res) => {
  console.log('=== FILE SCAN REQUEST RECEIVED ===');
  
  try {
    const {
      content,
      filename = 'uploaded-file',
      language = 'javascript',
      riskConfig = {},
      context = {}
    } = req.body;
    
    if (!content) {
      return res.status(400).json({
        status: 'error',
        message: 'No file content provided'
      });
    }
    
    // Scan the file
    const findings = classifier.scan(content, filename, language);
    
    // Calculate risk
    const sanitizedConfig = sanitizeRiskConfig(riskConfig);
    const sanitizedContext = sanitizeContextFactors(context);
    const calc = new EnhancedRiskCalculator(sanitizedConfig);
    const { score, risk } = calc.calculateFileRisk(findings, sanitizedContext);
    
    res.json({
      status: 'success',
      filename,
      language,
      findings,
      score,
      risk,
      vulnerabilities: {
        total: findings.length,
        critical: findings.filter(f => normalizeSeverity(f.severity) === 'critical').length,
        high: findings.filter(f => normalizeSeverity(f.severity) === 'high').length,
        medium: findings.filter(f => normalizeSeverity(f.severity) === 'medium').length,
        low: findings.filter(f => normalizeSeverity(f.severity) === 'low').length
      },
      metadata: {
        scanned_at: new Date().toISOString(),
        file_size: content.length,
        configuration: {
          customConfig: Object.keys(riskConfig).length > 0,
          contextProvided: Object.keys(context).length > 0
        }
      }
    });
    
  } catch (error) {
    console.error('File scan error:', error);
    res.status(500).json({
      status: 'error',
      message: 'File scan failed',
      error: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

/**
 * Batch scanning endpoint
 */
app.post('/scan-batch', rateLimiter(20, 60000), async (req, res) => {
  console.log('=== BATCH SCAN REQUEST RECEIVED ===');
  
  try {
    const {
      files = [],
      riskConfig = {},
      context = {}
    } = req.body;
    
    if (!Array.isArray(files) || files.length === 0) {
      return res.status(400).json({
        status: 'error',
        message: 'No files provided for batch scanning'
      });
    }
    
    const sanitizedConfig = sanitizeRiskConfig(riskConfig);
    const sanitizedContext = sanitizeContextFactors(context);
    const calc = new EnhancedRiskCalculator(sanitizedConfig);
    
    const results = [];
    let totalFindings = [];
    
    // Scan each file
    for (const file of files) {
      try {
        const { content, filename = 'unknown', language = 'javascript' } = file;
        
        if (!content) continue;
        
        const findings = classifier.scan(content, filename, language);
        totalFindings = totalFindings.concat(findings);
        
        results.push({
          filename,
          language,
          findings: findings.length,
          vulnerabilities: findings
        });
      } catch (fileError) {
        console.error(`Error scanning file ${file.filename}:`, fileError);
        results.push({
          filename: file.filename || 'unknown',
          error: fileError.message
        });
      }
    }
    
    // Calculate overall risk
    const { score, risk } = calc.calculateFileRisk(totalFindings, sanitizedContext);
    
    res.json({
      status: 'success',
      filesScanned: files.length,
      results,
      overallScore: score,
      overallRisk: risk,
      summary: {
        totalFindings: totalFindings.length,
        critical: totalFindings.filter(f => normalizeSeverity(f.severity) === 'critical').length,
        high: totalFindings.filter(f => normalizeSeverity(f.severity) === 'high').length,
        medium: totalFindings.filter(f => normalizeSeverity(f.severity) === 'medium').length,
        low: totalFindings.filter(f => normalizeSeverity(f.severity) === 'low').length
      },
      metadata: {
        scanned_at: new Date().toISOString(),
        configuration: {
          customConfig: Object.keys(riskConfig).length > 0,
          contextProvided: Object.keys(context).length > 0
        }
      }
    });
    
  } catch (error) {
    console.error('Batch scan error:', error);
    res.status(500).json({
      status: 'error',
      message: 'Batch scan failed',
      error: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

/**
 * Health check endpoints
 */
app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    features: {
      customRiskConfig: true,
      contextualAnalysis: true,
      enhancedRiskCalculator: true,
      batchScanning: true,
      dependencyScanning: true,
      astScanning: true,
      helmetSecurity: true
    }
  });
});

app.get('/healthz', (req, res) => {
  res.status(200).send('OK');
});

/**
 * Get current default configuration
 */
app.get('/config/defaults', (req, res) => {
  res.json({
    status: 'success',
    defaults: {
      severityPoints: {
        critical: 40,
        high: 25,
        medium: 15,
        low: 8,
        info: 3
      },
      riskThresholds: {
        critical: 80,
        high: 60,
        medium: 40,
        low: 20,
        minimal: 0
      },
      normalization: {
        enabled: false,
        minScore: 0,
        maxScore: 100,
        targetMin: 0,
        targetMax: 100
      },
      factors: {
        environmental: { enabled: true, weight: 1.0 },
        pattern: { enabled: true, weight: 1.0 },
        confidence: { enabled: true, weight: 1.0 },
        exploitability: { enabled: true, weight: 1.0 },
        businessImpact: { enabled: true, weight: 1.0 }
      }
    }
  });
});

/**
 * Root endpoint with API information
 */
app.get('/', (req, res) => {
  res.json({
    name: 'Neperia Security Scanner - Enhanced Edition',
    version: '4.0',
    status: 'operational',
    endpoints: {
      'POST /scan-code': 'Scan code with custom risk configuration',
      'POST /scan-dependencies': 'Scan dependencies with custom risk configuration',
      'POST /scan-file': 'Scan uploaded file with custom risk configuration',
      'POST /scan-batch': 'Batch scan multiple files',
      'GET /config/defaults': 'Get default configuration values',
      'GET /health': 'Health check with feature status',
      'GET /healthz': 'Simple health check'
    },
    features: [
      'User-configurable risk scoring',
      'Contextual risk analysis',
      'Per-request risk calculator instances',
      'Enhanced risk factors and multipliers',
      'Sanitized configuration inputs',
      'Batch file scanning',
      'Dependency vulnerability scanning',
      'OWASP/CWE/CVSS classification',
      'Business impact assessment',
      'AST-based code analysis',
      'Helmet security headers'
    ],
    configuration: {
      riskConfig: {
        description: 'Custom severity weights and thresholds',
        fields: ['severityPoints', 'riskThresholds', 'normalization']
      },
      context: {
        description: 'Environmental and business context',
        fields: ['businessUnit', 'environment', 'dataClassification', 'factors']
      }
    },
    supported_languages: ['javascript', 'typescript'],
    api_version: '4.0.0'
  });
});

/**
 * 404 handler
 */
app.use('*', (req, res) => {
  res.status(404).json({ 
    status: 'error', 
    message: 'Route not found',
    path: req.originalUrl,
    method: req.method,
    available_routes: [
      'GET /',
      'GET /health',
      'GET /healthz',
      'GET /config/defaults',
      'POST /scan-code',
      'POST /scan-dependencies',
      'POST /scan-file',
      'POST /scan-batch'
    ],
    timestamp: new Date().toISOString()
  });
});

/**
 * Error handling middleware
 */
app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  
  if (res.headersSent) {
    return next(error);
  }
  
  res.status(500).json({ 
    status: 'error', 
    message: 'Internal server error',
    error: process.env.NODE_ENV === 'development' ? error.message : undefined,
    timestamp: new Date().toISOString()
  });
});

/**
 * Start server
 */
const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`
╔══════════════════════════════════════════════════════════════╗
║     NEPERIA SECURITY SCANNER - ENHANCED EDITION v4.0        ║
╠══════════════════════════════════════════════════════════════╣
║  Server running on port ${PORT}                                 ║
║  Status: OPERATIONAL                                         ║
║                                                              ║
║  FEATURES:                                                   ║
║  ✓ User-configurable risk scoring                           ║
║  ✓ Per-request calculator instances                         ║
║  ✓ Contextual risk analysis                                 ║
║  ✓ Input sanitization and validation                        ║
║  ✓ Enhanced factor-based scoring                            ║
║  ✓ Batch file scanning                                      ║
║  ✓ AST-based vulnerability detection                        ║
║  ✓ Helmet security headers                                  ║
║                                                              ║
║  ENDPOINTS:                                                  ║
║  • POST /scan-code         - Code analysis                   ║
║  • POST /scan-dependencies - Dependency analysis             ║
║  • POST /scan-file         - File analysis                   ║
║  • POST /scan-batch        - Batch file analysis             ║
║  • GET /config/defaults    - Default configurations          ║
║                                                              ║
║  Configuration: Pass 'riskConfig' and 'context' in body      ║
╚══════════════════════════════════════════════════════════════╝
  `);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, closing server...');
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  console.log('SIGINT received, closing server...');
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
});

module.exports = app;