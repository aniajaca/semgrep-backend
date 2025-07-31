// src/server.js - CORRECTED Complete server with AI integration
const express = require('express');
const multer = require('multer');
const { spawn, exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { performance } = require('perf_hooks'); 

// ✅ SINGLE IMPORT - Import the enhanced SecurityClassificationSystem
const { SecurityClassificationSystem } = require('./SecurityClassificationSystem');

// Import AI router (optional - only if file exists)
let aiRouter = null;
try {
  aiRouter = require('./aiRouter');
  console.log('🤖 AI Router loaded successfully');
} catch (error) {
  console.log('⚠️ AI Router not available - continuing without AI features');
}

require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

console.log('🚀 Starting Neperia Cybersecurity Analysis Tool with AI Integration');
console.log('🔧 STATIC: Semgrep + CWE + OWASP + CVSS Classification');  
console.log('🤖 AI: OpenAI GPT-4 Enhanced Explanations and Reporting');

// Global error handlers to prevent crashes
process.on('uncaughtException', (error) => {
  console.error('❌ Uncaught Exception:', error);
  console.error('Stack:', error.stack);
  if (process.env.NODE_ENV !== 'production') {
    process.exit(1);
  }
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('❌ Unhandled Rejection at:', promise, 'reason:', reason);
  if (process.env.NODE_ENV !== 'production') {
    process.exit(1);
  }
});

// Enhanced startup logging
console.log('=== NEPERIA SECURITY SCANNER STARTUP ===');
console.log('Node version:', process.version);
console.log('Platform:', process.platform);
console.log('Environment:', process.env.NODE_ENV || 'development');
console.log('Port:', PORT);
console.log('OpenAI API:', process.env.OPENAI_API_KEY ? '✓ Configured' : '❌ Missing');
console.log('Current working directory:', process.cwd());
console.log('Temp directory:', os.tmpdir());

// CORS middleware for Lovable frontend integration
const customCors = (req, res, next) => {
  try {
    const origin = req.headers.origin;
    
    const allowedOrigins = [
      'https://preview--neperia-code-guardian.lovable.app',
      'https://neperia-code-guardian.lovable.app',
      'https://lovable.app',
      'http://localhost:3000',
      'http://localhost:5173'
    ];
    
    const isAllowed = 
      allowedOrigins.includes(origin) ||
      (origin && (
        origin.endsWith('.lovable.app') ||
        origin.endsWith('.lovableproject.com')
      ));
    
    res.setHeader(
      'Access-Control-Allow-Origin',
      isAllowed || !origin ? (origin || '*') 
                         : 'https://preview--neperia-code-guardian.lovable.app'
    );
    
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader(
      'Access-Control-Allow-Headers', 
      'Content-Type, Authorization, X-Requested-With, Accept, Origin'
    );
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Max-Age', '86400');
    
    console.log(`🌐 CORS: Origin ${origin} -> ${isAllowed ? 'ALLOWED' : 'DEFAULT'}`);
    
    if (req.method === 'OPTIONS') {
      return res.status(200).end();
    }
    
    next();
  } catch (error) {
    console.error('❌ CORS middleware error:', error);
    next(error);
  }
};

app.use(customCors);

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    try {
      const uploadDir = path.join(os.tmpdir(), 'uploads');
      if (!fs.existsSync(uploadDir)) {
        fs.mkdirSync(uploadDir, { recursive: true });
        console.log('📁 Created upload directory:', uploadDir);
      }
      cb(null, uploadDir);
    } catch (error) {
      console.error('❌ Error creating upload directory:', error);
      cb(error);
    }
  },
  filename: (req, file, cb) => {
    try {
      const timestamp = Date.now();
      const originalName = file.originalname || 'uploaded_file';
      const filename = `${timestamp}-${originalName}`;
      cb(null, filename);
    } catch (error) {
      console.error('❌ Error generating filename:', error);
      cb(error);
    }
  }
});

const upload = multer({ 
  storage: storage,
  limits: {
    fileSize: 10 * 1024 * 1024 // 10MB limit
  },
  fileFilter: (req, file, cb) => {
    cb(null, true); // Accept all files, let Semgrep handle compatibility
  }
});

// Root route
app.get('/', (req, res) => {
  console.log('🏠 Root endpoint accessed');
  res.status(200).json({
    message: 'Neperia Cybersecurity Analysis Tool with AI Enhancement',
    version: '3.0-corrected',
    status: 'active',
    features: {
      staticAnalysis: 'Semgrep + CWE + OWASP + CVSS',
      aiEnhancement: 'OpenAI GPT-4 Explanations',
      classification: 'SecurityClassificationSystem v3.0',
      audiences: ['developer', 'consultant', 'executive', 'auditor']
    },
    timestamp: new Date().toISOString(),
    endpoints: {
      'GET /': 'Root endpoint with system info',
      'GET /healthz': 'Health check',
      'GET /semgrep-status': 'Check Semgrep availability',
      'POST /scan': 'File scanning with AI enhancement',
      'POST /scan-code': 'Code scanning with AI enhancement',
      'POST /api/explain-finding': 'AI explanations for vulnerabilities (if AI router available)',
      'POST /api/assess-risk': 'AI risk assessment (if AI router available)',
      'POST /api/plan-remediation': 'AI remediation planning (if AI router available)',
      'POST /api/compliance-analysis': 'AI compliance analysis (if AI router available)',
      'POST /api/generate-report': 'AI-generated reports (if AI router available)'
    }
  });
});

// Health check endpoints
app.get('/healthz', (req, res) => {
  console.log('🏥 Health check accessed');
  
  res.set({
    'Content-Type': 'application/json',
    'Cache-Control': 'no-cache'
  });
  
  res.status(200).json({
    status: 'healthy',
    service: 'neperia-security-scanner',
    version: '3.0-corrected',
    components: {
      semgrep: 'checking...',
      openai: process.env.OPENAI_API_KEY ? 'available' : 'not-configured',
      classification: 'SecurityClassificationSystem v3.0',
      aiRouter: aiRouter ? 'available' : 'not-available'
    },
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

app.get('/health', (req, res) => {
  console.log('🏥 Alternative health check accessed');
  res.status(200).json({
    status: 'healthy',
    service: 'neperia-security-scanner-ai',
    timestamp: new Date().toISOString()
  });
});

// Semgrep status endpoint
app.get('/semgrep-status', (req, res) => {
  console.log('🔧 STATIC: Semgrep status check requested');
  
  checkSemgrepAvailability()
    .then(result => {
      res.json({
        status: 'success',
        semgrep: result,
        timestamp: new Date().toISOString()
      });
    })
    .catch(error => {
      res.status(500).json({
        status: 'error',
        message: 'Semgrep not available',
        error: error.message,
        timestamp: new Date().toISOString()
      });
    });
});

// ✅ SINGLE /scan-code endpoint - Enhanced with proper integration
app.post('/scan-code', async (req, res) => {
  console.log('=== 💻 ENHANCED CODE SCAN REQUEST ===');
  console.log('Headers:', req.headers);
  console.log('Origin:', req.headers.origin);
  
  const scanStartTime = performance.now();
  const memBefore = process.memoryUsage();
  
  try {
    const { 
      code, 
      filename = 'uploaded_code.py',
      environment = 'production',
      deployment = 'internet-facing',
      dataHandling = {},
      compliance = []
    } = req.body;

    if (!code) {
      return res.status(400).json({ 
        status: 'error', 
        message: 'No code provided in request body',
        expected: { code: 'string', filename: 'string (optional)' }
      });
    }

    console.log(`💻 Code analysis: ${filename} (${code.length} characters)`);
    console.log(`🌍 Context: ${environment}/${deployment}`);

    // Check Semgrep availability first
    const semgrepAvailable = await checkSemgrepAvailability();
    if (!semgrepAvailable.available) {
      return res.status(503).json({
        status: 'error',
        message: 'Semgrep scanner not available',
        details: semgrepAvailable.error,
        installation: 'Run: pip install semgrep'
      });
    }

    // Create temporary file for scanning
    const fileReadStartTime = performance.now();
    const tempDir = path.join(os.tmpdir(), 'neperia-scans');
    if (!fs.existsSync(tempDir)) {
      fs.mkdirSync(tempDir, { recursive: true });
    }
    
    const tempFile = path.join(tempDir, `${Date.now()}-${filename}`);
    fs.writeFileSync(tempFile, code, 'utf8');
    const fileReadEndTime = performance.now();

    console.log(`📁 Created temp file: ${tempFile}`);

    try {
      // Run Semgrep with proper code extraction
      const semgrepStartTime = performance.now();
      const semgrepResults = await runSemgrepScanWithCodeExtraction(tempFile, code);
      const semgrepEndTime = performance.now();
      
      console.log(`🔧 STATIC: Enhanced Semgrep scan completed (${(semgrepEndTime - semgrepStartTime).toFixed(2)}ms)`);

      // Classification with the SecurityClassificationSystem
      const classificationStartTime = performance.now();
      const classifier = new SecurityClassificationSystem();
      
      const componentContext = buildComponentContext({
        environment,
        deployment,
        dataHandling,
        compliance
      });

      // Classify each finding with context
      const classifiedFindings = semgrepResults.results.map(finding => {
        const findingWithContext = {
          ...finding,
          context: componentContext
        };
        const classified = classifier.classifyFinding(findingWithContext);
        
        console.log(`🔧 CLASSIFIED: ${classified.title} - ${classified.severity} (CVSS: ${classified.cvss?.adjustedScore})`);
        
        return classified;
      });
      
      // Aggregate risk with proper environmental context
      const riskAssessment = classifier.aggregateRiskScore(classifiedFindings, componentContext);
      const classificationEndTime = performance.now();
      
      console.log(`🔧 STATIC: Risk assessment completed - Score: ${riskAssessment.riskScore}, Level: ${riskAssessment.riskLevel}`);

      // Performance metrics
      const scanEndTime = performance.now();
      const memAfter = process.memoryUsage();
      
      const performanceMetrics = {
        totalScanTime: `${(scanEndTime - scanStartTime).toFixed(2)}ms`,
        fileProcessingTime: `${(fileReadEndTime - fileReadStartTime).toFixed(2)}ms`,
        semgrepScanTime: `${(semgrepEndTime - semgrepStartTime).toFixed(2)}ms`,
        classificationTime: `${(classificationEndTime - classificationStartTime).toFixed(2)}ms`,
        memoryUsed: `${Math.round((memAfter.heapUsed - memBefore.heapUsed) / 1024 / 1024)}MB`
      };

      // Generate structured report
      const report = generateStructuredReport({
        findings: classifiedFindings,
        riskAssessment,
        metadata: {
          scanned_at: new Date().toISOString(),
          code_length: code.length,
          filename: filename,
          environment: componentContext,
          semgrep_version: semgrepAvailable.version,
          classification_version: '3.0'
        },
        performance: performanceMetrics
      });

      console.log(`✅ ENHANCED: Scan completed successfully`);
      console.log(`📊 Results: ${classifiedFindings.length} findings, risk ${riskAssessment.riskScore}/${riskAssessment.riskLevel}`);

      // SUCCESS RESPONSE with complete data
      res.json({
        status: 'success',
        service: 'Neperia Security Scanner v3.0 - Enhanced Analysis',
        
        // Analysis summary with proper metrics
        analysis: {
          static: {
            filename: filename,
            codeLength: code.length,
            findingsCount: classifiedFindings.length,
            uniqueVulnerabilities: report.summary.uniqueVulnerabilities,
            riskScore: report.summary.riskScore,
            riskLevel: report.summary.riskLevel
          },
          aiReady: {
            enhancedFindings: classifiedFindings.length,
            aiMetadataIncluded: true,
            readyForAIAnalysis: aiRouter !== null,
            contextualData: 'Full environmental context included'
          }
        },
        
        // Structured report - Frontend expects this structure
        report,
        
        // Legacy compatibility - Keep existing API contract
        findings: classifiedFindings,
        riskScore: report.summary.riskScore,
        metadata: report.metadata,
        riskAssessment,
        
        // Performance data
        performance: performanceMetrics,
        
        // AI integration hints
        nextSteps: aiRouter ? {
          aiExplanations: 'POST /api/explain-finding with finding + audience',
          riskAnalysis: 'POST /api/assess-risk with findings array',
          remediationPlanning: 'POST /api/plan-remediation with finding + project context',
          complianceCheck: 'POST /api/compliance-analysis with findings + compliance context',
          executiveReport: 'POST /api/generate-report with findings + context'
        } : {
          message: 'AI features not available - aiRouter not configured'
        }
      });
      
    } finally {
      // Always remove temporary file
      if (fs.existsSync(tempFile)) {
        fs.unlinkSync(tempFile);
        console.log('🧹 Cleaned up temporary file');
      }
    }
    
  } catch (error) {
    console.error('❌ Enhanced code scan error:', error);
    console.error('Stack trace:', error.stack);
    
    const errorEndTime = performance.now();
    const errorResponseTime = `${(errorEndTime - scanStartTime).toFixed(2)}ms`;
    console.log('⚡ ERROR RESPONSE TIME:', errorResponseTime);
    
    res.status(500).json({ 
      status: 'error', 
      message: 'Enhanced code scan failed',
      error: error.message,
      service: 'Neperia Security Scanner v3.0',
      timestamp: new Date().toISOString(),
      performance: {
        errorResponseTime: errorResponseTime
      },
      troubleshooting: {
        semgrepInstalled: 'Check: semgrep --version',
        tempFileAccess: 'Check: write permissions to tmp directory',
        codeContent: 'Ensure code parameter is valid'
      }
    });
  }
});

// ✅ SINGLE /scan endpoint - File upload with AI integration
app.post('/scan', upload.single('file'), async (req, res) => {
  console.log('=== 📁 FILE SCAN REQUEST WITH AI ENHANCEMENT ===');
  console.log('Headers:', req.headers);
  console.log('Origin:', req.headers.origin);
  
  const scanStartTime = performance.now();
  const memBefore = process.memoryUsage();
  
  try {
    if (!req.file) {
      return res.status(400).json({ 
        status: 'error', 
        message: 'No file uploaded',
        hint: 'Send file via multipart/form-data'
      });
    }

    // Extract environmental context from request body
    const { 
      environment = 'production',
      deployment = 'internet-facing',
      dataHandling = {
        personalData: false,
        financialData: false,
        healthData: false
      },
      compliance = []
    } = req.body;

    const filePath = req.file.path;
    console.log(`📁 File uploaded: ${req.file.originalname} (${req.file.size} bytes)`);
    console.log(`🌍 Environment: ${environment} ${deployment} system`);

    // Check Semgrep availability
    const semgrepAvailable = await checkSemgrepAvailability();
    if (!semgrepAvailable.available) {
      // Clean up uploaded file
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
      }
      return res.status(503).json({
        status: 'error',
        message: 'Semgrep scanner not available',
        details: semgrepAvailable.error
      });
    }

    // Read file content for enhanced processing
    const fileReadStartTime = performance.now();
    const fileContent = fs.readFileSync(filePath, 'utf8');
    const fileReadEndTime = performance.now();

    // Run Semgrep scan
    const semgrepStartTime = performance.now();
    const semgrepResults = await runSemgrepScanWithCodeExtraction(filePath, fileContent);
    const semgrepEndTime = performance.now();
    
    console.log(`🔧 STATIC: Semgrep file scan completed (${(semgrepEndTime - semgrepStartTime).toFixed(2)}ms)`);

    // Enhanced classification
    const classificationStartTime = performance.now();
    const classifier = new SecurityClassificationSystem();
    
    const componentContext = buildComponentContext({
      environment,
      deployment,
      dataHandling,
      compliance
    });

    const classifiedFindings = semgrepResults.results.map(finding => {
      const findingWithContext = {
        ...finding,
        context: componentContext
      };
      return classifier.classifyFinding(findingWithContext);
    });
    
    const riskAssessment = classifier.aggregateRiskScore(classifiedFindings, componentContext);
    const classificationEndTime = performance.now();
    
    // Generate enhanced report
    const report = generateStructuredReport({
      findings: classifiedFindings,
      riskAssessment,
      metadata: {
        scanned_at: new Date().toISOString(),
        file_size: req.file.size,
        filename: req.file.originalname,
        environment: componentContext,
        semgrep_version: semgrepAvailable.version,
        classification_version: '3.0'
      },
      performance: {
        totalScanTime: `${(performance.now() - scanStartTime).toFixed(2)}ms`,
        fileReadTime: `${(fileReadEndTime - fileReadStartTime).toFixed(2)}ms`,
        semgrepTime: `${(semgrepEndTime - semgrepStartTime).toFixed(2)}ms`,
        classificationTime: `${(classificationEndTime - classificationStartTime).toFixed(2)}ms`
      }
    });
    
    const scanEndTime = performance.now();
    const memAfter = process.memoryUsage();
    
    const performanceMetrics = {
      totalScanTime: `${(scanEndTime - scanStartTime).toFixed(2)}ms`,
      fileReadTime: `${(fileReadEndTime - fileReadStartTime).toFixed(2)}ms`,
      semgrepTime: `${(semgrepEndTime - semgrepStartTime).toFixed(2)}ms`,
      classificationTime: `${(classificationEndTime - classificationStartTime).toFixed(2)}ms`,
      memoryUsed: `${Math.round((memAfter.heapUsed - memBefore.heapUsed) / 1024 / 1024)}MB`
    };
    
    console.log('⚡ FILE SCAN PERFORMANCE:', performanceMetrics);
    
    // Clean up uploaded file
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
      console.log('🧹 Cleaned up uploaded file');
    }
    
    res.json({
      status: 'success',
      service: 'Neperia Security Scanner v3.0 - File Analysis',
      
      // Enhanced analysis summary
      analysis: {
        static: {
          filename: req.file.originalname,
          fileSize: req.file.size,
          findingsCount: classifiedFindings.length,
          riskScore: riskAssessment.riskScore,
          riskLevel: riskAssessment.riskLevel
        },
        aiReady: {
          enhancedFindings: classifiedFindings.length,
          aiMetadataIncluded: true,
          readyForAIAnalysis: aiRouter !== null
        }
      },
      
      report,
      
      // Legacy compatibility
      filename: req.file.originalname,
      findings: classifiedFindings,
      riskScore: riskAssessment.riskScore,
      metadata: report.metadata,
      riskAssessment,
      
      performance: performanceMetrics
    });
    
  } catch (error) {
    console.error('❌ File scan error:', error);
    console.error('Stack trace:', error.stack);
    
    // Clean up uploaded file on error
    if (req.file && req.file.path && fs.existsSync(req.file.path)) {
      try {
        fs.unlinkSync(req.file.path);
        console.log('🧹 Cleaned up uploaded file after error');
      } catch (cleanupError) {
        console.error('❌ Error cleaning up file:', cleanupError);
      }
    }
    
    res.status(500).json({ 
      status: 'error', 
      message: 'File scan failed',
      error: error.message,
      service: 'Neperia Security Scanner',
      timestamp: new Date().toISOString()
    });
  }
});

// Mount AI enhancement routes (if available)
if (aiRouter) {
  console.log('🤖 AI: Mounting AI enhancement endpoints under /api');
  app.use('/api', aiRouter);
} else {
  console.log('⚠️ AI: AI router not available - skipping AI endpoints');
  // Basic API info endpoint
  app.get('/api', (req, res) => {
    res.json({
      status: 'info',
      message: 'AI features not available',
      reason: 'aiRouter module not found',
      availableFeatures: 'Static analysis only'
    });
  });
}

// ✅ HELPER FUNCTIONS - All properly defined

/**
 * Check Semgrep availability
 */
function checkSemgrepAvailability() {
  return new Promise((resolve) => {
    exec('semgrep --version', (error, stdout, stderr) => {
      if (error) {
        console.error('🔧 STATIC: Semgrep not available:', error.message);
        resolve({ 
          available: false, 
          error: error.message,
          stderr: stderr
        });
      } else {
        console.log('🔧 STATIC: Semgrep version:', stdout.trim());
        resolve({ 
          available: true, 
          version: stdout.trim() 
        });
      }
    });
  });
}

/**
 * Enhanced Semgrep scan with proper code extraction and line numbers
 * 🔧 STATIC: Fixes the "requires login" placeholder issue
 */
async function runSemgrepScanWithCodeExtraction(filePath, fileContent) {
  console.log('🔧 STATIC: Running enhanced Semgrep scan with code extraction');
  
  return new Promise((resolve, reject) => {
    const semgrepArgs = [
      '--json',
      '--config=auto',
      '--skip-unknown-extensions',
      '--timeout=30',
      '--verbose',
      filePath
    ];

    console.log(`🔧 STATIC: Executing: semgrep ${semgrepArgs.join(' ')}`);
    
    const semgrep = spawn('semgrep', semgrepArgs, {
      stdio: ['pipe', 'pipe', 'pipe']
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
      console.log(`🔧 STATIC: Semgrep exited with code ${code}`);
      
      if (code !== 0) {
        console.error('❌ Semgrep stderr:', stderr);
        return reject(new Error(`Semgrep failed with code ${code}: ${stderr}`));
      }

      try {
        const results = JSON.parse(stdout);
        console.log(`🔧 STATIC: Semgrep found ${results.results?.length || 0} findings`);

        // **CRITICAL FIX**: Replace "requires login" with actual code lines
        if (results.results && results.results.length > 0 && fileContent) {
          const codeLines = fileContent.split('\n');
          
          results.results = results.results.map(finding => {
            const lineNumber = finding.start?.line || 1;
            const startCol = finding.start?.col || 0;
            const endCol = finding.end?.col || startCol + 10;
            
            // Extract the actual vulnerable line
            const vulnerableLine = codeLines[lineNumber - 1] || 'Line not found';
            
            // Extract code context (3 lines before and after)
            const contextStart = Math.max(0, lineNumber - 4);
            const contextEnd = Math.min(codeLines.length, lineNumber + 3);
            const codeContext = codeLines.slice(contextStart, contextEnd).join('\n');
            
            // **FIX THE "requires login" ISSUE**
            finding.extra = finding.extra || {};
            finding.extra.lines = vulnerableLine.trim();
            finding.extractedCode = vulnerableLine.trim();
            finding.extra.context = codeContext;
            
            // Enhanced location info
            finding.scannerData = {
              location: {
                file: filePath,
                line: lineNumber,
                column: startCol,
                endColumn: endCol
              }
            };
            
            console.log(`🔧 STATIC: Fixed code extraction for line ${lineNumber}: "${vulnerableLine.trim().substring(0, 50)}..."`);
            
            return finding;
          });
        }

        resolve(results);
      } catch (parseError) {
        console.error('❌ JSON parse error:', parseError);
        reject(new Error(`Failed to parse Semgrep JSON: ${parseError.message}`));
      }
    });

    semgrep.on('error', (error) => {
      console.error('❌ Semgrep spawn error:', error);
      reject(new Error(`Failed to spawn Semgrep: ${error.message}`));
    });
  });
}

/**
 * Enhanced component context builder
 * 🔧 STATIC: Proper environmental context for risk scoring
 */
function buildComponentContext(requestContext) {
  const { environment = 'production', deployment = 'internet-facing', dataHandling = {}, compliance = [] } = requestContext;
  
  const context = {
    // Environmental factors
    isProduction: environment === 'production',
    isInternetFacing: deployment === 'internet-facing' || deployment === 'public',
    hasNetworkAccess: deployment !== 'isolated',
    isLegacy: environment === 'legacy',
    
    // Data sensitivity
    handlesPersonalData: dataHandling.personalData || false,
    handlesFinancialData: dataHandling.financialData || false,
    handlesHealthData: dataHandling.healthData || false,
    
    // Compliance requirements
    regulatoryRequirements: Array.isArray(compliance) ? compliance : [],
    
    // Risk multipliers (critical for proper scoring)
    environmentMultiplier: environment === 'production' ? 1.5 : 1.0,
    deploymentMultiplier: deployment === 'internet-facing' ? 1.4 : 1.0,
    dataMultiplier: dataHandling.financialData ? 1.6 : dataHandling.personalData ? 1.4 : 1.0,
    
    // Summary for logging
    summary: `${environment} ${deployment} system${compliance.length ? ` (${compliance.join(', ')})` : ''}`
  };
  
  console.log('🔧 STATIC: Built context with multipliers:', {
    environment: context.environmentMultiplier,
    deployment: context.deploymentMultiplier,
    data: context.dataMultiplier
  });
  
  return context;
}

/**
 * Enhanced structured report generator
 * 🔧 STATIC: Proper risk scoring and structured output
 */
function generateStructuredReport({ findings, riskAssessment, metadata, performance }) {
  console.log(`🔧 STATIC: Generating structured report for ${findings.length} findings`);
  
  // Apply deduplication if available
  let processedFindings = findings;
  try {
    const { deduplicateFindings } = require('./findingDeduplicator');
    processedFindings = deduplicateFindings(findings);
    console.log(`🔧 STATIC: Deduplicated ${findings.length} findings to ${processedFindings.length}`);
  } catch (error) {
    console.log('⚠️ Deduplication not available, using raw findings');
  }
  
  // **FIX**: Ensure proper risk score calculation (0-100 scale)
  const normalizedRiskScore = Math.min(100, Math.round(riskAssessment.riskScore * 10));
  
  // Generate severity breakdown
  const severityBreakdown = processedFindings.reduce((breakdown, finding) => {
    const severity = finding.severity || 'Unknown';
    breakdown[severity] = (breakdown[severity] || 0) + 1;
    return breakdown;
  }, {});
  
  // **FIX**: Ensure OWASP categories are properly mapped
  const owaspBreakdown = processedFindings.reduce((breakdown, finding) => {
    const owasp = finding.owaspCategory || 'Unknown';
    breakdown[owasp] = (breakdown[owasp] || 0) + 1;
    return breakdown;
  }, {});
  
  const report = {
    // Executive summary
    summary: {
      totalFindings: processedFindings.length,
      uniqueVulnerabilities: processedFindings.length,
      riskScore: normalizedRiskScore,
      riskLevel: riskAssessment.riskLevel,
      confidence: riskAssessment.confidence || 'Medium'
    },
    
    // Technical details
    findings: processedFindings.map(finding => ({
      id: finding.id,
      title: finding.title,
      severity: finding.severity,
      cwe: finding.cwe,
      owasp: finding.owaspCategory,
      cvss: finding.cvss,
      location: finding.scannerData?.location,
      codeSnippet: finding.codeSnippet,
      description: finding.cwe?.description,
      remediation: finding.remediation,
      confidence: finding.confidence
    })),
    
    // Risk analysis
    riskAnalysis: {
      overallRisk: {
        score: normalizedRiskScore,
        level: riskAssessment.riskLevel,
        factors: [
          'Environmental context assessed',
          'Industry best practices applied',
          'CVSS 3.1 scoring methodology'
        ]
      },
      severityDistribution: severityBreakdown,
      owaspDistribution: owaspBreakdown,
      topRisks: processedFindings
        .filter(f => f.severity === 'Critical' || f.severity === 'High')
        .slice(0, 5)
        .map(f => ({
          title: f.title,
          severity: f.severity,
          cvss: f.cvss?.adjustedScore || f.cvss?.baseScore || 0
        }))
    },
    
    // Compliance mapping
    compliance: {
      owaspTop10: Object.keys(owaspBreakdown),
      frameworks: processedFindings
        .flatMap(f => f.complianceMapping || [])
        .map(c => c.framework)
        .filter((v, i, a) => a.indexOf(v) === i)
    },
    
    // Metadata
    metadata: {
      ...metadata,
      processedAt: new Date().toISOString(),
      reportVersion: '3.0',
      aiEnhancementAvailable: aiRouter !== null
    },
    
    // Performance metrics
    performance
  };
  
  console.log(`🔧 STATIC: Generated report - Risk: ${normalizedRiskScore}/100, Findings: ${processedFindings.length}`);
  return report;
}

// Catch-all for undefined routes
app.use('*', (req, res) => {
  console.log('=== 404 REQUEST ===');
  console.log('Path:', req.originalUrl);
  console.log('Method:', req.method);
  
  res.status(404).json({ 
    status: 'error', 
    message: 'Route not found',
    path: req.originalUrl,
    method: req.method,
    service: 'Neperia Security Scanner v3.0',
    available_routes: {
      core: [
        'GET / - System information and capabilities',
        'GET /healthz - Health check with component status',
        'GET /semgrep-status - Static analysis engine status'
      ],
      scanning: [
        'POST /scan - File upload scanning with AI enhancement',
        'POST /scan-code - Direct code scanning with AI enhancement'
      ],
      ai_enhancement: aiRouter ? [
        'POST /api/explain-finding - AI explanations for vulnerabilities',
        'POST /api/assess-risk - AI risk assessment and prioritization',
        'POST /api/plan-remediation - AI remediation planning',
        'POST /api/compliance-analysis - AI compliance analysis',
        'POST /api/generate-report - AI comprehensive reports',
        'GET /api/cache-stats - AI performance statistics'
      ] : [
        'AI features not available - aiRouter not configured'
      ]
    },
    timestamp: new Date().toISOString()
  });
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('=== UNHANDLED ERROR ===');
  console.error('Error:', error);
  console.error('Stack:', error.stack);
  
  if (res.headersSent) {
    return next(error);
  }
  
  res.status(500).json({ 
    status: 'error', 
    message: 'Internal server error',
    service: 'Neperia Security Scanner v3.0',
    error: process.env.NODE_ENV === 'development' ? error.message : undefined,
    timestamp: new Date().toISOString()
  });
});

// Function to start server with proper error handling
function startServer() {
  try {
    const server = app.listen(PORT, '0.0.0.0', () => {
      console.log('=== 🚀 NEPERIA SECURITY SCANNER STARTED SUCCESSFULLY ===');
      console.log(`🌐 Server running on port ${PORT}`);
      console.log(`🔧 Static Analysis: Semgrep + SecurityClassificationSystem v3.0`);
      console.log(`🤖 AI Enhancement: OpenAI GPT-4 (${process.env.OPENAI_API_KEY ? 'Ready' : 'Not Configured'})`);
      console.log(`🎯 Target Audiences: Developer, Consultant, Executive, Auditor`);
      console.log(`⚖️ Compliance: OWASP Top 10, CWE, CVSS 3.1, PCI-DSS, GDPR, HIPAA`);
      console.log(`🔗 CORS: Configured for Lovable.app integration`);
      console.log(`📊 Performance: Monitoring enabled`);
      console.log(`🏗️ Neperia Integration: SEA Manager & KPS compatible`);
      console.log(`🤖 AI Router: ${aiRouter ? 'Available' : 'Not Available'}`);
      console.log('=== Ready to accept scan requests ===');
      
      // Log server address info
      const address = server.address();
      console.log('Server address info:', address);
      
      // Check system readiness
      checkSystemReadiness();
    });
    
    server.on('error', (error) => {
      console.error('=== ❌ SERVER ERROR ===');
      console.error('Server error:', error);
      if (error.code === 'EADDRINUSE') {
        console.error(`Port ${PORT} is already in use`);
      }
    });
    
    server.on('connection', (socket) => {
      console.log('🔌 New connection established from:', socket.remoteAddress);
    });
    
    // Graceful shutdown handlers
    process.on('SIGTERM', () => {
      console.log('🛑 SIGTERM received, shutting down gracefully');
      server.close(() => {
        console.log('✅ Server closed');
        process.exit(0);
      });
    });

    process.on('SIGINT', () => {
      console.log('🛑 SIGINT received, shutting down gracefully');
      server.close(() => {
        console.log('✅ Server closed');
        process.exit(0);
      });
    });
    
  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
}

// Check system readiness on startup
async function checkSystemReadiness() {
  console.log('=== 🔍 SYSTEM READINESS CHECK ===');
  
  try {
    // Check Semgrep availability
    const semgrepStatus = await checkSemgrepAvailability();
    if (semgrepStatus.available) {
      console.log('✅ Semgrep Static Analysis: Available -', semgrepStatus.version);
    } else {
      console.log('❌ Semgrep Static Analysis: Not Available -', semgrepStatus.error);
    }
    
    // Check OpenAI configuration
    if (process.env.OPENAI_API_KEY) {
      console.log('✅ OpenAI GPT-4 AI Enhancement: API Key Configured');
    } else {
      console.log('⚠️ OpenAI GPT-4 AI Enhancement: API Key Not Configured (AI features disabled)');
    }
    
    // Check SecurityClassificationSystem
    try {
      const testClassifier = new SecurityClassificationSystem();
      console.log('✅ SecurityClassificationSystem v3.0: Initialized');
    } catch (error) {
      console.log('❌ SecurityClassificationSystem: Failed to initialize -', error.message);
    }
    
    // Check AI Router
    if (aiRouter) {
      console.log('✅ AI Router: Available - AI endpoints mounted');
    } else {
      console.log('⚠️ AI Router: Not Available - AI endpoints disabled');
    }
    
    // Check file system permissions
    const tempDir = path.join(os.tmpdir(), 'scan-temp');
    try {
      if (!fs.existsSync(tempDir)) {
        fs.mkdirSync(tempDir, { recursive: true });
      }
      fs.writeFileSync(path.join(tempDir, 'test.txt'), 'test');
      fs.unlinkSync(path.join(tempDir, 'test.txt'));
      console.log('✅ File System: Read/Write permissions available');
    } catch (error) {
      console.log('❌ File System: Permission error -', error.message);
    }
    
    // Check deduplication
    try {
      require('./findingDeduplicator');
      console.log('✅ Deduplication: Available');
    } catch (error) {
      console.log('⚠️ Deduplication: Not available (optional feature)');
    }
    
    console.log('=== 🎯 SYSTEM READY FOR NEPERIA MODERNIZATION PROJECTS ===');
    
  } catch (error) {
    console.error('❌ System readiness check failed:', error);
  }
}

// Start the server
console.log('🚀 Initializing Neperia Cybersecurity Analysis Tool v3.0...');
startServer();