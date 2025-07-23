// src/server.js - Complete corrected server with AI integration
const express = require('express');
const multer = require('multer');
const { spawn, exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { performance } = require('perf_hooks'); 
require('dotenv').config();

// Import the enhanced SecurityClassificationSystem
const { SecurityClassificationSystem } = require('./SecurityClassificationSystem');

// Import AI router
const aiRouter = require('./aiRouter');

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
    version: '2.0',
    status: 'active',
    features: {
      staticAnalysis: 'Semgrep + CWE + OWASP + CVSS',
      aiEnhancement: 'OpenAI GPT-4 Explanations',
      classification: 'SecurityClassificationSystem v2.0',
      audiences: ['developer', 'consultant', 'executive', 'auditor']
    },
    timestamp: new Date().toISOString(),
    endpoints: {
      'GET /': 'Root endpoint with system info',
      'GET /healthz': 'Health check',
      'GET /semgrep-status': 'Check Semgrep availability',
      'POST /scan': 'File scanning with AI enhancement',
      'POST /scan-code': 'Code scanning with AI enhancement',
      'POST /api/explain-finding': 'AI explanations for vulnerabilities',
      'POST /api/assess-risk': 'AI risk assessment',
      'POST /api/plan-remediation': 'AI remediation planning',
      'POST /api/compliance-analysis': 'AI compliance analysis',
      'POST /api/generate-report': 'AI-generated reports'
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
    version: '2.0',
    components: {
      semgrep: 'checking...',
      openai: process.env.OPENAI_API_KEY ? 'available' : 'not-configured',
      classification: 'SecurityClassificationSystem v2.0'
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

// 🚀 ENHANCED: Code scanning endpoint with AI integration
app.post('/scan-code', async (req, res) => {
  console.log('=== 🔍 CODE SCAN REQUEST WITH AI ENHANCEMENT ===');
  console.log('Headers:', req.headers);
  console.log('Origin:', req.headers.origin);
  
  const scanStartTime = performance.now();
  const memBefore = process.memoryUsage();
  
  try {
    const { 
      code, 
      language = 'javascript', 
      filename = 'code.js',
      // Enhanced environmental context for AI
      environment = 'production',
      deployment = 'internet-facing',
      dataHandling = {
        personalData: false,
        financialData: false,
        healthData: false
      },
      compliance = []
    } = req.body;
    
    if (!code || typeof code !== 'string' || code.trim() === '') {
      return res.status(400).json({ 
        status: 'error', 
        message: 'No code provided',
        hint: 'Send code in request body for analysis'
      });
    }

    console.log(`📝 Code analysis: ${code.length} chars, ${language}, ${filename}`);
    console.log(`🌍 Environment: ${environment} ${deployment} system`);
    console.log(`📊 Data context: ${JSON.stringify(dataHandling)}`);
    console.log(`⚖️ Compliance: ${compliance.join(', ') || 'none'}`);

    // Check Semgrep availability
    const semgrepAvailable = await checkSemgrepAvailability();
    if (!semgrepAvailable.available) {
      return res.status(503).json({
        status: 'error',
        message: 'Semgrep scanner not available',
        details: semgrepAvailable.error,
        service: 'Static Analysis'
      });
    }

    // Create temporary file for scanning
    const tempDir = path.join(os.tmpdir(), 'scan-temp');
    if (!fs.existsSync(tempDir)) {
      fs.mkdirSync(tempDir, { recursive: true });
    }
    
    const tempFilePath = path.join(tempDir, `${Date.now()}-${filename}`);
    fs.writeFileSync(tempFilePath, code, 'utf8');
    
    console.log(`📁 Created temp file: ${tempFilePath}`);

    // 🔧 STATIC: Run Semgrep scan
    const semgrepStartTime = performance.now();
    const semgrepResults = await runSemgrepScanWithCodeExtraction(tempFilePath, code);
    const semgrepEndTime = performance.now();
    
    console.log(`🔧 STATIC: Semgrep scan completed (${(semgrepEndTime - semgrepStartTime).toFixed(2)}ms)`);
    console.log(`🔧 STATIC: Found ${semgrepResults.results?.length || 0} raw findings`);

    // 🔧 STATIC: Enhanced classification with SecurityClassificationSystem
    const classificationStartTime = performance.now();
    const classifier = new SecurityClassificationSystem();
    
    // Build dynamic component context for AI
    const componentContext = buildComponentContext({
      environment,
      deployment,
      dataHandling,
      compliance
    });

    console.log(`🔧 STATIC: Environmental context:`, componentContext.summary);
    
    // Classify each finding with AI-ready metadata
    const classifiedFindings = semgrepResults.results.map(finding => {
      const findingWithContext = {
        ...finding,
        context: componentContext
      };
      const classified = classifier.classifyFinding(findingWithContext);
      
      console.log(`🔧 STATIC: Classified ${classified.cwe?.name} as ${classified.severity} (CVSS: ${classified.cvss?.adjustedScore})`);
      return classified;
    });
    
    // Calculate aggregated risk assessment
    const riskAssessment = classifier.aggregateRiskScore(classifiedFindings, componentContext);
    
    const classificationEndTime = performance.now();
    console.log(`🔧 STATIC: Classification completed (${(classificationEndTime - classificationStartTime).toFixed(2)}ms)`);
    console.log(`🔧 STATIC: Overall risk: ${riskAssessment.riskScore} (${riskAssessment.riskLevel})`);

    // Generate structured report with AI-ready data
    const report = generateStructuredReport({
      findings: classifiedFindings,
      riskAssessment,
      metadata: {
        scanned_at: new Date().toISOString(),
        code_length: code.length,
        language,
        filename,
        environment: componentContext,
        semgrep_version: semgrepAvailable.version,
        classification_version: '2.0'
      },
      performance: {
        totalScanTime: `${(performance.now() - scanStartTime).toFixed(2)}ms`,
        semgrepTime: `${(semgrepEndTime - semgrepStartTime).toFixed(2)}ms`,
        classificationTime: `${(classificationEndTime - classificationStartTime).toFixed(2)}ms`
      }
    });
    
    // Calculate final performance metrics
    const scanEndTime = performance.now();
    const memAfter = process.memoryUsage();
    
    const performanceMetrics = {
      totalScanTime: `${(scanEndTime - scanStartTime).toFixed(2)}ms`,
      semgrepTime: `${(semgrepEndTime - semgrepStartTime).toFixed(2)}ms`,
      classificationTime: `${(classificationEndTime - classificationStartTime).toFixed(2)}ms`,
      memoryUsed: `${Math.round((memAfter.heapUsed - memBefore.heapUsed) / 1024 / 1024)}MB`,
      totalMemory: `${Math.round(memAfter.heapTotal / 1024 / 1024)}MB`
    };
    
    console.log('⚡ PERFORMANCE METRICS:', performanceMetrics);
    
    // Clean up temp file
    if (fs.existsSync(tempFilePath)) {
      fs.unlinkSync(tempFilePath);
      console.log('🧹 Cleaned up temp file');
    }
    
    // Send enhanced response with AI-ready data
    res.json({
      status: 'success',
      service: 'Neperia Security Scanner v2.0',
      analysis: {
        static: {
          semgrepFindings: semgrepResults.results?.length || 0,
          classification: 'SecurityClassificationSystem v2.0',
          riskScore: riskAssessment.riskScore,
          riskLevel: riskAssessment.riskLevel
        },
        aiReady: {
          enhancedFindings: classifiedFindings.length,
          aiMetadataIncluded: true,
          audienceTargeting: ['developer', 'consultant', 'executive', 'auditor'],
          aiEndpoints: [
            '/api/explain-finding - Individual vulnerability explanations',
            '/api/assess-risk - Overall risk assessment', 
            '/api/plan-remediation - Detailed remediation planning',
            '/api/compliance-analysis - Regulatory compliance analysis',
            '/api/generate-report - Comprehensive reports'
          ]
        }
      },
      
      // Enhanced structured report
      report,
      
      // Legacy compatibility fields
      findings: classifiedFindings,
      riskScore: riskAssessment.riskScore,
      metadata: report.metadata,
      riskAssessment,
      
      // Performance data
      performance: performanceMetrics,
      
      // Next steps for AI enhancement
      nextSteps: {
        aiExplanations: 'POST /api/explain-finding with finding + audience',
        riskAnalysis: 'POST /api/assess-risk with findings array',
        remediationPlanning: 'POST /api/plan-remediation with finding + project context',
        complianceCheck: 'POST /api/compliance-analysis with findings + compliance context',
        executiveReport: 'POST /api/generate-report with findings + context'
      }
    });
    
  } catch (error) {
    console.error('❌ Code scan error:', error);
    console.error('Stack trace:', error.stack);
    
    const errorEndTime = performance.now();
    const errorResponseTime = `${(errorEndTime - scanStartTime).toFixed(2)}ms`;
    console.log('⚡ ERROR RESPONSE TIME:', errorResponseTime);
    
    res.status(500).json({ 
      status: 'error', 
      message: 'Code scan failed',
      error: error.message,
      service: 'Neperia Security Scanner',
      timestamp: new Date().toISOString(),
      performance: {
        errorResponseTime: errorResponseTime
      }
    });
  }
});

// 🚀 ENHANCED: File upload scan endpoint with AI integration
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

    // 🔧 STATIC: Run Semgrep scan
    const semgrepStartTime = performance.now();
    const semgrepResults = await runSemgrepScanWithCodeExtraction(filePath, fileContent);
    const semgrepEndTime = performance.now();
    
    console.log(`🔧 STATIC: Semgrep file scan completed (${(semgrepEndTime - semgrepStartTime).toFixed(2)}ms)`);

    // 🔧 STATIC: Enhanced classification
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
        classification_version: '2.0'
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
      service: 'Neperia Security Scanner v2.0 - File Analysis',
      
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
          readyForAIAnalysis: true
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

// Mount AI enhancement routes
console.log('🤖 AI: Mounting AI enhancement endpoints under /api');
app.use('/api', aiRouter);

// Function to check Semgrep availability
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

// Enhanced Semgrep scan function with code extraction
function runSemgrepScanWithCodeExtraction(filePath, originalCode) {
  return new Promise((resolve, reject) => {
    console.log('🔧 STATIC: Starting enhanced Semgrep scan');
    console.log('File path:', filePath);
    
    if (!fs.existsSync(filePath)) {
      return reject(new Error('File not found: ' + filePath));
    }
    
    const fileContent = fs.readFileSync(filePath, 'utf8');
    console.log(`🔧 STATIC: File content: ${fileContent.length} chars`);
    
    const semgrepArgs = [
      '--json',
      '--config=auto',
      '--skip-unknown-extensions',
      '--timeout=30',
      '--verbose',
      filePath
    ];
    
    console.log('🔧 STATIC: Semgrep command:', 'semgrep', semgrepArgs.join(' '));
    
    const semgrepProcessStartTime = performance.now();
    const semgrepProcess = spawn('semgrep', semgrepArgs, {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: { ...process.env, PATH: process.env.PATH }
    });
    
    let stdout = '';
    let stderr = '';
    
    semgrepProcess.stdout.on('data', (data) => {
      stdout += data.toString();
    });
    
    semgrepProcess.stderr.on('data', (data) => {
      stderr += data.toString();
    });
    
    semgrepProcess.on('close', (code) => {
      const semgrepProcessEndTime = performance.now();
      const semgrepProcessTime = semgrepProcessEndTime - semgrepProcessStartTime;
      
      console.log('🔧 STATIC: Semgrep scan completed');
      console.log('Exit code:', code);
      console.log('Process time:', `${semgrepProcessTime.toFixed(2)}ms`);
      
      if (code === 0 || code === 1) {
        // Success cases
        try {
          const parseStartTime = performance.now();
          const results = stdout ? JSON.parse(stdout) : { results: [] };
          const parseEndTime = performance.now();
          
          console.log(`🔧 STATIC: Parsed ${results.results?.length || 0} findings`);
          
          // Enhance findings with actual code extraction
          if (results.results && results.results.length > 0) {
            const enhancementStartTime = performance.now();
            const codeLines = originalCode.split('\n');
            
            results.results = results.results.map(finding => {
              const lineNumber = finding.start?.line || 1;
              const vulnerableLine = codeLines[lineNumber - 1] || '';
              
              console.log(`🔧 STATIC: Enhancing finding at line ${lineNumber}`);
              
              // Enhance with extracted code
              finding.extra = finding.extra || {};
              finding.extra.lines = vulnerableLine.trim();
              finding.extra.rendered_text = vulnerableLine.trim();
              finding.extra.original_code = vulnerableLine.trim();
              finding.extractedCode = vulnerableLine.trim();
              
              // Add context lines
              const startLine = Math.max(0, lineNumber - 2);
              const endLine = Math.min(codeLines.length, lineNumber + 2);
              const contextLines = codeLines.slice(startLine, endLine);
              finding.extra.context = contextLines.join('\n');
              
              return finding;
            });
            
            const enhancementEndTime = performance.now();
            console.log(`🔧 STATIC: Enhancement completed (${(enhancementEndTime - enhancementStartTime).toFixed(2)}ms)`);
          }
          
          // Add performance metadata to results
          results.performance = {
            semgrepProcessTime: `${semgrepProcessTime.toFixed(2)}ms`,
            jsonParseTime: `${(parseEndTime - parseStartTime).toFixed(2)}ms`,
            findingsCount: results.results?.length || 0
          };
          
          resolve(results);
        } catch (parseError) {
          console.error('🔧 STATIC: Failed to parse Semgrep output:', parseError);
          resolve({ 
            results: [], 
            raw_output: stdout.substring(0, 1000),
            parse_error: parseError.message 
          });
        }
      } else {
        const errorMessage = `Semgrep failed with exit code ${code}: ${stderr}`;
        console.error('🔧 STATIC: Semgrep error:', errorMessage);
        reject(new Error(errorMessage));
      }
    });
    
    semgrepProcess.on('error', (error) => {
      console.error('🔧 STATIC: Semgrep spawn error:', error);
      reject(error);
    });
    
    // Timeout prevention
    const timeout = setTimeout(() => {
      console.error('🔧 STATIC: Semgrep scan timeout');
      semgrepProcess.kill('SIGTERM');
      reject(new Error('Semgrep scan timeout'));
    }, 45000);
    
    semgrepProcess.on('close', () => {
      clearTimeout(timeout);
    });
  });
}

// Helper function to build component context for AI
function buildComponentContext(options) {
  const { environment, deployment, dataHandling, compliance } = options;
  
  return {
    // Environment type flags
    isProduction: environment === 'production',
    isDevelopment: environment === 'development',
    isStaging: environment === 'staging',
    isLegacy: environment === 'legacy',
    
    // Deployment context flags
    isInternetFacing: deployment === 'internet-facing',
    hasNetworkAccess: deployment !== 'air-gapped',
    isInternal: deployment === 'internal',
    isAirGapped: deployment === 'air-gapped',
    
    // Data handling flags
    handlesPersonalData: dataHandling.personalData,
    handlesFinancialData: dataHandling.financialData,
    handlesHealthData: dataHandling.healthData,
    
    // Compliance requirements
    regulatoryRequirements: compliance,
    
    // Risk multiplier calculation
    environmentMultiplier: calculateEnvironmentMultiplier(environment, deployment),
    
    // Human-readable summary for AI
    summary: `${environment} ${deployment} system${compliance.length ? ` (${compliance.join(', ')})` : ''}`,
    
    // Additional context for AI
    environment,
    deployment
  };
}

// Calculate environment-based risk multiplier
function calculateEnvironmentMultiplier(environment, deployment) {
  const baseMultipliers = {
    'production': 1.0,
    'legacy': 0.9,
    'staging': 0.7,
    'development': 0.5
  };
  
  const deploymentMultipliers = {
    'internet-facing': 1.5,
    'external': 1.3,
    'internal': 1.0,
    'air-gapped': 0.7
  };
  
  const base = baseMultipliers[environment] || 1.0;
  const deploy = deploymentMultipliers[deployment] || 1.0;
  
  return base * deploy;
}

// Generate structured report with AI-ready metadata
function generateStructuredReport(data) {
  const { findings, riskAssessment, metadata, performance } = data;
  
  // Group findings by severity
  const findingsBySeverity = {
    Critical: findings.filter(f => f.severity === 'Critical'),
    High: findings.filter(f => f.severity === 'High'),
    Medium: findings.filter(f => f.severity === 'Medium'),
    Low: findings.filter(f => f.severity === 'Low')
  };
  
  // Get top risks with enhanced data
  const topRisks = findings
    .sort((a, b) => (b.cvss?.adjustedScore || 0) - (a.cvss?.adjustedScore || 0))
    .slice(0, 3)
    .map(f => ({
      id: f.id,
      title: f.title,
      cwe: f.cwe?.name,
      score: f.cvss?.adjustedScore,
      file: f.scannerData?.location?.file,
      line: f.scannerData?.location?.line,
      impact: f.impact,
      businessRisk: f.businessRisk
    }));
  
  return {
    // Executive Summary with AI-ready data
    executiveSummary: {
      scanDate: metadata.scanned_at,
      projectName: metadata.filename,
      totalFindings: findings.length,
      findingsBySeverity: {
        critical: findingsBySeverity.Critical.length,
        high: findingsBySeverity.High.length,
        medium: findingsBySeverity.Medium.length,
        low: findingsBySeverity.Low.length
      },
      overallRiskRating: riskAssessment.riskLevel,
      riskScore: riskAssessment.riskScore,
      riskConfidence: riskAssessment.confidence,
      topRisks,
      environmentContext: metadata.environment.summary,
      businessRiskFlags: {
        handlesPII: metadata.environment.handlesPersonalData,
        handlesFinancial: metadata.environment.handlesFinancialData,
        handlesHealth: metadata.environment.handlesHealthData,
        complianceRequired: metadata.environment.regulatoryRequirements?.length > 0
      }
    },
    
    // Component Risk Analysis
    componentRisk: analyzeComponentRisk(findings),
    
    // Enhanced Findings for AI Processing
    findings: findings.map(f => ({
      // Core finding data
      id: f.id,
      title: f.title,
      ruleId: f.ruleId,
      
      // Classification (🔧 STATIC)
      cwe: f.cwe,
      owaspCategory: f.owaspCategory,
      severity: f.severity,
      
      // Location and code (🔧 STATIC)
      file: f.scannerData?.location?.file,
      line: f.scannerData?.location?.line,
      extractedCode: f.codeSnippet,
      codeContext: f.codeContext,
      
      // Risk assessment (🔧 STATIC)
      cvss: f.cvss,
      businessImpact: f.impact,
      businessRisk: f.businessRisk,
      exploitability: f.exploitability,
      
      // Remediation guidance (🔧 STATIC templates, 🤖 AI-enhanceable)
      remediation: f.remediation,
      remediationComplexity: f.remediationComplexity,
      
      // Compliance mapping (🔧 STATIC)
      complianceMapping: f.complianceMapping,
      
      // AI metadata (🤖 AI-READY)
      aiMetadata: f.aiMetadata,
      aiEnhancementAvailable: true
    })),
    
    // Remediation Checklist
    remediationChecklist: generateRemediationChecklist(findings),
    
    // AI Enhancement Instructions
    aiEnhancement: {
      available: true,
      endpoints: {
        explanations: '/api/explain-finding',
        riskAssessment: '/api/assess-risk',
        remediationPlanning: '/api/plan-remediation',
        complianceAnalysis: '/api/compliance-analysis',
        comprehensiveReport: '/api/generate-report'
      },
      audiences: ['developer', 'consultant', 'executive', 'auditor'],
      enhancementReady: findings.every(f => f.aiMetadata)
    },
    
    // Technical Metadata
    technicalMetadata: {
      ...metadata,
      performance,
      scanEngine: 'Semgrep v' + (metadata.semgrep_version || 'unknown'),
      classificationSystem: 'SecurityClassificationSystem v2.0',
      aiIntegration: 'OpenAI GPT-4 Ready',
      neperiaCompatible: true
    }
  };
}

// Analyze risk by component/file
function analyzeComponentRisk(findings) {
  const componentMap = new Map();
  
  findings.forEach(f => {
    const file = f.scannerData?.location?.file || 'unknown';
    if (!componentMap.has(file)) {
      componentMap.set(file, {
        file,
        findings: [],
        highestRisk: 0,
        totalRisk: 0,
        severityBreakdown: { Critical: 0, High: 0, Medium: 0, Low: 0 }
      });
    }
    
    const component = componentMap.get(file);
    component.findings.push(f);
    component.highestRisk = Math.max(component.highestRisk, f.cvss?.adjustedScore || 0);
    component.totalRisk += f.cvss?.adjustedScore || 0;
    
    if (component.severityBreakdown[f.severity] !== undefined) {
      component.severityBreakdown[f.severity]++;
    }
  });
  
  return Array.from(componentMap.values()).map(c => ({
    file: c.file,
    findingsCount: c.findings.length,
    highestRisk: c.highestRisk,
    averageRisk: c.findings.length > 0 ? (c.totalRisk / c.findings.length).toFixed(1) : 0,
    classification: getRiskClassification(c.highestRisk),
    severityBreakdown: c.severityBreakdown,
    aiAnalysisAvailable: true
  })).sort((a, b) => b.highestRisk - a.highestRisk);
}

// Generate remediation checklist
function generateRemediationChecklist(findings) {
  const checklist = findings
    .sort((a, b) => (b.cvss?.adjustedScore || 0) - (a.cvss?.adjustedScore || 0))
    .map(f => ({
      id: f.id,
      action: f.remediation?.immediate || `Address ${f.cwe?.name}`,
      severity: f.severity,
      file: f.scannerData?.location?.file,
      line: f.scannerData?.location?.line,
      cwe: f.cwe?.id,
      priority: getPriority(f.cvss?.adjustedScore || 0),
      complexity: f.remediationComplexity?.level || 'unknown',
      estimatedEffort: getEffortEstimate(f.remediationComplexity?.score || 5),
      aiPlanningAvailable: true
    }));
  
  // Remove duplicates by action + file
  const seen = new Set();
  return checklist.filter(item => {
    const key = `${item.action}:${item.file}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

// Helper functions
function getRiskClassification(score) {
  if (score >= 9.0) return 'Critical';
  if (score >= 7.0) return 'High';
  if (score >= 4.0) return 'Medium';
  return 'Low';
}

function getPriority(score) {
  if (score >= 9.0) return 'P0 - Immediate';
  if (score >= 7.0) return 'P1 - High';
  if (score >= 4.0) return 'P2 - Medium';
  return 'P3 - Low';
}

function getEffortEstimate(complexityScore) {
  if (complexityScore >= 8) return '2-4 weeks';
  if (complexityScore >= 6) return '1-2 weeks';
  if (complexityScore >= 4) return '3-5 days';
  return '1-2 days';
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
    service: 'Neperia Security Scanner v2.0',
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
      ai_enhancement: [
        'POST /api/explain-finding - AI explanations for vulnerabilities',
        'POST /api/assess-risk - AI risk assessment and prioritization',
        'POST /api/plan-remediation - AI remediation planning',
        'POST /api/compliance-analysis - AI compliance analysis',
        'POST /api/generate-report - AI comprehensive reports',
        'GET /api/cache-stats - AI performance statistics'
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
    service: 'Neperia Security Scanner v2.0',
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
      console.log(`🔧 Static Analysis: Semgrep + SecurityClassificationSystem v2.0`);
      console.log(`🤖 AI Enhancement: OpenAI GPT-4 (${process.env.OPENAI_API_KEY ? 'Ready' : 'Not Configured'})`);
      console.log(`🎯 Target Audiences: Developer, Consultant, Executive, Auditor`);
      console.log(`⚖️ Compliance: OWASP Top 10, CWE, CVSS 3.1, PCI-DSS, GDPR, HIPAA`);
      console.log(`🔗 CORS: Configured for Lovable.app integration`);
      console.log(`📊 Performance: Monitoring enabled`);
      console.log(`🏗️ Neperia Integration: SEA Manager & KPS compatible`);
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
      console.log('✅ SecurityClassificationSystem v2.0: Initialized');
    } catch (error) {
      console.log('❌ SecurityClassificationSystem: Failed to initialize -', error.message);
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
    
    console.log('=== 🎯 SYSTEM READY FOR NEPERIA MODERNIZATION PROJECTS ===');
    
  } catch (error) {
    console.error('❌ System readiness check failed:', error);
  }
}

// Start the server
console.log('🚀 Initializing Neperia Cybersecurity Analysis Tool v2.0...');
startServer();