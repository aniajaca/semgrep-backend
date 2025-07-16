const express = require('express');
const multer = require('multer');
const { spawn, exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

const app = express();
const PORT = process.env.PORT || 3000;

// Global error handlers to prevent crashes
process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error);
  console.error('Stack:', error.stack);
  // Don't exit immediately in production, let Railway handle restarts
  if (process.env.NODE_ENV !== 'production') {
    process.exit(1);
  }
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
  // Don't exit immediately in production
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
console.log('Allowed Origin:', process.env.ALLOWED_ORIGIN || 'not set');
console.log('Current working directory:', process.cwd());
console.log('Temp directory:', os.tmpdir());

// FIXED CORS middleware - properly configured for Lovable frontend
const customCors = (req, res, next) => {
  try {
    const origin = req.headers.origin;
    
    // List of allowed origins
    const allowedOrigins = [
      'https://preview--neperia-code-guardian.lovable.app',
      'https://neperia-code-guardian.lovable.app',
      'https://lovable.app',
      'http://localhost:3000',
      'http://localhost:5173' // Vite dev server
    ];
    
    // Check if origin is allowed or if it's a Lovable subdomain
    const isAllowed = allowedOrigins.includes(origin) || 
                     (origin && origin.includes('.lovable.app'));
    
    if (isAllowed || !origin) {
      res.setHeader('Access-Control-Allow-Origin', origin || '*');
    } else {
      res.setHeader('Access-Control-Allow-Origin', 'https://preview--neperia-code-guardian.lovable.app');
    }
    
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, Accept, Origin');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Max-Age', '86400'); // 24 hours
    
    console.log(`CORS: Origin ${origin} -> ${isAllowed ? 'ALLOWED' : 'DEFAULT'}`);
    
    if (req.method === 'OPTIONS') {
      console.log('Handling OPTIONS preflight request');
      return res.status(200).end();
    }
    
    next();
  } catch (error) {
    console.error('CORS middleware error:', error);
    next(error);
  }
};

// Request logging middleware
app.use((req, res, next) => {
  const timestamp = new Date().toISOString();
  console.log(`${timestamp} - ${req.method} ${req.path} - Origin: ${req.headers.origin || 'none'}`);
  console.log(`User-Agent: ${req.get('User-Agent') || 'none'}`);
  console.log(`IP: ${req.ip}`);
  next();
});

// Apply CORS middleware FIRST
app.use(customCors);

// Body parsing middleware with error handling
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    try {
      const uploadDir = path.join(os.tmpdir(), 'uploads');
      if (!fs.existsSync(uploadDir)) {
        fs.mkdirSync(uploadDir, { recursive: true });
        console.log('Created upload directory:', uploadDir);
      }
      cb(null, uploadDir);
    } catch (error) {
      console.error('Error creating upload directory:', error);
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
      console.error('Error generating filename:', error);
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
    // Accept all files for now, let Semgrep handle compatibility
    cb(null, true);
  }
});

// Root route - simplified for Railway
app.get('/', (req, res) => {
  console.log('🏠 Root accessed');
  res.status(200).json({
    message: 'Cybersecurity Scanner API is running',
    status: 'active',
    timestamp: new Date().toISOString(),
    endpoints: {
      'GET /': 'Root endpoint',
      'GET /healthz': 'Health check',
      'GET /semgrep-status': 'Check Semgrep availability',
      'POST /scan': 'File scanning endpoint',
      'POST /scan-code': 'Direct code scanning endpoint'
    }
  });
});

// Health check endpoint - Railway compatible (simplified)
app.get('/healthz', (req, res) => {
  console.log('🏥 Health check accessed');
  console.log('Headers:', JSON.stringify(req.headers, null, 2));
  
  // Set explicit headers for Railway
  res.set({
    'Content-Type': 'application/json',
    'Cache-Control': 'no-cache'
  });
  
  // Send JSON response for better frontend integration
  res.status(200).json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// Alternative health check endpoint
app.get('/health', (req, res) => {
  console.log('🏥 /health accessed');
  res.status(200).json({
    status: 'healthy',
    service: 'semgrep-scanner',
    timestamp: new Date().toISOString()
  });
});

// Debug endpoint for Railway troubleshooting
app.get('/debug', (req, res) => {
  try {
    res.json({
      headers: req.headers,
      ip: req.ip,
      ips: req.ips,
      method: req.method,
      path: req.path,
      query: req.query,
      timestamp: new Date().toISOString(),
      port: PORT,
      environment: process.env.NODE_ENV,
      railway: {
        deploymentId: process.env.RAILWAY_DEPLOYMENT_ID,
        projectId: process.env.RAILWAY_PROJECT_ID,
        serviceId: process.env.RAILWAY_SERVICE_ID,
        environment: process.env.RAILWAY_ENVIRONMENT,
      }
    });
  } catch (error) {
    console.error('Error in debug route:', error);
    res.status(500).json({ status: 'error', message: 'Debug endpoint error' });
  }
});

// Semgrep status endpoint
app.get('/semgrep-status', (req, res) => {
  console.log('=== SEMGREP STATUS REQUEST ===');
  
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

// API info endpoint
app.get('/api', (req, res) => {
  try {
    res.status(200).json({ 
      status: 'success', 
      message: 'API is running',
      endpoints: {
        'GET /': 'Root endpoint',
        'GET /healthz': 'Health check',
        'GET /health': 'Alternative health check',
        'GET /semgrep-status': 'Check Semgrep availability',
        'GET /debug': 'Debug information',
        'POST /scan': 'File scanning endpoint',
        'POST /scan-code': 'Direct code scanning endpoint'
      },
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Error in API info route:', error);
    res.status(500).json({ status: 'error', message: 'Internal server error' });
  }
});

// 🔧 ENHANCED: Code scanning endpoint with PERFORMANCE MONITORING
app.post('/scan-code', async (req, res) => {
  console.log('=== CODE SCAN REQUEST RECEIVED ===');
  console.log('Headers:', req.headers);
  console.log('Origin:', req.headers.origin);
  
  // 🔧 ADD PERFORMANCE MONITORING
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
    console.log('Code preview:', code.substring(0, 200) + '...');

    // Check if Semgrep is available before trying to scan
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
    
    // 🔧 CRITICAL FIX: Write the actual code to the file
    fs.writeFileSync(tempFilePath, code, 'utf8');
    
    console.log('Created temp file:', tempFilePath);
    console.log('File content length:', fs.readFileSync(tempFilePath, 'utf8').length);

    // 🔧 MEASURE SEMGREP TIME
    const semgrepStartTime = performance.now();
    const semgrepResults = await runSemgrepScanWithCodeExtraction(tempFilePath, code);
    const semgrepEndTime = performance.now();
    
    // 🔧 MEASURE CLASSIFICATION TIME (placeholder for when SecurityClassificationSystem is integrated)
    const classificationStartTime = performance.now();
    // TODO: Add SecurityClassificationSystem integration here
    // const classifiedFindings = classifier.classifyFindings(semgrepResults.results);
    const classificationEndTime = performance.now();
    
    // 🔧 FINAL PERFORMANCE METRICS
    const scanEndTime = performance.now();
    const memAfter = process.memoryUsage();
    
    const performanceMetrics = {
      totalScanTime: `${(scanEndTime - scanStartTime).toFixed(2)}ms`,
      semgrepTime: `${(semgrepEndTime - semgrepStartTime).toFixed(2)}ms`,
      classificationTime: `${(classificationEndTime - classificationStartTime).toFixed(2)}ms`,
      memoryUsed: `${Math.round((memAfter.heapUsed - memBefore.heapUsed) / 1024 / 1024)}MB`,
      totalMemory: `${Math.round(memAfter.heapTotal / 1024 / 1024)}MB`,
      peakMemory: `${Math.round(memAfter.heapUsed / 1024 / 1024)}MB`
    };
    
    console.log('🔧 PERFORMANCE METRICS:', performanceMetrics);
    
    // Clean up temp file
    if (fs.existsSync(tempFilePath)) {
      fs.unlinkSync(tempFilePath);
      console.log('Cleaned up temp file');
    }
    
    res.json({
      status: 'success',
      language: language,
      findings: semgrepResults.results || [],
      metadata: {
        scanned_at: new Date().toISOString(),
        code_length: code.length,
        semgrep_version: semgrepAvailable.version,
        findings_count: (semgrepResults.results || []).length,
        performance: performanceMetrics  // 🔧 ADD PERFORMANCE DATA
      }
    });
    
  } catch (error) {
    console.error('Code scan error:', error);
    console.error('Stack trace:', error.stack);
    
    // Calculate error response time
    const errorEndTime = performance.now();
    const errorResponseTime = `${(errorEndTime - scanStartTime).toFixed(2)}ms`;
    console.log('🔧 ERROR RESPONSE TIME:', errorResponseTime);
    
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

// 🔧 ENHANCED: File upload scan endpoint with PERFORMANCE MONITORING
app.post('/scan', upload.single('file'), async (req, res) => {
  console.log('=== FILE SCAN REQUEST RECEIVED ===');
  console.log('Headers:', req.headers);
  console.log('Origin:', req.headers.origin);
  
  // 🔧 ADD PERFORMANCE MONITORING
  const scanStartTime = performance.now();
  const memBefore = process.memoryUsage();
  
  try {
    if (!req.file) {
      return res.status(400).json({ 
        status: 'error', 
        message: 'No file uploaded' 
      });
    }

    const filePath = req.file.path;
    console.log('File uploaded to:', filePath);
    console.log('File details:', {
      originalName: req.file.originalname,
      size: req.file.size,
      mimetype: req.file.mimetype
    });

    // Check if Semgrep is available before trying to scan
    const semgrepAvailable = await checkSemgrepAvailability();
    if (!semgrepAvailable.available) {
      // Clean up uploaded file
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
      }
      return res.status(503).json({
        status: 'error',
        message: 'Semgrep is not available',
        details: semgrepAvailable.error
      });
    }

    // Read file content for code extraction
    const fileReadStartTime = performance.now();
    const fileContent = fs.readFileSync(filePath, 'utf8');
    const fileReadEndTime = performance.now();

    // 🔧 MEASURE SEMGREP TIME
    const semgrepStartTime = performance.now();
    const semgrepResults = await runSemgrepScanWithCodeExtraction(filePath, fileContent);
    const semgrepEndTime = performance.now();
    
    // 🔧 FINAL PERFORMANCE METRICS
    const scanEndTime = performance.now();
    const memAfter = process.memoryUsage();
    
    const performanceMetrics = {
      totalScanTime: `${(scanEndTime - scanStartTime).toFixed(2)}ms`,
      fileReadTime: `${(fileReadEndTime - fileReadStartTime).toFixed(2)}ms`,
      semgrepTime: `${(semgrepEndTime - semgrepStartTime).toFixed(2)}ms`,
      memoryUsed: `${Math.round((memAfter.heapUsed - memBefore.heapUsed) / 1024 / 1024)}MB`,
      totalMemory: `${Math.round(memAfter.heapTotal / 1024 / 1024)}MB`
    };
    
    console.log('🔧 PERFORMANCE METRICS:', performanceMetrics);
    
    // Clean up uploaded file
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
      console.log('Cleaned up uploaded file');
    }
    
    res.json({
      status: 'success',
      filename: req.file.originalname,
      findings: semgrepResults.results || [],
      metadata: {
        scanned_at: new Date().toISOString(),
        file_size: req.file.size,
        semgrep_version: semgrepAvailable.version,
        findings_count: (semgrepResults.results || []).length,
        performance: performanceMetrics  // 🔧 ADD PERFORMANCE DATA
      }
    });
    
  } catch (error) {
    console.error('File scan error:', error);
    console.error('Stack trace:', error.stack);
    
    // Clean up uploaded file on error
    if (req.file && req.file.path && fs.existsSync(req.file.path)) {
      try {
        fs.unlinkSync(req.file.path);
        console.log('Cleaned up uploaded file after error');
      } catch (cleanupError) {
        console.error('Error cleaning up file:', cleanupError);
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

// Function to check Semgrep availability
function checkSemgrepAvailability() {
  return new Promise((resolve) => {
    exec('semgrep --version', (error, stdout, stderr) => {
      if (error) {
        console.error('Semgrep not available:', error.message);
        resolve({ 
          available: false, 
          error: error.message,
          stderr: stderr
        });
      } else {
        console.log('Semgrep version:', stdout.trim());
        resolve({ 
          available: true, 
          version: stdout.trim() 
        });
      }
    });
  });
}

// 🔧 ENHANCED: Semgrep scan function with proper code extraction and PERFORMANCE MONITORING
function runSemgrepScanWithCodeExtraction(filePath, originalCode) {
  return new Promise((resolve, reject) => {
    console.log('=== STARTING SEMGREP SCAN WITH CODE EXTRACTION ===');
    console.log('File path:', filePath);
    
    // Verify file exists and has content
    if (!fs.existsSync(filePath)) {
      return reject(new Error('File not found: ' + filePath));
    }
    
    const fileContent = fs.readFileSync(filePath, 'utf8');
    console.log('File content length:', fileContent.length);
    console.log('Original code length:', originalCode.length);
    
    const semgrepArgs = [
      '--json',
      '--config=auto',
      '--skip-unknown-extensions',
      '--timeout=30',
      '--verbose',
      filePath
    ];
    
    console.log('Semgrep command:', 'semgrep', semgrepArgs.join(' '));
    
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
      
      console.log('=== SEMGREP SCAN COMPLETED ===');
      console.log('Exit code:', code);
      console.log('Process time:', `${semgrepProcessTime.toFixed(2)}ms`);
      console.log('Stdout length:', stdout.length);
      console.log('Stderr length:', stderr.length);
      
      if (stderr) {
        console.log('Stderr preview:', stderr.substring(0, 500));
      }
      
      if (code === 0 || code === 1) {
        // Code 0 = no findings, Code 1 = findings found (both are success)
        try {
          const parseStartTime = performance.now();
          const results = stdout ? JSON.parse(stdout) : { results: [] };
          const parseEndTime = performance.now();
          
          console.log('JSON parse time:', `${(parseEndTime - parseStartTime).toFixed(2)}ms`);
          console.log('Parsed results successfully, findings:', results.results?.length || 0);
          
          // 🔧 CRITICAL FIX: Enhance findings with actual code
          if (results.results && results.results.length > 0) {
            const enhancementStartTime = performance.now();
            const codeLines = originalCode.split('\n');
            
            results.results = results.results.map(finding => {
              // Extract the actual vulnerable code line
              const lineNumber = finding.start?.line || 1;
              const vulnerableLine = codeLines[lineNumber - 1] || '';
              
              console.log(`Processing finding at line ${lineNumber}:`, vulnerableLine.substring(0, 100));
              
              // 🔧 COMPLETELY REPLACE the "requires login" placeholder
              finding.extra = finding.extra || {};
              finding.extra.lines = vulnerableLine.trim();
              finding.extra.rendered_text = vulnerableLine.trim();
              finding.extra.original_code = vulnerableLine.trim();
              
              // 🔧 ADD EXTRACTED CODE FIELD FOR FRONTEND
              finding.extractedCode = vulnerableLine.trim();
              
              // Remove any "requires login" placeholders
              if (finding.extra.fingerprint === "requires login") {
                finding.extra.fingerprint = `line-${lineNumber}-${finding.check_id}`;
              }
              
              // Add context lines if available (3 lines before and after)
              const startLine = Math.max(0, lineNumber - 2);
              const endLine = Math.min(codeLines.length, lineNumber + 2);
              const contextLines = codeLines.slice(startLine, endLine);
              finding.extra.context = contextLines.join('\n');
              
              console.log('Enhanced finding:', {
                ruleId: finding.check_id,
                line: lineNumber,
                extractedCode: vulnerableLine.trim(),
                message: finding.message
              });
              
              return finding;
            });
            
            const enhancementEndTime = performance.now();
            console.log('Finding enhancement time:', `${(enhancementEndTime - enhancementStartTime).toFixed(2)}ms`);
          }
          
          // Add performance metadata to results
          results.performance = {
            semgrepProcessTime: `${semgrepProcessTime.toFixed(2)}ms`,
            jsonParseTime: `${(parseEndTime - parseStartTime).toFixed(2)}ms`,
            findingsCount: results.results?.length || 0
          };
          
          resolve(results);
        } catch (parseError) {
          console.error('Failed to parse Semgrep output:', parseError);
          console.error('Raw output preview:', stdout.substring(0, 500));
          resolve({ 
            results: [], 
            raw_output: stdout.substring(0, 1000),
            parse_error: parseError.message 
          });
        }
      } else {
        // Other exit codes indicate errors
        const errorMessage = `Semgrep failed with exit code ${code}: ${stderr}`;
        console.error('Semgrep error:', errorMessage);
        reject(new Error(errorMessage));
      }
    });
    
    semgrepProcess.on('error', (error) => {
      console.error('Semgrep spawn error:', error);
      reject(error);
    });
    
    // Set a timeout to prevent hanging
    const timeout = setTimeout(() => {
      console.error('Semgrep scan timeout');
      semgrepProcess.kill('SIGTERM');
      reject(new Error('Semgrep scan timeout'));
    }, 45000); // 45 second timeout
    
    semgrepProcess.on('close', () => {
      clearTimeout(timeout);
    });
  });
}

// Legacy function for backward compatibility
function runSemgrepScan(filePath) {
  const fileContent = fs.readFileSync(filePath, 'utf8');
  return runSemgrepScanWithCodeExtraction(filePath, fileContent);
}

// Catch-all for undefined routes (this should be last)
app.use('*', (req, res) => {
  console.log('=== 404 REQUEST ===');
  console.log('Path:', req.originalUrl);
  console.log('Method:', req.method);
  console.log('Headers:', req.headers);
  
  res.status(404).json({ 
    status: 'error', 
    message: 'Route not found',
    path: req.originalUrl,
    method: req.method,
    available_routes: [
      'GET /',
      'GET /healthz',
      'GET /semgrep-status', 
      'POST /scan',
      'POST /scan-code'
    ],
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
    timestamp: new Date().toISOString()
  });
});

// Function to start server with proper error handling
function startServer() {
  try {
    const server = app.listen(PORT, '0.0.0.0', () => {
      console.log('=== SERVER STARTED SUCCESSFULLY ===');
      console.log(`Server running on port ${PORT}`);
      console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
      console.log(`Allowed origins: Lovable subdomains + localhost`);
      console.log(`Server listening on: 0.0.0.0:${PORT}`);
      console.log('Server ready to accept connections');
      
      // Log server address info
      const address = server.address();
      console.log('Server address info:', address);
      
      // Check Semgrep availability on startup
      checkSemgrepAvailability()
        .then(result => {
          if (result.available) {
            console.log('✅ Semgrep is available:', result.version);
          } else {
            console.log('❌ Semgrep is not available:', result.error);
          }
        })
        .catch(error => {
          console.error('Error checking Semgrep:', error);
        });
    });
    
    server.on('error', (error) => {
      console.error('=== SERVER ERROR ===');
      console.error('Server error:', error);
      if (error.code === 'EADDRINUSE') {
        console.error(`Port ${PORT} is already in use`);
      }
    });
    
    server.on('connection', (socket) => {
      console.log('New connection established from:', socket.remoteAddress);
    });
    
    // Graceful shutdown handlers
    process.on('SIGTERM', () => {
      console.log('SIGTERM received, shutting down gracefully');
      server.close(() => {
        console.log('Server closed');
        process.exit(0);
      });
    });

    process.on('SIGINT', () => {
      console.log('SIGINT received, shutting down gracefully');
      server.close(() => {
        console.log('Server closed');
        process.exit(0);
      });
    });
    
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
}

// Start the server
startServer();