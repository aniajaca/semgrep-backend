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

// Custom CORS middleware - Railway compatible
const customCors = (req, res, next) => {
  try {
    const allowedOrigins = [
      process.env.ALLOWED_ORIGIN,
      'http://localhost:3000',
      'http://localhost:5173',
      'https://preview--neperia-code-guardian.lovable.app',
      'https://healthcheck.railway.app'  // Railway health check hostname
    ].filter(Boolean);

    const origin = req.headers.origin;
    
    // For Railway health checks, they might not send an origin header
    if (!origin && req.get('User-Agent')?.includes('Railway')) {
      res.setHeader('Access-Control-Allow-Origin', '*');
    } else if (allowedOrigins.includes(origin)) {
      res.setHeader('Access-Control-Allow-Origin', origin);
    } else if (allowedOrigins.length === 0) {
      res.setHeader('Access-Control-Allow-Origin', '*');
    }
    
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    
    if (req.method === 'OPTIONS') {
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

// Apply CORS middleware
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

// Root route - handles Railway health checks
app.get('/', (req, res) => {
  try {
    console.log('=== ROOT REQUEST ===');
    console.log('Headers:', req.headers);
    console.log('IP:', req.ip);
    console.log('User Agent:', req.get('User-Agent'));
    
    res.status(200).json({ 
      status: 'success', 
      message: 'Cybersecurity Scanner API is running',
      version: '1.0.0',
      environment: process.env.NODE_ENV || 'development',
      timestamp: new Date().toISOString(),
      endpoints: {
        'GET /': 'Root endpoint',
        'GET /healthz': 'Health check',
        'GET /semgrep-status': 'Check Semgrep availability',
        'GET /api': 'API information',
        'POST /scan': 'File scanning endpoint'
      }
    });
  } catch (error) {
    console.error('Error in root route:', error);
    res.status(500).json({ status: 'error', message: 'Internal server error' });
  }
});

// Health check endpoint - Railway compatible
app.get('/healthz', (req, res) => {
  try {
    console.log('=== HEALTH CHECK REQUEST ===');
    console.log('Request headers:', req.headers);
    console.log('Request IP:', req.ip);
    console.log('User Agent:', req.get('User-Agent'));
    
    res.status(200).json({ 
      status: 'healthy',
      service: 'semgrep-backend',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      port: PORT,
      environment: process.env.NODE_ENV,
      memory: process.memoryUsage()
    });
  } catch (error) {
    console.error('Health check failed:', error);
    res.status(503).json({ 
      status: 'unhealthy',
      error: error.message,
      timestamp: new Date().toISOString()
    });
  }
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
      environment: process.env.NODE_ENV
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
        'GET /semgrep-status': 'Check Semgrep availability',
        'GET /debug': 'Debug information',
        'POST /scan': 'File scanning endpoint'
      },
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Error in API info route:', error);
    res.status(500).json({ status: 'error', message: 'Internal server error' });
  }
});

// Scan endpoint
app.post('/scan', upload.single('file'), async (req, res) => {
  console.log('=== SCAN REQUEST RECEIVED ===');
  console.log('Headers:', req.headers);
  console.log('Origin:', req.headers.origin);
  
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

    // Run Semgrep scan
    const semgrepResults = await runSemgrepScan(filePath);
    
    // Clean up uploaded file
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
      console.log('Cleaned up uploaded file');
    }
    
    res.json({
      status: 'success',
      filename: req.file.originalname,
      results: semgrepResults,
      timestamp: new Date().toISOString()
    });
    
  } catch (error) {
    console.error('Scan error:', error);
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
      message: 'Scan failed',
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

// Function to run Semgrep scan
function runSemgrepScan(filePath) {
  return new Promise((resolve, reject) => {
    console.log('=== STARTING SEMGREP SCAN ===');
    console.log('File path:', filePath);
    
    // Verify file exists
    if (!fs.existsSync(filePath)) {
      return reject(new Error('File not found: ' + filePath));
    }
    
    const semgrepArgs = [
      '--json',
      '--config=auto',
      filePath
    ];
    
    console.log('Semgrep command:', 'semgrep', semgrepArgs.join(' '));
    
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
      console.log('=== SEMGREP SCAN COMPLETED ===');
      console.log('Exit code:', code);
      console.log('Stdout length:', stdout.length);
      console.log('Stderr length:', stderr.length);
      
      if (stderr) {
        console.log('Stderr preview:', stderr.substring(0, 500));
      }
      
      if (code === 0 || code === 1) {
        // Code 0 = no findings, Code 1 = findings found (both are success)
        try {
          const results = stdout ? JSON.parse(stdout) : { results: [] };
          console.log('Parsed results successfully, findings:', results.results?.length || 0);
          resolve(results);
        } catch (parseError) {
          console.error('Failed to parse Semgrep output:', parseError);
          console.error('Raw output preview:', stdout.substring(0, 500));
          resolve({ 
            results: [], 
            raw_output: stdout.substring(0, 1000), // Limit output size
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
    }, 60000); // 60 second timeout
    
    semgrepProcess.on('close', () => {
      clearTimeout(timeout);
    });
  });
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
      console.log(`Allowed origins: ${process.env.ALLOWED_ORIGIN || 'not set'}`);
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