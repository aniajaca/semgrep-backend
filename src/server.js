// server.js - Enhanced with real AST-based scanning
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const { Parser } = require('@babel/parser');
const traverse = require('@babel/traverse').default;
const t = require('@babel/types');
const fs = require('fs');
const path = require('path');
const os = require('os');

const app = express();
const PORT = process.env.PORT || 3000;

// Enhanced CORS configuration
app.use(cors({
  origin: [
    'http://localhost:3000',
    'http://localhost:5173',
    'http://localhost:5174',
    'https://*.lovable.app',
    'https://*.base44.app',
    'https://*.vercel.app',
    'https://*.railway.app'
  ],
  methods: ['GET', 'POST', 'OPTIONS'],
  credentials: true,
  allowedHeaders: ['Content-Type', 'Authorization', 'Accept']
}));

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

const upload = multer({ 
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024 }
});

// AST-based vulnerability scanner
class ASTVulnerabilityScanner {
  constructor() {
    this.findings = [];
    this.currentFile = '';
  }

  reset() {
    this.findings = [];
    this.currentFile = '';
  }

  // Parse JavaScript/TypeScript code into AST
  parseCode(code, language = 'javascript') {
    try {
      const ast = Parser.parse(code, {
        sourceType: 'module',
        plugins: [
          'jsx',
          'typescript',
          'decorators-legacy',
          'dynamicImport',
          'classProperties',
          'asyncGenerators'
        ],
        errorRecovery: true
      });
      return ast;
    } catch (error) {
      console.error('Parse error:', error);
      return null;
    }
  }

  // Main scanning function
  scan(code, filename = 'code.js', language = 'javascript') {
    this.reset();
    this.currentFile = filename;

    const ast = this.parseCode(code, language);
    if (!ast) {
      return this.findings;
    }

    // Run all detection methods
    this.detectSQLInjection(ast, code);
    this.detectXSS(ast, code);
    this.detectHardcodedSecrets(ast, code);
    this.detectCommandInjection(ast, code);
    this.detectInsecureCrypto(ast, code);
    this.detectPathTraversal(ast, code);
    this.detectInsecureDeserialization(ast, code);
    this.detectWeakRandomness(ast, code);
    this.detectInsecureFileOperations(ast, code);
    this.detectAuthenticationIssues(ast, code);

    return this.findings;
  }

  // SQL Injection Detection
  detectSQLInjection(ast, code) {
    traverse(ast, {
      CallExpression: (path) => {
        const node = path.node;
        
        // Check for database query methods
        const dbMethods = ['query', 'execute', 'exec', 'run', 'all', 'get'];
        const callee = node.callee;
        
        if (t.isMemberExpression(callee) && 
            dbMethods.includes(callee.property.name)) {
          
          // Check if query uses string concatenation or template literals with variables
          const firstArg = node.arguments[0];
          
          if (firstArg) {
            // Check for binary expression (string concatenation)
            if (t.isBinaryExpression(firstArg) && firstArg.operator === '+') {
              this.addFinding({
                type: 'SQL_INJECTION',
                severity: 'high',
                line: node.loc?.start.line || 0,
                message: 'Potential SQL injection: Query uses string concatenation',
                code: this.getCodeSnippet(code, node.loc)
              });
            }
            
            // Check for template literals with expressions
            if (t.isTemplateLiteral(firstArg) && firstArg.expressions.length > 0) {
              let hasUserInput = false;
              firstArg.expressions.forEach(expr => {
                if (t.isIdentifier(expr) || t.isMemberExpression(expr)) {
                  hasUserInput = true;
                }
              });
              
              if (hasUserInput) {
                this.addFinding({
                  type: 'SQL_INJECTION',
                  severity: 'high',
                  line: node.loc?.start.line || 0,
                  message: 'Potential SQL injection: Query uses template literals with variables',
                  code: this.getCodeSnippet(code, node.loc)
                });
              }
            }
          }
        }
      }
    });
  }

  // XSS Detection
  detectXSS(ast, code) {
    traverse(ast, {
      MemberExpression: (path) => {
        const node = path.node;
        
        // Detect innerHTML usage
        if (t.isIdentifier(node.property) && node.property.name === 'innerHTML') {
          const parent = path.parent;
          if (t.isAssignmentExpression(parent)) {
            this.addFinding({
              type: 'XSS',
              severity: 'high',
              line: node.loc?.start.line || 0,
              message: 'Potential XSS: Direct innerHTML assignment',
              code: this.getCodeSnippet(code, node.loc)
            });
          }
        }
        
        // Detect document.write
        if (t.isIdentifier(node.object, { name: 'document' }) &&
            t.isIdentifier(node.property, { name: 'write' })) {
          this.addFinding({
            type: 'XSS',
            severity: 'high',
            line: node.loc?.start.line || 0,
            message: 'Potential XSS: document.write usage',
            code: this.getCodeSnippet(code, node.loc)
          });
        }
      },
      
      // Detect eval usage
      CallExpression: (path) => {
        const node = path.node;
        if (t.isIdentifier(node.callee, { name: 'eval' })) {
          this.addFinding({
            type: 'CODE_INJECTION',
            severity: 'critical',
            line: node.loc?.start.line || 0,
            message: 'Code injection risk: eval() usage detected',
            code: this.getCodeSnippet(code, node.loc)
          });
        }
      }
    });
  }

  // Hardcoded Secrets Detection
  detectHardcodedSecrets(ast, code) {
    traverse(ast, {
      VariableDeclarator: (path) => {
        const node = path.node;
        
        if (t.isIdentifier(node.id)) {
          const varName = node.id.name.toLowerCase();
          const secretPatterns = [
            'password', 'passwd', 'pwd', 'secret', 'apikey', 
            'api_key', 'token', 'auth', 'credential', 'private'
          ];
          
          // Check if variable name suggests it's a secret
          const isSecret = secretPatterns.some(pattern => varName.includes(pattern));
          
          if (isSecret && node.init) {
            // Check if it's a string literal (hardcoded)
            if (t.isStringLiteral(node.init) && node.init.value.length > 0) {
              this.addFinding({
                type: 'HARDCODED_SECRET',
                severity: 'critical',
                line: node.loc?.start.line || 0,
                message: `Hardcoded credential detected: ${node.id.name}`,
                code: this.getCodeSnippet(code, node.loc)
              });
            }
          }
        }
      },
      
      ObjectProperty: (path) => {
        const node = path.node;
        const key = node.key.name || node.key.value;
        
        if (typeof key === 'string') {
          const keyLower = key.toLowerCase();
          const secretPatterns = ['password', 'secret', 'apikey', 'token'];
          
          const isSecret = secretPatterns.some(pattern => keyLower.includes(pattern));
          
          if (isSecret && t.isStringLiteral(node.value) && node.value.value.length > 0) {
            this.addFinding({
              type: 'HARDCODED_SECRET',
              severity: 'critical',
              line: node.loc?.start.line || 0,
              message: `Hardcoded credential in object: ${key}`,
              code: this.getCodeSnippet(code, node.loc)
            });
          }
        }
      }
    });
  }

  // Command Injection Detection
  detectCommandInjection(ast, code) {
    traverse(ast, {
      CallExpression: (path) => {
        const node = path.node;
        
        // Check for dangerous functions
        const dangerousFuncs = ['exec', 'execSync', 'spawn', 'spawnSync', 'execFile'];
        
        if (t.isMemberExpression(node.callee)) {
          const method = node.callee.property.name;
          if (dangerousFuncs.includes(method)) {
            // Check if arguments contain variables (potential user input)
            const hasVariable = node.arguments.some(arg => 
              t.isIdentifier(arg) || 
              t.isMemberExpression(arg) ||
              (t.isTemplateLiteral(arg) && arg.expressions.length > 0)
            );
            
            if (hasVariable) {
              this.addFinding({
                type: 'COMMAND_INJECTION',
                severity: 'critical',
                line: node.loc?.start.line || 0,
                message: `Potential command injection: ${method} with variable input`,
                code: this.getCodeSnippet(code, node.loc)
              });
            }
          }
        }
      }
    });
  }

  // Insecure Cryptography Detection
  detectInsecureCrypto(ast, code) {
    traverse(ast, {
      CallExpression: (path) => {
        const node = path.node;
        
        // Check for weak hash algorithms
        if (t.isMemberExpression(node.callee)) {
          const method = node.callee.property.name;
          
          if (method === 'createHash') {
            const firstArg = node.arguments[0];
            if (t.isStringLiteral(firstArg)) {
              const algorithm = firstArg.value.toLowerCase();
              const weakAlgos = ['md5', 'sha1', 'md4', 'ripemd160'];
              
              if (weakAlgos.includes(algorithm)) {
                this.addFinding({
                  type: 'WEAK_CRYPTO',
                  severity: 'high',
                  line: node.loc?.start.line || 0,
                  message: `Weak cryptographic algorithm: ${algorithm}`,
                  code: this.getCodeSnippet(code, node.loc)
                });
              }
            }
          }
        }
        
        // Check for Math.random() in security context
        if (t.isMemberExpression(node.callee) &&
            t.isIdentifier(node.callee.object, { name: 'Math' }) &&
            t.isIdentifier(node.callee.property, { name: 'random' })) {
          
          // Check if it's being used for token/id generation
          const parent = path.getFunctionParent();
          if (parent) {
            const funcName = parent.node.id?.name?.toLowerCase() || '';
            if (funcName.includes('token') || funcName.includes('id') || 
                funcName.includes('key') || funcName.includes('password')) {
              this.addFinding({
                type: 'WEAK_RANDOM',
                severity: 'medium',
                line: node.loc?.start.line || 0,
                message: 'Weak random number generation for security-sensitive operation',
                code: this.getCodeSnippet(code, node.loc)
              });
            }
          }
        }
      }
    });
  }

  // Path Traversal Detection
  detectPathTraversal(ast, code) {
    traverse(ast, {
      CallExpression: (path) => {
        const node = path.node;
        const fsOps = ['readFile', 'readFileSync', 'writeFile', 'writeFileSync', 
                       'unlink', 'unlinkSync', 'readdir', 'readdirSync'];
        
        if (t.isMemberExpression(node.callee)) {
          const method = node.callee.property.name;
          
          if (fsOps.includes(method)) {
            const pathArg = node.arguments[0];
            
            // Check if path contains user input
            if (pathArg && (t.isIdentifier(pathArg) || 
                t.isMemberExpression(pathArg) ||
                t.isTemplateLiteral(pathArg))) {
              this.addFinding({
                type: 'PATH_TRAVERSAL',
                severity: 'high',
                line: node.loc?.start.line || 0,
                message: 'Potential path traversal vulnerability',
                code: this.getCodeSnippet(code, node.loc)
              });
            }
          }
        }
      }
    });
  }

  // Insecure Deserialization Detection
  detectInsecureDeserialization(ast, code) {
    traverse(ast, {
      CallExpression: (path) => {
        const node = path.node;
        
        // Check for JSON.parse with unvalidated input
        if (t.isMemberExpression(node.callee) &&
            t.isIdentifier(node.callee.object, { name: 'JSON' }) &&
            t.isIdentifier(node.callee.property, { name: 'parse' })) {
          
          const arg = node.arguments[0];
          if (arg && (t.isIdentifier(arg) || t.isMemberExpression(arg))) {
            this.addFinding({
              type: 'INSECURE_DESERIALIZATION',
              severity: 'medium',
              line: node.loc?.start.line || 0,
              message: 'Potential insecure deserialization of untrusted data',
              code: this.getCodeSnippet(code, node.loc)
            });
          }
        }
      }
    });
  }

  // Weak Randomness Detection
  detectWeakRandomness(ast, code) {
    traverse(ast, {
      CallExpression: (path) => {
        const node = path.node;
        
        if (t.isMemberExpression(node.callee) &&
            t.isIdentifier(node.callee.object, { name: 'Math' }) &&
            t.isIdentifier(node.callee.property, { name: 'random' })) {
          
          this.addFinding({
            type: 'WEAK_RANDOM',
            severity: 'medium',
            line: node.loc?.start.line || 0,
            message: 'Use of Math.random() for potentially security-sensitive operation',
            code: this.getCodeSnippet(code, node.loc)
          });
        }
      }
    });
  }

  // Insecure File Operations
  detectInsecureFileOperations(ast, code) {
    traverse(ast, {
      CallExpression: (path) => {
        const node = path.node;
        
        // Check for chmod with weak permissions
        if (t.isMemberExpression(node.callee) &&
            node.callee.property.name === 'chmod') {
          
          const modeArg = node.arguments[1];
          if (t.isNumericLiteral(modeArg) || t.isStringLiteral(modeArg)) {
            const mode = modeArg.value;
            if (mode === 0o777 || mode === '777') {
              this.addFinding({
                type: 'INSECURE_FILE_PERMISSION',
                severity: 'medium',
                line: node.loc?.start.line || 0,
                message: 'Insecure file permissions (777)',
                code: this.getCodeSnippet(code, node.loc)
              });
            }
          }
        }
      }
    });
  }

  // Authentication Issues Detection
  detectAuthenticationIssues(ast, code) {
    traverse(ast, {
      // Check for missing authentication checks
      FunctionDeclaration: (path) => {
        const node = path.node;
        const funcName = node.id?.name?.toLowerCase() || '';
        
        // Look for route handlers that might need auth
        if (funcName.includes('route') || funcName.includes('handler') ||
            funcName.includes('endpoint')) {
          
          let hasAuthCheck = false;
          path.traverse({
            CallExpression(innerPath) {
              const callee = innerPath.node.callee;
              if (t.isIdentifier(callee)) {
                const name = callee.name.toLowerCase();
                if (name.includes('auth') || name.includes('verify') || 
                    name.includes('check')) {
                  hasAuthCheck = true;
                }
              }
            }
          });
          
          if (!hasAuthCheck) {
            this.addFinding({
              type: 'MISSING_AUTHENTICATION',
              severity: 'medium',
              line: node.loc?.start.line || 0,
              message: 'Potentially missing authentication check in route handler',
              code: this.getCodeSnippet(code, node.loc)
            });
          }
        }
      }
    });
  }

  // Helper function to get code snippet
  getCodeSnippet(code, loc) {
    if (!loc) return '';
    
    const lines = code.split('\n');
    const startLine = Math.max(0, loc.start.line - 2);
    const endLine = Math.min(lines.length, loc.end.line + 1);
    
    return lines.slice(startLine, endLine).join('\n');
  }

  // Add finding with CWE and OWASP mapping
  addFinding(finding) {
    const cweMapping = {
      'SQL_INJECTION': { id: 'CWE-89', name: 'SQL Injection', owasp: 'A03:2021' },
      'XSS': { id: 'CWE-79', name: 'Cross-site Scripting', owasp: 'A03:2021' },
      'HARDCODED_SECRET': { id: 'CWE-798', name: 'Use of Hard-coded Credentials', owasp: 'A07:2021' },
      'COMMAND_INJECTION': { id: 'CWE-78', name: 'OS Command Injection', owasp: 'A03:2021' },
      'CODE_INJECTION': { id: 'CWE-94', name: 'Code Injection', owasp: 'A03:2021' },
      'WEAK_CRYPTO': { id: 'CWE-327', name: 'Use of Broken or Risky Cryptographic Algorithm', owasp: 'A02:2021' },
      'WEAK_RANDOM': { id: 'CWE-330', name: 'Use of Insufficiently Random Values', owasp: 'A02:2021' },
      'PATH_TRAVERSAL': { id: 'CWE-22', name: 'Path Traversal', owasp: 'A01:2021' },
      'INSECURE_DESERIALIZATION': { id: 'CWE-502', name: 'Deserialization of Untrusted Data', owasp: 'A08:2021' },
      'INSECURE_FILE_PERMISSION': { id: 'CWE-732', name: 'Incorrect Permission Assignment', owasp: 'A01:2021' },
      'MISSING_AUTHENTICATION': { id: 'CWE-306', name: 'Missing Authentication for Critical Function', owasp: 'A07:2021' }
    };

    const cwe = cweMapping[finding.type] || { id: 'CWE-Unknown', name: finding.type, owasp: 'Unknown' };
    
    this.findings.push({
      ...finding,
      cwe: cwe,
      owasp: cwe.owasp,
      file: this.currentFile,
      timestamp: new Date().toISOString()
    });
  }
}

// Create scanner instance
const scanner = new ASTVulnerabilityScanner();

// Calculate risk score based on findings
function calculateRiskScore(findings) {
  const severityScores = {
    critical: 10,
    high: 7,
    medium: 4,
    low: 1
  };

  let totalScore = 0;
  findings.forEach(finding => {
    totalScore += severityScores[finding.severity] || 0;
  });

  // Normalize to 0-100 scale
  return Math.min(100, totalScore);
}

// Main scanning endpoint
app.post('/scan-code', async (req, res) => {
  console.log('=== AST SCAN REQUEST RECEIVED ===');
  
  try {
    const { code, language = 'javascript', filename = 'code.js' } = req.body;
    
    if (!code || typeof code !== 'string' || code.trim() === '') {
      return res.status(400).json({ 
        status: 'error', 
        message: 'No code provided' 
      });
    }

    const startTime = Date.now();
    
    // Perform AST-based scanning
    const findings = scanner.scan(code, filename, language);
    
    const endTime = Date.now();
    const scanTime = endTime - startTime;
    
    // Calculate risk score
    const riskScore = calculateRiskScore(findings);
    
    res.json({
      status: 'success',
      language: language,
      findings: findings,
      riskScore: riskScore,
      metadata: {
        scanned_at: new Date().toISOString(),
        code_length: code.length,
        findings_count: findings.length,
        scan_time_ms: scanTime,
        scanner: 'AST-based Scanner v2.0'
      },
      riskAssessment: {
        riskScore: riskScore,
        riskLevel: riskScore > 70 ? 'Critical' : 
                   riskScore > 40 ? 'High' : 
                   riskScore > 20 ? 'Medium' : 
                   riskScore > 0 ? 'Low' : 'Minimal',
        criticalFindings: findings.filter(f => f.severity === 'critical').length,
        highFindings: findings.filter(f => f.severity === 'high').length,
        mediumFindings: findings.filter(f => f.severity === 'medium').length,
        lowFindings: findings.filter(f => f.severity === 'low').length
      }
    });
    
  } catch (error) {
    console.error('Scan error:', error);
    res.status(500).json({ 
      status: 'error', 
      message: 'Scan failed',
      error: error.message 
    });
  }
});

// File upload endpoint
app.post('/scan', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ 
        status: 'error', 
        message: 'No file uploaded' 
      });
    }

    const code = req.file.buffer.toString('utf8');
    const filename = req.file.originalname;
    const language = path.extname(filename).slice(1) || 'javascript';

    const findings = scanner.scan(code, filename, language);
    const riskScore = calculateRiskScore(findings);

    res.json({
      status: 'success',
      filename: filename,
      language: language,
      findings: findings,
      riskScore: riskScore,
      metadata: {
        scanned_at: new Date().toISOString(),
        file_size: req.file.size,
        findings_count: findings.length
      }
    });

  } catch (error) {
    console.error('File scan error:', error);
    res.status(500).json({ 
      status: 'error', 
      message: 'File scan failed',
      error: error.message 
    });
  }
});

// Health check endpoints
app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy',
    timestamp: new Date().toISOString(),
    scanner: 'AST Scanner',
    version: '2.0'
  });
});

app.get('/healthz', (req, res) => {
  res.status(200).send('OK');
});

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    name: 'Neperia AST Security Scanner',
    version: '2.0',
    status: 'operational',
    endpoints: {
      '/scan-code': 'POST - Scan code for vulnerabilities using AST',
      '/scan': 'POST - Upload file for scanning',
      '/health': 'GET - Health check',
      '/healthz': 'GET - Railway health check'
    },
    features: [
      'AST-based vulnerability detection',
      'No regex patterns - real code analysis',
      'JavaScript/TypeScript support',
      'CWE/OWASP mapping',
      'Risk score calculation',
      'Comprehensive vulnerability coverage'
    ],
    vulnerabilities_detected: [
      'SQL Injection (CWE-89)',
      'XSS (CWE-79)',
      'Hardcoded Credentials (CWE-798)',
      'Command Injection (CWE-78)',
      'Code Injection (CWE-94)',
      'Weak Cryptography (CWE-327)',
      'Path Traversal (CWE-22)',
      'Insecure Deserialization (CWE-502)',
      'Authentication Issues (CWE-306)'
    ]
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`
╔══════════════════════════════════════════════╗
║   NEPERIA AST SECURITY SCANNER v2.0         ║
║   Real AST Analysis - No Regex Patterns     ║
╠══════════════════════════════════════════════╣
║   Status: OPERATIONAL                        ║
║   Port: ${PORT}                                  ║
║   Mode: AST-based Scanning                  ║
║   Coverage: OWASP Top 10                    ║
╚══════════════════════════════════════════════╝
  `);
});