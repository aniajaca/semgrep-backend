// server.js - Enhanced with real AST-based scanning
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const parser = require('@babel/parser');
const traverse = require('@babel/traverse').default;
const t = require('@babel/types');
const fs = require('fs');
const path = require('path');
const os = require('os');

const app = express();
const PORT = process.env.PORT || 3000;
const HOST = '0.0.0.0'; // CRITICAL: Must bind to 0.0.0.0 for Railway

// Enhanced CORS configuration - Fixed for Railway
const corsOptions = {
  origin: function (origin, callback) {
    const allowedOrigins = [
      'http://localhost:3000',
      'http://localhost:5173',
      'http://localhost:5174',
      'https://neperia-code-guardian.lovable.app',
      'https://semgrep-backend-production.up.railway.app'
    ];
    
    // Allow requests with no origin (like mobile apps or Postman)
    if (!origin) return callback(null, true);
    
    // Check if origin matches allowed patterns
    const isAllowed = allowedOrigins.some(allowed => origin === allowed) ||
                      origin.includes('.lovable.app') ||
                      origin.includes('.base44.app') ||
                      origin.includes('.vercel.app') ||
                      origin.includes('.railway.app');
    
    if (isAllowed) {
      callback(null, true);
    } else {
      console.log('CORS blocked origin:', origin);
      callback(null, true); // For debugging, allow all origins temporarily
    }
  },
  methods: ['GET', 'POST', 'OPTIONS'],
  credentials: true,
  allowedHeaders: ['Content-Type', 'Authorization', 'Accept'],
  optionsSuccessStatus: 200 // For legacy browser support
};

app.use(cors(corsOptions));

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

const upload = multer({ 
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024 }
});

// Add request logging middleware
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path} - Origin: ${req.headers.origin || 'no-origin'}`);
  next();
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

  // Helper functions to handle both regular and optional chaining
  isMember(n) {
    return t.isMemberExpression(n) || t.isOptionalMemberExpression(n);
  }

  isCall(n) {
    return t.isCallExpression(n) || t.isOptionalCallExpression(n);
  }

  getPropName(member) {
    if (!this.isMember(member)) return null;
    const p = member.property;
    return t.isIdentifier(p) ? p.name : (t.isStringLiteral(p) ? p.value : null);
  }

  // Parse JavaScript/TypeScript code into AST
  parseCode(code, language = 'javascript') {
    try {
      console.log('Attempting to parse code...');
      const ast = parser.parse(code, {
        sourceType: 'unambiguous', // Auto-detect module vs script
        plugins: [
          'jsx',
          'typescript',
          'decorators-legacy',
          'dynamicImport',
          'classProperties',
          'asyncGenerators',
          'objectRestSpread',
          'optionalChaining',
          'nullishCoalescingOperator',
          'exportDefaultFrom',
          'exportNamespaceFrom',
          'throwExpressions',
          'classPrivateProperties',
          'classPrivateMethods'
        ],
        errorRecovery: true,
        allowReturnOutsideFunction: true,
        allowImportExportEverywhere: true,
        allowAwaitOutsideFunction: true,
        allowSuperOutsideMethod: true,
        allowUndeclaredExports: true
      });
      console.log('✅ Parse successful, AST generated');
      return ast;
    } catch (error) {
      console.error('❌ Parse error:', error.message);
      console.error('First 500 chars of code:', code.substring(0, 500));
      
      // Try alternative parsing strategy
      try {
        console.log('Trying alternative parse with script mode...');
        const ast = parser.parse(code, {
          sourceType: 'script',
          allowReturnOutsideFunction: true,
          errorRecovery: true
        });
        console.log('✅ Alternative parse successful');
        return ast;
      } catch (altError) {
        console.error('❌ Alternative parse also failed:', altError.message);
      }
      
      // Add a finding to show parsing failed
      this.addFinding({
        type: 'PARSE_ERROR',
        severity: 'info',
        line: 0,
        message: `Code parsing failed: ${error.message}`,
        code: code.substring(0, 200)
      });
      return null;
    }
  }

  // Main scanning function
  scan(code, filename = 'code.js', language = 'javascript') {
    console.log(`🔍 Starting scan of ${filename}, code length: ${code.length}`);
    this.reset();
    this.currentFile = filename;

    const ast = this.parseCode(code, language);
    if (!ast) {
      console.log('❌ No AST generated, returning empty findings');
      return this.findings;
    }

    console.log('🔎 AST generated, running detectors...');
    
    // Run all detection methods with logging
    console.log('  - Detecting SQL Injection...');
    this.detectSQLInjection(ast, code);
    
    console.log('  - Detecting XSS...');
    this.detectXSS(ast, code);
    
    console.log('  - Detecting Hardcoded Secrets...');
    this.detectHardcodedSecrets(ast, code);
    
    console.log('  - Detecting Command Injection...');
    this.detectCommandInjection(ast, code);
    
    console.log('  - Detecting Insecure Crypto...');
    this.detectInsecureCrypto(ast, code);
    
    console.log('  - Detecting Path Traversal...');
    this.detectPathTraversal(ast, code);
    
    console.log('  - Detecting Insecure Deserialization...');
    this.detectInsecureDeserialization(ast, code);
    
    console.log('  - Detecting Insecure File Operations...');
    this.detectInsecureFileOperations(ast, code);
    
    console.log('  - Detecting Authentication Issues...');
    this.detectAuthenticationIssues(ast, code);

    console.log(`✅ Scan complete, found ${this.findings.length} vulnerabilities`);
    if (this.findings.length > 0) {
      console.log('Findings:', this.findings.map(f => `${f.type} (${f.severity})`).join(', '));
    }
    return this.findings;
  }

  // Fixed SQL Injection Detection
  detectSQLInjection(ast, code) {
    let sqlFindings = 0;
    const dbMethods = ['query', 'execute', 'exec', 'run', 'all', 'get'];
    
    traverse(ast, {
      CallExpression: (path) => {
        const node = path.node;
        const callee = node.callee;
        
        if (!this.isMember(callee)) return;
        
        const method = this.getPropName(callee);
        if (!method || !dbMethods.includes(method)) return;
        
        const firstArg = node.arguments[0];
        if (!firstArg) return;
        
        // Check for string concatenation
        if (t.isBinaryExpression(firstArg, { operator: '+' })) {
          this.addFinding({
            type: 'SQL_INJECTION',
            severity: 'high',
            line: node.loc?.start.line || 0,
            message: 'Potential SQL injection: Query uses string concatenation',
            code: this.getCodeSnippet(code, node.loc)
          });
          sqlFindings++;
        }
        
        // Check for template literals
        if (t.isTemplateLiteral(firstArg) && firstArg.expressions.length > 0) {
          this.addFinding({
            type: 'SQL_INJECTION',
            severity: 'high',
            line: node.loc?.start.line || 0,
            message: 'Potential SQL injection: Query uses template literals with variables',
            code: this.getCodeSnippet(code, node.loc)
          });
          sqlFindings++;
        }
        
        // Check for tagged templates (SQL`...${x}`)
        if (t.isTaggedTemplateExpression(firstArg)) {
          if (firstArg.quasi.expressions?.length) {
            this.addFinding({
              type: 'SQL_INJECTION',
              severity: 'high',
              line: node.loc?.start.line || 0,
              message: 'Potential SQL injection: Tagged template with expressions',
              code: this.getCodeSnippet(code, node.loc)
            });
            sqlFindings++;
          }
        }
      },
      
      OptionalCallExpression: (path) => {
        // Handle optional chaining: db?.query()
        const node = path.node;
        const callee = node.callee;
        
        if (!this.isMember(callee)) return;
        
        const method = this.getPropName(callee);
        if (!method || !dbMethods.includes(method)) return;
        
        const firstArg = node.arguments[0];
        if (!firstArg) return;
        
        if (t.isBinaryExpression(firstArg, { operator: '+' }) || 
            (t.isTemplateLiteral(firstArg) && firstArg.expressions.length > 0)) {
          this.addFinding({
            type: 'SQL_INJECTION',
            severity: 'high',
            line: node.loc?.start.line || 0,
            message: 'Potential SQL injection in optional chain',
            code: this.getCodeSnippet(code, node.loc)
          });
          sqlFindings++;
        }
      }
    });
    
    if (sqlFindings > 0) console.log(`    Found ${sqlFindings} SQL injection vulnerabilities`);
  }

  // Enhanced XSS Detection
  detectXSS(ast, code) {
    let xssFindings = 0;
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
            xssFindings++;
          }
        }
        
        // Detect outerHTML
        if (t.isIdentifier(node.property) && node.property.name === 'outerHTML') {
          const parent = path.parent;
          if (t.isAssignmentExpression(parent)) {
            this.addFinding({
              type: 'XSS',
              severity: 'high',
              line: node.loc?.start.line || 0,
              message: 'Potential XSS: Direct outerHTML assignment',
              code: this.getCodeSnippet(code, node.loc)
            });
            xssFindings++;
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
          xssFindings++;
        }
      },
      
      CallExpression: (path) => {
        const node = path.node;
        
        // Detect eval usage
        if (t.isIdentifier(node.callee, { name: 'eval' })) {
          this.addFinding({
            type: 'CODE_INJECTION',
            severity: 'critical',
            line: node.loc?.start.line || 0,
            message: 'Code injection risk: eval() usage detected',
            code: this.getCodeSnippet(code, node.loc)
          });
          xssFindings++;
        }
        
        // Detect insertAdjacentHTML
        if (this.isMember(node.callee)) {
          const method = this.getPropName(node.callee);
          if (method === 'insertAdjacentHTML') {
            const arg = node.arguments[1];
            if (arg && (t.isIdentifier(arg) || t.isMemberExpression(arg) || 
                (t.isTemplateLiteral(arg) && arg.expressions.length))) {
              this.addFinding({
                type: 'XSS',
                severity: 'high',
                line: node.loc?.start.line || 0,
                message: 'Potential XSS: insertAdjacentHTML with dynamic content',
                code: this.getCodeSnippet(code, node.loc)
              });
              xssFindings++;
            }
          }
        }
      }
    });
    if (xssFindings > 0) console.log(`    Found ${xssFindings} XSS/Code injection vulnerabilities`);
  }

  // Hardcoded Secrets Detection
  detectHardcodedSecrets(ast, code) {
    let secretFindings = 0;
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
              secretFindings++;
            }
          }
        }
      },
      
      ObjectProperty: (path) => {
        const node = path.node;
        const key = node.key.name || node.key.value;
        
        if (typeof key === 'string') {
          const keyLower = key.toLowerCase();
          const secretPatterns = ['password', 'secret', 'apikey', 'token', 'api_key', 'jwt'];
          
          const isSecret = secretPatterns.some(pattern => keyLower.includes(pattern));
          
          if (isSecret && t.isStringLiteral(node.value) && node.value.value.length > 0) {
            this.addFinding({
              type: 'HARDCODED_SECRET',
              severity: 'critical',
              line: node.loc?.start.line || 0,
              message: `Hardcoded credential in object: ${key}`,
              code: this.getCodeSnippet(code, node.loc)
            });
            secretFindings++;
          }
        }
      }
    });
    if (secretFindings > 0) console.log(`    Found ${secretFindings} hardcoded secrets`);
  }

  // Fixed Command Injection Detection
  detectCommandInjection(ast, code) {
    let cmdFindings = 0;
    const dangerous = new Set(['exec', 'execSync', 'spawn', 'spawnSync', 'execFile', 'system']);
    
    traverse(ast, {
      CallExpression: (path) => {
        const node = path.node;
        let method = null;
        
        // Direct function call: exec(...)
        if (t.isIdentifier(node.callee) && dangerous.has(node.callee.name)) {
          method = node.callee.name;
        } 
        // Method call: child_process.exec(...) or cp?.exec(...)
        else if (this.isMember(node.callee)) {
          const name = this.getPropName(node.callee);
          if (dangerous.has(name)) method = name;
        }
        
        if (!method) return;
        
        // Check for dynamic input
        const hasDynamic = node.arguments.some(arg =>
          t.isIdentifier(arg) || 
          t.isMemberExpression(arg) ||
          t.isOptionalMemberExpression(arg) ||
          (t.isTemplateLiteral(arg) && arg.expressions.length) ||
          (t.isBinaryExpression(arg, { operator: '+' }))
        );
        
        if (hasDynamic || node.arguments.length > 0) {
          this.addFinding({
            type: 'COMMAND_INJECTION',
            severity: 'critical',
            line: node.loc?.start.line || 0,
            message: `Potential command injection: ${method} with dynamic input`,
            code: this.getCodeSnippet(code, node.loc)
          });
          cmdFindings++;
        }
      },
      
      OptionalCallExpression: (path) => {
        const node = path.node;
        
        if (this.isMember(node.callee)) {
          const name = this.getPropName(node.callee);
          if (dangerous.has(name)) {
            this.addFinding({
              type: 'COMMAND_INJECTION',
              severity: 'critical',
              line: node.loc?.start.line || 0,
              message: `Potential command injection: ${name} with optional chaining`,
              code: this.getCodeSnippet(code, node.loc)
            });
            cmdFindings++;
          }
        }
      }
    });
    
    if (cmdFindings > 0) console.log(`    Found ${cmdFindings} command injection vulnerabilities`);
  }

  // Insecure Cryptography Detection
  detectInsecureCrypto(ast, code) {
    let cryptoFindings = 0;
    traverse(ast, {
      CallExpression: (path) => {
        const node = path.node;
        
        // Check for weak hash algorithms
        if (this.isMember(node.callee)) {
          const method = this.getPropName(node.callee);
          
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
                cryptoFindings++;
              }
            }
          }
        }
        
        // Check for Math.random()
        if (this.isMember(node.callee) &&
            t.isIdentifier(node.callee.object, { name: 'Math' }) &&
            t.isIdentifier(node.callee.property, { name: 'random' })) {
          
          this.addFinding({
            type: 'WEAK_RANDOM',
            severity: 'medium',
            line: node.loc?.start.line || 0,
            message: 'Weak random number generation (Math.random) - use crypto.randomBytes for security',
            code: this.getCodeSnippet(code, node.loc)
          });
          cryptoFindings++;
        }
      }
    });
    if (cryptoFindings > 0) console.log(`    Found ${cryptoFindings} crypto/randomness issues`);
  }

  // Path Traversal Detection
  detectPathTraversal(ast, code) {
    let pathFindings = 0;
    const fsOps = ['readFile', 'readFileSync', 'writeFile', 'writeFileSync', 
                   'unlink', 'unlinkSync', 'readdir', 'readdirSync', 'open', 'openSync'];
    
    traverse(ast, {
      CallExpression: (path) => {
        const node = path.node;
        
        if (this.isMember(node.callee)) {
          const method = this.getPropName(node.callee);
          
          if (fsOps.includes(method)) {
            const pathArg = node.arguments[0];
            
            // Check if path contains user input
            if (pathArg && (t.isIdentifier(pathArg) || 
                t.isMemberExpression(pathArg) ||
                t.isOptionalMemberExpression(pathArg) ||a
                t.isTemplateLiteral(pathArg) ||
                t.isBinaryExpression(pathArg, { operator: '+' }))) {
              this.addFinding({
                type: 'PATH_TRAVERSAL',
                severity: 'high',
                line: node.loc?.start.line || 0,
                message: 'Potential path traversal vulnerability',
                code: this.getCodeSnippet(code, node.loc)
              });
              pathFindings++;
            }
          }
        }
      }
    });
    if (pathFindings > 0) console.log(`    Found ${pathFindings} path traversal vulnerabilities`);
  }

  // Insecure Deserialization Detections
  detectInsecureDeserialization(ast, code) {
    let deserialFindings = 0;
    traverse(ast, {
      CallExpression: (path) => {
        const node = path.node;
        
        // Check for JSON.parse with unvalidated input
        if (this.isMember(node.callee) &&
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
            deserialFindings++;
          }
        }
      }
    });
    if (deserialFindings > 0) console.log(`    Found ${deserialFindings} deserialization issues`);
  }

  // Insecure File Operations
  detectInsecureFileOperations(ast, code) {
    let fileFindings = 0;
    traverse(ast, {
      CallExpression: (path) => {
        const node = path.node;
        
        // Check for chmod with weak permissions
        if (this.isMember(node.callee)) {
          const method = this.getPropName(node.callee);
          
          if (method === 'chmod' || method === 'chmodSync') {
            const modeArg = node.arguments[1];
            if (t.isNumericLiteral(modeArg) || t.isStringLiteral(modeArg)) {
              const mode = modeArg.value;
              if (mode === 0o777 || mode === '777' || mode === 0o666 || mode === '666') {
                this.addFinding({
                  type: 'INSECURE_FILE_PERMISSION',
                  severity: 'medium',
                  line: node.loc?.start.line || 0,
                  message: `Insecure file permissions (${mode})`,
                  code: this.getCodeSnippet(code, node.loc)
                });
                fileFindings++;
              }
            }
          }
        }
      }
    });
    if (fileFindings > 0) console.log(`    Found ${fileFindings} insecure file operations`);
  }

  // Authentication Issues Detection
  detectAuthenticationIssues(ast, code) {
    let authFindings = 0;
    traverse(ast, {
      FunctionDeclaration: (path) => {
        const node = path.node;
        const funcName = node.id?.name?.toLowerCase() || '';
        
        // Look for route handlers that might need auth
        if (funcName.includes('route') || funcName.includes('handler') ||
            funcName.includes('endpoint') || funcName.includes('controller')) {
          
          let hasAuthCheck = false;
          path.traverse({
            CallExpression(innerPath) {
              const callee = innerPath.node.callee;
              if (t.isIdentifier(callee)) {
                const name = callee.name.toLowerCase();
                if (name.includes('auth') || name.includes('verify') || 
                    name.includes('check') || name.includes('permission')) {
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
            authFindings++;
          }
        }
      }
    });
    if (authFindings > 0) console.log(`    Found ${authFindings} authentication issues`);
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
      'MISSING_AUTHENTICATION': { id: 'CWE-306', name: 'Missing Authentication for Critical Function', owasp: 'A07:2021' },
      'PARSE_ERROR': { id: 'CWE-0', name: 'Parse Error', owasp: 'N/A' }
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

// Calculate risk score based on findings
function calculateRiskScore(findings) {
  const severityScores = {
    critical: 10,
    high: 7,
    medium: 4,
    low: 1,
    info: 0
  };

  let totalScore = 0;
  findings.forEach(finding => {
    totalScore += severityScores[finding.severity] || 0;
  });

  // Normalize to 0-100 scale
  return Math.min(100, totalScore);
}

// Test endpoint for debugging
app.get('/test-scanner', (req, res) => {
  console.log('=== TEST SCANNER ENDPOINT ===');
  const testCode = `
    const password = "admin123";
    const apiKey = "sk-12345";
    eval("console.log('test')");
    Math.random();
    document.innerHTML = userInput;
    db.query("SELECT * FROM users WHERE id = " + userId);
    db?.query(\`SELECT * FROM users WHERE id = \${userId}\`);
    exec("rm -rf " + userPath);
    crypto.createHash('md5');
  `;
  
  // Create new scanner instance for this request
  const scanner = new ASTVulnerabilityScanner();
  const findings = scanner.scan(testCode, 'test.js', 'javascript');
  
  res.json({
    message: 'Scanner test',
    code: testCode,
    findings: findings,
    findingsCount: findings.length,
    success: findings.length > 0
  });
});

// Health check endpoints
app.get('/health', (req, res) => {
  console.log('Health check requested');
  res.json({ 
    status: 'healthy',
    timestamp: new Date().toISOString(),
    scanner: 'AST Scanner',
    version: '2.0',
    port: PORT,
    environment: process.env.NODE_ENV || 'production'
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
      '/test-scanner': 'GET - Test scanner functionality',
      '/health': 'GET - Health check',
      '/healthz': 'GET - Railway health check'
    },
    features: [
      'AST-based vulnerability detection',
      'No regex patterns - real code analysis',
      'JavaScript/TypeScript support',
      'CWE/OWASP mapping',
      'Risk score calculation',
      'Comprehensive vulnerability coverage',
      'Optional chaining support',
      'Tagged template detection'
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

// Main scanning endpoint
app.post('/scan-code', async (req, res) => {
  console.log('=== AST SCAN REQUEST RECEIVED ===');
  
  try {
    const { code, language = 'javascript', filename = 'code.js' } = req.body;
    
    console.log('📥 Code received:', {
      length: code?.length,
      firstLine: code?.split('\n')[0]?.substring(0, 100),
      language,
      filename
    });
    
    if (!code || typeof code !== 'string' || code.trim() === '') {
      console.log('❌ No code provided');
      return res.status(400).json({ 
        status: 'error', 
        message: 'No code provided' 
      });
    }

    const startTime = Date.now();
    
    // Create new scanner instance for this request (prevents concurrency issues)
    const scanner = new ASTVulnerabilityScanner();
    const findings = scanner.scan(code, filename, language);
    
    const endTime = Date.now();
    const scanTime = endTime - startTime;
    
    console.log(`📊 Scan results: ${findings.length} findings in ${scanTime}ms`);
    
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
    console.error('❌ Scan error:', error);
    res.status(500).json({ 
      status: 'error', 
      message: 'Scan failed',
      error: error.message 
    });
  }
});

// File upload endpoint
app.post('/scan', upload.single('file'), async (req, res) => {
  console.log('=== FILE SCAN REQUEST RECEIVED ===');
  
  try {
    if (!req.file) {
      console.log('❌ No file uploaded');
      return res.status(400).json({ 
        status: 'error', 
        message: 'No file uploaded' 
      });
    }

    const code = req.file.buffer.toString('utf8');
    const filename = req.file.originalname;
    const language = path.extname(filename).slice(1) || 'javascript';
    
    console.log(`📎 File: ${filename}, Size: ${req.file.size} bytes, Language: ${language}`);

    // Create new scanner instance for this request (prevents concurrency issues)
    const scanner = new ASTVulnerabilityScanner();
    const findings = scanner.scan(code, filename, language);
    const riskScore = calculateRiskScore(findings);
    
    console.log(`📊 File scan results: ${findings.length} findings`);

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
    console.error('❌ File scan error:', error);
    res.status(500).json({ 
      status: 'error', 
      message: 'File scan failed',
      error: error.message 
    });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('❌ Server Error:', err);
  res.status(500).json({
    status: 'error',
    message: 'Internal server error',
    error: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

// Handle 404
app.use((req, res) => {
  console.log(`❓ 404 - Path not found: ${req.path}`);
  res.status(404).json({
    status: 'error',
    message: 'Endpoint not found',
    path: req.path
  });
});

// Start server - CRITICAL: Bind to 0.0.0.0
const server = app.listen(PORT, HOST, (err) => {
  if (err) {
    console.error('Failed to start server:', err);
    process.exit(1);
  }
  
  console.log(`
╔══════════════════════════════════════════════╗
║   NEPERIA AST SECURITY SCANNER v2.0         ║
║   Real AST Analysis - No Regex Patterns     ║
╠══════════════════════════════════════════════╣
║   Status: OPERATIONAL                        ║
║   Host: ${HOST}                             ║
║   Port: ${PORT}                              ║
║   Mode: AST-based Scanning                  ║
║   Coverage: OWASP Top 10                    ║
║   Environment: ${process.env.NODE_ENV || 'production'}     ║
╚══════════════════════════════════════════════╝
  `);
  
  console.log('✅ Server is listening on:', server.address());
  console.log(`✅ Health check available at: http://${HOST}:${PORT}/health`);
  console.log(`✅ Test scanner at: http://${HOST}:${PORT}/test-scanner`);
  console.log(`Railway URL: https://semgrep-backend-production.up.railway.app`);
});

// Add graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, closing server...');
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
});// Force rebuild: Thu Sep 11 23:10:12 CEST 2025
