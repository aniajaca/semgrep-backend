// ==============================================================================
// src/contextInference/detectors/jsDetector.js
// ==============================================================================

const Parser = require('@babel/parser');
const traverse = require('@babel/traverse').default;

class JSContextDetector {
  constructor(config = {}) {
    this.config = config;
  }

  /**
   * Detect if finding is in a route handler
   */
  async detectRoutes(fileContent, finding) {
    const evidence = [];
    let confidence = 0;
    
    try {
      // Try AST parsing first
      const ast = Parser.parse(fileContent, {
        sourceType: 'module',
        plugins: ['jsx', 'typescript'],
        errorRecovery: true
      });
      
      let routeFound = false;
      
      traverse(ast, {
        CallExpression(path) {
          const node = path.node;
          
          // Express/Koa style routes
          if (node.callee.type === 'MemberExpression') {
            const object = node.callee.object.name;
            const method = node.callee.property.name;
            
            if ((object === 'app' || object === 'router') && 
                ['get', 'post', 'put', 'delete', 'patch', 'use'].includes(method)) {
              routeFound = true;
              evidence.push(`Found route: ${object}.${method}()`);
            }
          }
          
          // NestJS decorators
          if (node.callee.name && ['Get', 'Post', 'Put', 'Delete', 'Controller'].includes(node.callee.name)) {
            routeFound = true;
            evidence.push(`Found NestJS decorator: @${node.callee.name}`);
          }
        }
      });
      
      if (routeFound) {
        confidence = 0.9; // High confidence with AST
      }
      
    } catch (error) {
      // Fallback to regex
      const patterns = [
        /app\.(get|post|put|delete|patch)\s*\(/gi,
        /router\.(get|post|put|delete|patch)\s*\(/gi,
        /@(Get|Post|Put|Delete|Controller)\s*\(/gi,
        /fastify\.(get|post|put|delete|patch)\s*\(/gi
      ];
      
      for (const pattern of patterns) {
        const matches = fileContent.match(pattern);
        if (matches) {
          evidence.push(`Regex match: ${matches[0]}`);
          confidence = 0.6; // Medium confidence with regex
          break;
        }
      }
    }
    
    // Path-based heuristic
    if (confidence === 0 && finding.file.match(/\/(routes?|controllers?|api|endpoints?)\//i)) {
      evidence.push(`Path suggests route file: ${finding.file}`);
      confidence = 0.4; // Low confidence
    }
    
    return {
      detected: confidence > 0,
      confidence,
      evidence
    };
  }

  /**
   * Detect missing authentication
   */
  async detectAuth(fileContent, finding) {
    const evidence = [];
    let confidence = 0;
    let authFound = false;
    
    try {
      const ast = Parser.parse(fileContent, {
        sourceType: 'module',
        plugins: ['jsx', 'typescript'],
        errorRecovery: true
      });
      
      // Look for auth middleware patterns
      traverse(ast, {
        CallExpression(path) {
          const node = path.node;
          
          // Common auth middleware names
          const authPatterns = [
            'authenticate', 'requireAuth', 'isAuthenticated',
            'verifyToken', 'checkAuth', 'auth', 'protect',
            'ensureAuthenticated', 'passport.authenticate'
          ];
          
          const callName = this.getCallName(node);
          if (authPatterns.some(pattern => callName.includes(pattern))) {
            authFound = true;
            evidence.push(`Found auth middleware: ${callName}`);
          }
        }
      });
      
      if (!authFound) {
        confidence = 0.7; // Medium-high confidence
        evidence.push('No auth middleware detected in AST');
      }
      
    } catch (error) {
      // Regex fallback
      const authPatterns = [
        /authenticate|requireAuth|isAuthenticated/gi,
        /verifyToken|checkAuth|ensureAuthenticated/gi,
        /passport\.authenticate/gi,
        /\[Authorize\]/gi // .NET style
      ];
      
      const hasAuth = authPatterns.some(pattern => pattern.test(fileContent));
      
      if (!hasAuth) {
        confidence = 0.5; // Medium confidence
        evidence.push('No auth patterns found via regex');
      }
    }
    
    return {
      missing: confidence > 0,
      confidence,
      evidence
    };
  }

  /**
   * Detect PII fields
   */
  async detectPII(fileContent, finding) {
    const evidence = [];
    let confidence = 0;
    
    const piiFields = [
      'email', 'name', 'address', 'phone', 'ssn', 'dob',
      'passport', 'license', 'iban', 'creditcard', 'cvv',
      'firstName', 'lastName', 'dateOfBirth', 'socialSecurity'
    ];
    
    try {
      const ast = Parser.parse(fileContent, {
        sourceType: 'module', 
        plugins: ['jsx', 'typescript'],
        errorRecovery: true
      });
      
      traverse(ast, {
        ObjectProperty(path) {
          const key = path.node.key.name || path.node.key.value;
          if (key && piiFields.some(field => key.toLowerCase().includes(field))) {
            evidence.push(`PII field in schema: ${key}`);
            confidence = Math.max(confidence, 0.9);
          }
        },
        
        // Mongoose/Sequelize schemas
        CallExpression(path) {
          if (path.node.callee.name === 'Schema' || 
              path.node.callee.property?.name === 'define') {
            // Schema definition likely contains PII
            const schemaCode = fileContent.substring(path.node.start, path.node.end);
            const foundFields = piiFields.filter(field => 
              new RegExp(field, 'i').test(schemaCode)
            );
            
            if (foundFields.length > 0) {
              evidence.push(`PII fields in model: ${foundFields.join(', ')}`);
              confidence = Math.max(confidence, 0.9);
            }
          }
        }
      });
      
    } catch (error) {
      // Regex fallback
      const foundFields = piiFields.filter(field => 
        new RegExp(`['"\`]${field}['"\`]`, 'i').test(fileContent)
      );
      
      if (foundFields.length > 0) {
        evidence.push(`PII keywords found: ${foundFields.join(', ')}`);
        confidence = 0.6; // Medium confidence
      }
    }
    
    return {
      detected: confidence > 0,
      confidence,
      evidence
    };
  }

  /**
   * Detect public API endpoints
   */
  async detectPublicAPI(fileContent) {
    const evidence = [];
    let routeCount = 0;
    
    // Count route definitions
    const routePatterns = [
      /app\.(get|post|put|delete|patch)\s*\(/gi,
      /router\.(get|post|put|delete|patch)\s*\(/gi,
      /@(Get|Post|Put|Delete)\s*\(/gi
    ];
    
    for (const pattern of routePatterns) {
      const matches = fileContent.match(pattern);
      if (matches) {
        routeCount += matches.length;
        evidence.push(`Found ${matches.length} routes`);
      }
    }
    
    const confidence = routeCount > 0 ? Math.min(0.9, 0.3 + (routeCount * 0.1)) : 0;
    
    return {
      detected: routeCount > 0,
      confidence,
      evidence,
      metadata: { routeCount }
    };
  }

  /**
   * Detect user input handling
   */
  async detectUserInput(fileContent) {
    const evidence = [];
    let confidence = 0;
    
    const inputPatterns = [
      /req\.(body|query|params)/gi,
      /request\.(body|query|params)/gi,
      /ctx\.(request|query|params)/gi,
      /fastify\.(body|query|params)/gi,
      /JSON\.parse\s*\(/gi,
      /formData|FormData/gi
    ];
    
    for (const pattern of inputPatterns) {
      if (pattern.test(fileContent)) {
        const match = fileContent.match(pattern)[0];
        evidence.push(`User input: ${match}`);
        confidence = Math.max(confidence, 0.8);
      }
    }
    
    return {
      detected: confidence > 0,
      confidence,
      evidence
    };
  }

  /**
   * Check file-level auth
   */
  async detectFileAuth(fileContent) {
    // Reuse finding-level auth detection
    return this.detectAuth(fileContent, { file: 'unknown' });
  }

  /**
   * Helper to get call expression name
   */
  getCallName(node) {
    if (node.callee.type === 'Identifier') {
      return node.callee.name;
    } else if (node.callee.type === 'MemberExpression') {
      const obj = node.callee.object.name || '';
      const prop = node.callee.property.name || '';
      return `${obj}.${prop}`;
    }
    return '';
  }
}

module.exports = JSContextDetector;