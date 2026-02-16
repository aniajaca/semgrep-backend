// src/contextInference/detectors/pythonDetector.js
// Works without tree-sitter dependency

class PythonContextDetector {
  constructor(config = {}) {
    this.config = config;
  }

  /**
   * Detect route definitions using regex patterns
   */
  async detectRoutes(fileContent, finding) {
    const evidence = [];
    let confidence = 0;
    
    // Regex patterns for Flask/FastAPI/Django
    const patterns = [
      { pattern: /@app\.route\s*\(['"](.*?)['"]\)/gi, framework: 'Flask' },
      { pattern: /@router\.(get|post|put|delete)\s*\(['"](.*?)['"]\)/gi, framework: 'FastAPI' },
      { pattern: /@api_view\s*\(\[.*?\]\)/gi, framework: 'Django REST' },
      { pattern: /path\s*\(['"](.*?)['"],/gi, framework: 'Django' },
      { pattern: /@get\s*\(['"](.*?)['"]\)/gi, framework: 'FastAPI' },
      { pattern: /@post\s*\(['"](.*?)['"]\)/gi, framework: 'FastAPI' }
    ];
    
    for (const { pattern, framework } of patterns) {
      const matches = fileContent.match(pattern);
      if (matches) {
        evidence.push(`${framework}: ${matches[0]}`);
        confidence = Math.max(confidence, 0.8);
      }
    }
    
    // Path heuristic
    if (confidence === 0 && finding.file.match(/\/(views?|urls?|api|endpoints?|routes?)\.py$/i)) {
      evidence.push(`Path suggests route file: ${finding.file}`);
      confidence = 0.5;
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
    
    // Check for auth decorators/middleware
    const authPatterns = [
      /@login_required/gi,
      /@requires_auth/gi,
      /@jwt_required/gi,
      /@token_required/gi,
      /@authenticated/gi,
      /permission_required/gi,
      /IsAuthenticated/gi,  // Django REST
      /Depends\s*\(\s*get_current_user\s*\)/gi,  // FastAPI
      /current_user\s*:\s*User\s*=\s*Depends/gi
    ];
    
    for (const pattern of authPatterns) {
      if (pattern.test(fileContent)) {
        authFound = true;
        const match = fileContent.match(pattern)[0];
        evidence.push(`Found auth pattern: ${match}`);
        break;
      }
    }
    
    // Check if we're in a route handler
    const inRoute = /@app\.route|@router\.|def\s+(get|post|put|delete)_/i.test(fileContent);
    
    if (inRoute && !authFound) {
      confidence = 0.7;
      evidence.push('Route handler without auth decorator');
    } else if (!authFound) {
      confidence = 0.5;
      evidence.push('No auth patterns detected');
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
      'passport', 'license', 'iban', 'credit_card', 'cvv',
      'first_name', 'last_name', 'date_of_birth', 'social_security',
      'tax_id', 'national_id', 'driver_license'
    ];
    
    // Django/SQLAlchemy model patterns
    const modelPatterns = [
      /class\s+\w+\(.*Model.*\):/gi,
      /class\s+\w+\(.*BaseModel.*\):/gi,
      /class\s+\w+\(.*db\.Model.*\):/gi
    ];
    
    let inModel = false;
    for (const pattern of modelPatterns) {
      if (pattern.test(fileContent)) {
        inModel = true;
        evidence.push('Model class detected');
        break;
      }
    }
    
    // Check for PII fields
    for (const field of piiFields) {
      const fieldPattern = new RegExp(`\\b${field}\\s*[:=]`, 'gi');
      if (fieldPattern.test(fileContent)) {
        evidence.push(`PII field: ${field}`);
        confidence = Math.max(confidence, inModel ? 0.9 : 0.6);
      }
    }
    
    // Check for Django field types that suggest PII
    const djangoFieldPatterns = [
      /EmailField/gi,
      /PhoneNumberField/gi,
      /SSNField/gi,
      /CreditCardField/gi
    ];
    
    for (const pattern of djangoFieldPatterns) {
      if (pattern.test(fileContent)) {
        const match = fileContent.match(pattern)[0];
        evidence.push(`Django PII field type: ${match}`);
        confidence = Math.max(confidence, 0.9);
      }
    }
    
    // Marshmallow/Pydantic validators
    if (/EmailStr|EmailValidator|email_validator/gi.test(fileContent)) {
      evidence.push('Email validation found');
      confidence = Math.max(confidence, 0.8);
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
    
    // Count route decorators
    const routePatterns = [
      /@app\.route/gi,
      /@router\.(get|post|put|delete|patch)/gi,
      /@api_view/gi,
      /path\s*\(/gi
    ];
    
    for (const pattern of routePatterns) {
      const matches = fileContent.match(pattern);
      if (matches) {
        routeCount += matches.length;
        evidence.push(`Found ${matches.length} route definitions`);
      }
    }
    
    // Check for API blueprint/router
    if (/Blueprint|APIRouter|Router/gi.test(fileContent)) {
      evidence.push('API router/blueprint detected');
      routeCount = Math.max(routeCount, 1);
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
      /request\.(json|data|args|form|files)/gi,
      /request\.get_json/gi,
      /request\.POST/gi,
      /request\.GET/gi,
      /request\.body/gi,
      /json\.loads\s*\(/gi,
      /parse_qs/gi,
      /FormData/gi,
      /MultiDict/gi
    ];
    
    for (const pattern of inputPatterns) {
      if (pattern.test(fileContent)) {
        const match = fileContent.match(pattern)[0];
        evidence.push(`User input: ${match}`);
        confidence = Math.max(confidence, 0.8);
      }
    }
    
    // FastAPI automatic parsing
    if (/def\s+\w+\s*\([^)]*:\s*(dict|Dict|BaseModel|Schema)/gi.test(fileContent)) {
      evidence.push('FastAPI/Pydantic input model');
      confidence = Math.max(confidence, 0.9);
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
    return this.detectAuth(fileContent, { file: 'unknown' });
  }
}

module.exports = PythonContextDetector;