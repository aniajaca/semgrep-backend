// src/contextInference/detectors/javaDetector.js
// Simplified version without tree-sitter

class JavaContextDetector {
  constructor(config = {}) {
    this.config = config;
  }

  /**
   * Detect Spring/JAX-RS routes
   */
  async detectRoutes(fileContent, finding) {
    const evidence = [];
    let confidence = 0;
    
    // Spring annotations
    const springPatterns = [
      { pattern: /@RestController/gi, type: 'Spring RestController' },
      { pattern: /@Controller/gi, type: 'Spring Controller' },
      { pattern: /@RequestMapping/gi, type: 'Spring RequestMapping' },
      { pattern: /@GetMapping/gi, type: 'Spring GET' },
      { pattern: /@PostMapping/gi, type: 'Spring POST' },
      { pattern: /@PutMapping/gi, type: 'Spring PUT' },
      { pattern: /@DeleteMapping/gi, type: 'Spring DELETE' },
      { pattern: /@PatchMapping/gi, type: 'Spring PATCH' }
    ];
    
    // JAX-RS annotations
    const jaxrsPatterns = [
      { pattern: /@Path\s*\(/gi, type: 'JAX-RS Path' },
      { pattern: /@GET/gi, type: 'JAX-RS GET' },
      { pattern: /@POST/gi, type: 'JAX-RS POST' },
      { pattern: /@PUT/gi, type: 'JAX-RS PUT' },
      { pattern: /@DELETE/gi, type: 'JAX-RS DELETE' },
      { pattern: /@Produces/gi, type: 'JAX-RS Produces' },
      { pattern: /@Consumes/gi, type: 'JAX-RS Consumes' }
    ];
    
    // Check Spring patterns
    for (const { pattern, type } of springPatterns) {
      pattern.lastIndex = 0; // Reset regex
      if (pattern.test(fileContent)) {
        pattern.lastIndex = 0;
        const match = fileContent.match(pattern)[0];
        evidence.push(`${type}: ${match}`);
        confidence = Math.max(confidence, 0.9);
      }
    }
    
    // Check JAX-RS patterns
    for (const { pattern, type } of jaxrsPatterns) {
      pattern.lastIndex = 0;
      if (pattern.test(fileContent)) {
        pattern.lastIndex = 0;
        const match = fileContent.match(pattern)[0];
        evidence.push(`${type}: ${match}`);
        confidence = Math.max(confidence, 0.9);
      }
    }
    
    // Path heuristic
    if (confidence === 0 && finding.file.match(/\/(controller|resource|endpoint|api)\//i)) {
      evidence.push(`Path suggests controller: ${finding.file}`);
      confidence = 0.4;
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
    
    const authPatterns = [
      /@PreAuthorize/gi,
      /@PostAuthorize/gi,
      /@RolesAllowed/gi,
      /@Secured/gi,
      /@WithMockUser/gi,
      /@RequiresAuthentication/gi,
      /@RequiresPermissions/gi,
      /@RequiresRoles/gi,
      /SecurityContext/gi,
      /Principal\s+principal/gi,
      /Authentication\s+auth/gi
    ];
    
    for (const pattern of authPatterns) {
      pattern.lastIndex = 0;
      if (pattern.test(fileContent)) {
        authFound = true;
        pattern.lastIndex = 0;
        const match = fileContent.match(pattern)[0];
        evidence.push(`Found auth: ${match}`);
        break;
      }
    }
    
    // Check if we're in a controller
    const inController = /@(Rest)?Controller|@Path/gi.test(fileContent);
    
    if (inController && !authFound) {
      confidence = 0.7;
      evidence.push('Controller without auth annotations');
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
   * Detect PII fields in entities/DTOs
   */
  async detectPII(fileContent, finding) {
    const evidence = [];
    let confidence = 0;
    
    const piiFields = [
      'email', 'name', 'address', 'phone', 'ssn', 'dob',
      'passport', 'license', 'iban', 'creditCard', 'cvv',
      'firstName', 'lastName', 'dateOfBirth', 'socialSecurity',
      'taxId', 'nationalId', 'driverLicense'
    ];
    
    // Check if this is an entity or DTO
    const entityPatterns = [
      /@Entity/gi,
      /@Table/gi,
      /@Document/gi,  // MongoDB
      /class\s+\w+DTO/gi,
      /class\s+\w+Entity/gi,
      /class\s+\w+Model/gi
    ];
    
    let inEntity = false;
    for (const pattern of entityPatterns) {
      pattern.lastIndex = 0;
      if (pattern.test(fileContent)) {
        inEntity = true;
        evidence.push('Entity/DTO class detected');
        break;
      }
    }
    
    // Check for PII fields
    for (const field of piiFields) {
      const patterns = [
        new RegExp(`private\\s+\\w+\\s+${field}`, 'gi'),
        new RegExp(`String\\s+${field}`, 'gi'),
        new RegExp(`@Column.*name\\s*=\\s*"${field}"`, 'gi')
      ];
      
      for (const pattern of patterns) {
        if (pattern.test(fileContent)) {
          evidence.push(`PII field: ${field}`);
          confidence = Math.max(confidence, inEntity ? 0.9 : 0.6);
          break;
        }
      }
    }
    
    // JPA/Validation annotations that suggest PII
    const piiAnnotations = [
      /@Email/gi,
      /@PersonalData/gi,
      /@SensitiveData/gi,
      /@Encrypted/gi,
      /@Masked/gi
    ];
    
    for (const pattern of piiAnnotations) {
      pattern.lastIndex = 0;
      if (pattern.test(fileContent)) {
        pattern.lastIndex = 0;
        const match = fileContent.match(pattern)[0];
        evidence.push(`PII annotation: ${match}`);
        confidence = Math.max(confidence, 0.9);
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
    
    // Count mapping annotations
    const mappingPatterns = [
      /@RequestMapping/gi,
      /@GetMapping/gi,
      /@PostMapping/gi,
      /@PutMapping/gi,
      /@DeleteMapping/gi,
      /@PatchMapping/gi,
      /@Path\s*\(/gi
    ];
    
    for (const pattern of mappingPatterns) {
      pattern.lastIndex = 0;
      const matches = fileContent.match(pattern);
      if (matches) {
        routeCount += matches.length;
        evidence.push(`Found ${matches.length} mappings`);
      }
    }
    
    // Check for controller class
    const controllerPattern = /@(Rest)?Controller|@Path/gi;
    if (controllerPattern.test(fileContent)) {
      evidence.push('Controller class detected');
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
      /@RequestBody/gi,
      /@RequestParam/gi,
      /@PathVariable/gi,
      /@ModelAttribute/gi,
      /@FormParam/gi,
      /@QueryParam/gi,
      /HttpServletRequest/gi,
      /ServletRequest/gi,
      /MultipartFile/gi,
      /@Valid/gi
    ];
    
    for (const pattern of inputPatterns) {
      pattern.lastIndex = 0;
      if (pattern.test(fileContent)) {
        pattern.lastIndex = 0;
        const match = fileContent.match(pattern)[0];
        evidence.push(`User input: ${match}`);
        confidence = Math.max(confidence, 0.8);
      }
    }
    
    // Object mapper patterns
    if (/ObjectMapper.*readValue/gi.test(fileContent)) {
      evidence.push('JSON deserialization detected');
      confidence = Math.max(confidence, 0.8);
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

module.exports = JavaContextDetector;