// src/SecurityClassificationSystem.js - Enhanced implementation with intelligent pattern matching
const { getSeverityWeight, getSeverityLevel, classifySeverity } = require('./utils');

/**
 * Enhanced Security Classification System with intelligent CWE inference and proper vulnerability naming
 * 🔧 STATIC: This class provides comprehensive rule-based vulnerability classification
 * 🎯 FOCUS: Proper vulnerability naming instead of generic "Security Issue"
 */
class SecurityClassificationSystem {
  constructor() {
    this.cweDatabase = this.initializeCWEDatabase();
    this.owaspMapping = this.initializeOWASPMapping();
    this.rulePatternDatabase = this.initializeRulePatternDatabase();
    this.cvssCalculator = new CVSSCalculator();
    console.log('🔧 STATIC: Enhanced SecurityClassificationSystem v3.0 initialized');
  }

  /**
   * Classify a security finding with enhanced context and intelligent CWE inference
   * 🔧 STATIC: Rule-based classification with intelligent pattern matching
   * @param {Object} finding - Raw finding from Semgrep
   * @returns {Object} Enhanced classified finding
   */
  classifyFinding(finding) {
    const context = finding.context || {};
    
    console.log('🔧 STATIC: Classifying finding:', finding.check_id);
    
    // Step 1: Extract enhanced information with intelligent CWE inference
    const enhancedInfo = this.extractEnhancedInfo(finding);
    
    // Step 2: Get CWE information with proper fallback
    const cweInfo = this.getCWEInfoWithIntelligence(enhancedInfo);
    
    // Step 3: Map to OWASP category
    const owaspCategory = this.mapToOWASP(cweInfo.category);
    
    // Step 4: Calculate CVSS score with environmental adjustments
    const cvssInfo = this.cvssCalculator.calculate(finding, context);
    
    // Step 5: Determine final severity
    const finalSeverity = this.determineFinalSeverity(cvssInfo.adjustedScore);
    
    // Step 6: Generate AI-friendly metadata
    const aiMetadata = this.generateAIMetadata(finding, context, cweInfo);
    
    // Step 7: Create business impact assessment
    const businessImpact = this.assessBusinessImpact(finding, context, cvssInfo);
    
    // Step 8: Generate proper human-readable title
    const properTitle = this.generateProperTitle(finding, cweInfo);
    
    console.log(`🔧 STATIC: Classified as "${cweInfo.name}" with ${finalSeverity} severity (CVSS: ${cvssInfo.adjustedScore})`);
    
    return {
      // Core identification
      id: this.generateFindingId(finding),
      ruleId: enhancedInfo.ruleId,
      title: properTitle,
      
      // Classification (🔧 STATIC) - ENHANCED WITH PROPER NAMES
      severity: finalSeverity,
      confidence: enhancedInfo.confidence,
      cwe: {
        id: cweInfo.id,
        name: cweInfo.name,
        category: cweInfo.category,
        description: cweInfo.description,
        confidenceLevel: enhancedInfo.cweConfidence
      },
      owaspCategory,
      
      // Risk scoring (🔧 STATIC)
      cvss: {
        baseScore: cvssInfo.baseScore,
        adjustedScore: cvssInfo.adjustedScore,
        vector: cvssInfo.vector,
        severity: cvssInfo.severity,
        environmentalScore: cvssInfo.environmentalScore
      },
      
      // Code context (🔧 STATIC)
      scannerData: {
        location: {
          file: finding.path || finding.scannerData?.location?.file || 'unknown',
          line: finding.start?.line || finding.scannerData?.location?.line || 0,
          column: finding.start?.col || finding.scannerData?.location?.column || 0
        },
        rawMessage: finding.message || finding.title,
        confidence: finding.extra?.confidence || enhancedInfo.confidence,
        vulnerabilityClass: finding.extra?.metadata?.vulnerability_class || [cweInfo.name]
      },
      
      // Code snippet and context (🔧 STATIC)
      codeSnippet: finding.extractedCode || finding.extra?.lines || '',
      codeContext: finding.extra?.context || '',
      
      // Business context (🔧 STATIC)
      impact: businessImpact.description,
      businessRisk: businessImpact.level,
      exploitability: this.assessExploitability(finding, context),
      
      // Remediation guidance (🔧 STATIC templates, 🤖 AI will enhance)
      remediation: this.generateRemediationGuidance(cweInfo, context),
      remediationComplexity: this.assessRemediationComplexity(finding, context),
      
      // AI integration metadata (🤖 AI PREPARATION)
      aiMetadata,
      
      // Environmental context (🔧 STATIC)
      environmentalFactors: this.analyzeEnvironmentalFactors(context),
      
      // Compliance mapping (🔧 STATIC)
      complianceMapping: this.mapToCompliance(cweInfo, context),
      
      // Classification metadata
      classificationSource: enhancedInfo.source,
      patternMatched: enhancedInfo.patternMatched,
      
      // Timestamps and metadata
      classifiedAt: new Date().toISOString(),
      classificationVersion: '3.0'
    };
  }

  /**
   * Extract enhanced information from raw finding with intelligent inference
   * 🔧 STATIC: Advanced data extraction and CWE inference
   */
  extractEnhancedInfo(finding) {
    const ruleId = finding.check_id || finding.ruleId || 'unknown-rule';
    
    // Step 1: Try to extract CWE from Semgrep metadata (PRIORITY)
    let cweId = null;
    let confidence = 'medium';
    let source = 'inferred';
    let patternMatched = false;

    // Check Semgrep metadata first (highest confidence)
    if (finding.extra?.metadata?.cwe && Array.isArray(finding.extra.metadata.cwe)) {
      const cweString = finding.extra.metadata.cwe[0];
      const match = cweString.match(/CWE-(\d+)/i);
      if (match) {
        cweId = `CWE-${match[1]}`;
        confidence = 'high';
        source = 'semgrep-metadata';
      }
    }

    // Step 2: Try vulnerability_class from Semgrep
    if (!cweId && finding.extra?.metadata?.vulnerability_class) {
      const vulnClass = finding.extra.metadata.vulnerability_class[0];
      cweId = this.mapVulnerabilityClassToCWE(vulnClass);
      if (cweId) {
        confidence = 'high';
        source = 'vulnerability-class';
      }
    }

    // Step 3: Rule pattern matching (enhanced)
    if (!cweId) {
      const patternResult = this.intelligentRulePatternMatch(ruleId);
      cweId = patternResult.cweId;
      confidence = patternResult.confidence;
      source = 'pattern-matching';
      patternMatched = patternResult.patternFound;
    }

    // Step 4: Message analysis fallback
    if (!cweId) {
      cweId = this.inferCWEFromMessage(finding.message || finding.title || '');
      confidence = 'low';
      source = 'message-analysis';
    }

    return {
      ruleId,
      cweId: cweId || 'CWE-200',
      confidence,
      cweConfidence: confidence,
      source,
      patternMatched,
      message: finding.message || finding.title || 'No description available',
      severity: finding.severity || 'medium'
    };
  }

  /**
   * Map Semgrep vulnerability_class to CWE
   * 🔧 STATIC: Direct mapping from Semgrep classifications
   */
  mapVulnerabilityClassToCWE(vulnerabilityClass) {
    const classMapping = {
      'SQL Injection': 'CWE-89',
      'Cross-Site Scripting (XSS)': 'CWE-79',
      'Code Injection': 'CWE-94',
      'Command Injection': 'CWE-78',
      'Path Traversal': 'CWE-22',
      'Cross-Site Request Forgery (CSRF)': 'CWE-352',
      'Cryptographic Issues': 'CWE-327',
      'Improper Validation': 'CWE-20',
      'Authentication Issues': 'CWE-287',
      'Authorization Issues': 'CWE-863',
      'Information Disclosure': 'CWE-200',
      'Insecure Storage': 'CWE-312',
      'Insecure Communication': 'CWE-319',
      'Session Management': 'CWE-613',
      'Input Validation': 'CWE-20',
      'File Upload': 'CWE-434',
      'Deserialization': 'CWE-502',
      'XML Issues': 'CWE-611',
      'Hardcoded Secrets': 'CWE-798'
    };

    return classMapping[vulnerabilityClass] || null;
  }

  /**
   * Intelligent rule pattern matching with comprehensive database
   * 🔧 STATIC: Advanced pattern recognition
   */
  intelligentRulePatternMatch(ruleId) {
    if (!ruleId) return { cweId: null, confidence: 'low', patternFound: false };

    const lowerRuleId = ruleId.toLowerCase();
    
    // Direct rule mapping (highest confidence)
    if (this.rulePatternDatabase.directMappings[ruleId]) {
      return {
        cweId: this.rulePatternDatabase.directMappings[ruleId],
        confidence: 'very-high',
        patternFound: true
      };
    }

    // Pattern-based matching (high confidence)
    for (const [pattern, cweId] of this.rulePatternDatabase.patterns) {
      if (lowerRuleId.includes(pattern)) {
        return {
          cweId,
          confidence: 'high',
          patternFound: true
        };
      }
    }

    // Fuzzy matching for complex rule names (medium confidence)
    const fuzzyResult = this.fuzzyPatternMatch(lowerRuleId);
    if (fuzzyResult.cweId) {
      return {
        cweId: fuzzyResult.cweId,
        confidence: 'medium',
        patternFound: true
      };
    }

    return { cweId: null, confidence: 'low', patternFound: false };
  }

  /**
   * Initialize comprehensive rule pattern database
   * 🔧 STATIC: Extensive mapping of Semgrep rules to CWE
   */
  initializeRulePatternDatabase() {
    return {
      // Direct rule mappings (exact matches from Semgrep)
      directMappings: {
        'python.lang.security.audit.formatted-sql-query.formatted-sql-query': 'CWE-89',
        'python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query': 'CWE-89',
        'javascript.express.security.audit.xss.template-string-in-response': 'CWE-79',
        'javascript.browser.security.insecure-document-method.insecure-document-method': 'CWE-79',
        'javascript.lang.security.detect-child-process.detect-child-process': 'CWE-78',
        'python.lang.security.audit.subprocess-shell-true.subprocess-shell-true': 'CWE-78',
        'javascript.express.security.audit.express-check-csurf-middleware-usage.express-check-csurf-middleware-usage': 'CWE-352',
        'python.lang.security.audit.md5-used-as-password.md5-used-as-password': 'CWE-327',
        'javascript.lang.security.audit.md5-used-as-password.md5-used-as-password': 'CWE-327',
        'python.lang.security.audit.hardcoded-password.hardcoded-password': 'CWE-798',
        'javascript.lang.security.audit.hardcoded-secret.hardcoded-secret': 'CWE-798',
        'python.lang.security.audit.path-traversal.path-traversal': 'CWE-22',
        'javascript.browser.security.eval-detected.eval-detected': 'CWE-94',
        'python.lang.security.audit.eval-use.eval-use': 'CWE-94'
      },

      // Pattern-based mappings (substring matching)
      patterns: [
        // SQL Injection patterns
        ['sql-injection', 'CWE-89'],
        ['sql.injection', 'CWE-89'],
        ['sqlinjection', 'CWE-89'],
        ['formatted-sql', 'CWE-89'],
        ['sql-query', 'CWE-89'],
        ['sqlalchemy-execute', 'CWE-89'],
        ['raw-sql', 'CWE-89'],
        ['concatenat.*sql', 'CWE-89'],

        // XSS patterns
        ['xss', 'CWE-79'],
        ['cross-site-scripting', 'CWE-79'],
        ['template-string-in-response', 'CWE-79'],
        ['insecure-document-method', 'CWE-79'],
        ['innerHTML', 'CWE-79'],
        ['outerHTML', 'CWE-79'],
        ['document.write', 'CWE-79'],

        // Command Injection patterns
        ['command-injection', 'CWE-78'],
        ['child-process', 'CWE-78'],
        ['subprocess', 'CWE-78'],
        ['shell-true', 'CWE-78'],
        ['os.system', 'CWE-78'],
        ['exec', 'CWE-78'],

        // Code Injection patterns
        ['code-injection', 'CWE-94'],
        ['eval-detected', 'CWE-94'],
        ['eval-use', 'CWE-94'],
        ['dynamic-code', 'CWE-94'],

        // CSRF patterns
        ['csrf', 'CWE-352'],
        ['cross-site-request-forgery', 'CWE-352'],
        ['csurf-middleware', 'CWE-352'],

        // Cryptographic patterns
        ['md5-used-as-password', 'CWE-327'],
        ['weak-crypto', 'CWE-327'],
        ['weak-hash', 'CWE-327'],
        ['insecure-hash', 'CWE-327'],
        ['weak-cipher', 'CWE-327'],
        ['des-cipher', 'CWE-327'],

        // Path Traversal patterns
        ['path-traversal', 'CWE-22'],
        ['directory-traversal', 'CWE-22'],
        ['path-injection', 'CWE-22'],

        // Hardcoded Credentials patterns
        ['hardcoded-password', 'CWE-798'],
        ['hardcoded-secret', 'CWE-798'],
        ['hardcoded-key', 'CWE-798'],
        ['embedded-credentials', 'CWE-798'],

        // Deserialization patterns
        ['deserialization', 'CWE-502'],
        ['pickle-load', 'CWE-502'],
        ['yaml-load', 'CWE-502'],
        ['untrusted-deserialization', 'CWE-502'],

        // XXE patterns
        ['xxe', 'CWE-611'],
        ['xml-external-entity', 'CWE-611'],
        ['xml-parser', 'CWE-611'],

        // Information Disclosure patterns
        ['information-disclosure', 'CWE-200'],
        ['sensitive-data', 'CWE-200'],
        ['debug-info', 'CWE-200'],
        ['stack-trace', 'CWE-200']
      ]
    };
  }

  /**
   * Fuzzy pattern matching for complex rule names
   * 🔧 STATIC: Advanced pattern recognition
   */
  fuzzyPatternMatch(ruleId) {
    const fuzzyPatterns = [
      { keywords: ['sql', 'query', 'format'], cweId: 'CWE-89', weight: 3 },
      { keywords: ['sql', 'inject'], cweId: 'CWE-89', weight: 3 },
      { keywords: ['cross', 'site', 'script'], cweId: 'CWE-79', weight: 3 },
      { keywords: ['template', 'response'], cweId: 'CWE-79', weight: 2 },
      { keywords: ['command', 'inject'], cweId: 'CWE-78', weight: 3 },
      { keywords: ['process', 'exec'], cweId: 'CWE-78', weight: 2 },
      { keywords: ['eval', 'dynamic'], cweId: 'CWE-94', weight: 2 },
      { keywords: ['crypto', 'weak'], cweId: 'CWE-327', weight: 2 },
      { keywords: ['hash', 'md5'], cweId: 'CWE-327', weight: 2 },
      { keywords: ['password', 'hardcode'], cweId: 'CWE-798', weight: 3 },
      { keywords: ['secret', 'hardcode'], cweId: 'CWE-798', weight: 3 },
      { keywords: ['path', 'traversal'], cweId: 'CWE-22', weight: 3 },
      { keywords: ['deserialize', 'untrust'], cweId: 'CWE-502', weight: 3 }
    ];

    let bestMatch = { cweId: null, score: 0 };

    for (const pattern of fuzzyPatterns) {
      let score = 0;
      for (const keyword of pattern.keywords) {
        if (ruleId.includes(keyword)) {
          score += pattern.weight;
        }
      }

      if (score > bestMatch.score && score >= pattern.weight) {
        bestMatch = { cweId: pattern.cweId, score };
      }
    }

    return bestMatch;
  }

  /**
   * Infer CWE from message content
   * 🔧 STATIC: Message analysis fallback
   */
  inferCWEFromMessage(message) {
    const lowerMessage = message.toLowerCase();

    const messagePatterns = {
      'sql injection': 'CWE-89',
      'parameterized queries': 'CWE-89',
      'cross-site scripting': 'CWE-79',
      'xss': 'CWE-79',
      'command injection': 'CWE-78',
      'code injection': 'CWE-94',
      'eval': 'CWE-94',
      'path traversal': 'CWE-22',
      'directory traversal': 'CWE-22',
      'hardcoded': 'CWE-798',
      'weak crypto': 'CWE-327',
      'md5': 'CWE-327',
      'csrf': 'CWE-352',
      'deserialization': 'CWE-502',
      'xml external entity': 'CWE-611',
      'xxe': 'CWE-611'
    };

    for (const [pattern, cwe] of Object.entries(messagePatterns)) {
      if (lowerMessage.includes(pattern)) {
        return cwe;
      }
    }

    return 'CWE-200'; // Default to information exposure
  }

  /**
   * Get CWE information with intelligent fallback
   * 🔧 STATIC: Enhanced database lookup with proper naming
   */
  getCWEInfoWithIntelligence(enhancedInfo) {
    const cweId = enhancedInfo.cweId;
    
    // Try exact match first
    if (this.cweDatabase[cweId]) {
      return this.cweDatabase[cweId];
    }

    // Enhanced fallback with better naming
    const fallbackInfo = {
      id: cweId || 'CWE-200',
      name: this.generateCWEName(cweId, enhancedInfo),
      category: this.inferCWECategory(cweId),
      description: this.generateCWEDescription(cweId, enhancedInfo),
      baseScore: this.inferBaseScore(cweId),
      impact: this.inferImpact(cweId)
    };

    console.log(`🔧 STATIC: Generated fallback CWE info for ${cweId}: ${fallbackInfo.name}`);
    return fallbackInfo;
  }

  /**
   * Generate proper CWE name instead of "Security Issue"
   * 🔧 STATIC: Intelligent naming based on CWE and context
   */
  generateCWEName(cweId, enhancedInfo) {
    // Known CWE names
    const knownNames = {
      'CWE-89': 'SQL Injection',
      'CWE-79': 'Cross-Site Scripting (XSS)',
      'CWE-78': 'OS Command Injection',
      'CWE-94': 'Code Injection',
      'CWE-22': 'Path Traversal',
      'CWE-352': 'Cross-Site Request Forgery (CSRF)',
      'CWE-327': 'Weak Cryptography',
      'CWE-798': 'Hardcoded Credentials',
      'CWE-502': 'Deserialization of Untrusted Data',
      'CWE-611': 'XML External Entity (XXE)',
      'CWE-200': 'Information Exposure',
      'CWE-20': 'Improper Input Validation',
      'CWE-287': 'Improper Authentication',
      'CWE-863': 'Incorrect Authorization',
      'CWE-434': 'Unrestricted File Upload'
    };

    if (knownNames[cweId]) {
      return knownNames[cweId];
    }

    // Infer from rule ID if possible
    if (enhancedInfo.ruleId) {
      const ruleId = enhancedInfo.ruleId.toLowerCase();
      if (ruleId.includes('sql')) return 'SQL Injection';
      if (ruleId.includes('xss')) return 'Cross-Site Scripting';
      if (ruleId.includes('command') || ruleId.includes('exec')) return 'Command Injection';
      if (ruleId.includes('path')) return 'Path Traversal';
      if (ruleId.includes('crypto') || ruleId.includes('hash')) return 'Cryptographic Weakness';
      if (ruleId.includes('hardcode')) return 'Hardcoded Credentials';
    }

    // Extract from CWE ID if it follows standard format
    const match = cweId?.match(/CWE-(\d+)/);
    if (match) {
      return `Security Weakness (${cweId})`;
    }

    return 'Security Vulnerability';
  }

  /**
   * Generate proper human-readable title
   * 🔧 STATIC: Enhanced title generation
   */
  generateProperTitle(finding, cweInfo) {
    const fileName = this.extractFileName(finding.path || finding.scannerData?.location?.file || 'unknown file');
    const lineNumber = finding.start?.line || finding.scannerData?.location?.line;
    
    if (lineNumber) {
      return `${cweInfo.name} in ${fileName}:${lineNumber}`;
    } else {
      return `${cweInfo.name} in ${fileName}`;
    }
  }

  /**
   * Extract clean file name from path
   * 🔧 STATIC: File path processing
   */
  extractFileName(filePath) {
    if (!filePath || filePath === 'unknown file') return 'unknown file';
    
    // Handle different path formats
    const normalizedPath = filePath.replace(/\\/g, '/');
    const parts = normalizedPath.split('/');
    const fileName = parts[parts.length - 1];
    
    // Clean up temporary file paths
    if (fileName.startsWith('upload_') || fileName.includes('tmp')) {
      return 'uploaded file';
    }
    
    return fileName || 'unknown file';
  }

  /**
   * Infer CWE category for proper OWASP mapping
   * 🔧 STATIC: Category inference
   */
  inferCWECategory(cweId) {
    const categoryMapping = {
      'CWE-89': 'Input Validation',
      'CWE-79': 'Input Validation', 
      'CWE-78': 'Input Validation',
      'CWE-94': 'Input Validation',
      'CWE-22': 'Input Validation',
      'CWE-352': 'Authentication',
      'CWE-327': 'Cryptographic Issues',
      'CWE-798': 'Authentication',
      'CWE-502': 'Input Validation',
      'CWE-611': 'Input Validation',
      'CWE-200': 'Information Disclosure',
      'CWE-20': 'Input Validation',
      'CWE-287': 'Authentication',
      'CWE-863': 'Authorization'
    };

    return categoryMapping[cweId] || 'General';
  }

  /**
   * Generate CWE description
   * 🔧 STATIC: Description generation
   */
  generateCWEDescription(cweId, enhancedInfo) {
    const descriptions = {
      'CWE-89': 'Improper neutralization of special elements used in an SQL command',
      'CWE-79': 'Improper neutralization of input during web page generation',
      'CWE-78': 'Improper neutralization of special elements used in an OS command',
      'CWE-94': 'Improper control of generation of code',
      'CWE-22': 'Improper limitation of a pathname to a restricted directory',
      'CWE-352': 'Cross-site request forgery vulnerability',
      'CWE-327': 'Use of a broken or risky cryptographic algorithm',
      'CWE-798': 'Use of hard-coded credentials',
      'CWE-502': 'Deserialization of untrusted data',
      'CWE-611': 'Improper restriction of XML external entity reference',
      'CWE-200': 'Exposure of sensitive information to an unauthorized actor'
    };

    return descriptions[cweId] || `Security vulnerability detected: ${cweId}`;
  }

  /**
   * Infer base CVSS score
   * 🔧 STATIC: Score inference
   */
  inferBaseScore(cweId) {
    const scores = {
      'CWE-89': 9.8,
      'CWE-78': 9.8,
      'CWE-94': 9.3,
      'CWE-502': 9.8,
      'CWE-352': 8.8,
      'CWE-611': 8.2,
      'CWE-79': 6.1,
      'CWE-798': 7.8,
      'CWE-327': 7.4,
      'CWE-22': 7.5,
      'CWE-200': 5.3
    };

    return scores[cweId] || 5.0;
  }

  /**
   * Infer impact level
   * 🔧 STATIC: Impact inference
   */
  inferImpact(cweId) {
    const impacts = {
      'CWE-89': 'Critical',
      'CWE-78': 'Critical', 
      'CWE-94': 'Critical',
      'CWE-502': 'Critical',
      'CWE-352': 'High',
      'CWE-611': 'High',
      'CWE-798': 'High',
      'CWE-327': 'High',
      'CWE-22': 'High',
      'CWE-79': 'Medium',
      'CWE-200': 'Medium'
    };

    return impacts[cweId] || 'Medium';
  }

  /**
   * Initialize comprehensive CWE database
   * 🔧 STATIC: Extended vulnerability knowledge base
   */
  initializeCWEDatabase() {
    return {
      'CWE-79': {
        id: 'CWE-79',
        name: 'Cross-Site Scripting (XSS)',
        category: 'Input Validation',
        description: 'Improper neutralization of input during web page generation',
        baseScore: 6.1,
        impact: 'Medium'
      },
      'CWE-89': {
        id: 'CWE-89',
        name: 'SQL Injection',
        category: 'Input Validation',
        description: 'Improper neutralization of special elements used in an SQL command',
        baseScore: 9.8,
        impact: 'Critical'
      },
      'CWE-78': {
        id: 'CWE-78',
        name: 'OS Command Injection',
        category: 'Input Validation',
        description: 'Improper neutralization of special elements used in an OS command',
        baseScore: 9.8,
        impact: 'Critical'
      },
      'CWE-94': {
        id: 'CWE-94',
        name: 'Code Injection',
        category: 'Input Validation',
        description: 'Improper control of generation of code',
        baseScore: 9.3,
        impact: 'Critical'
      },
      'CWE-22': {
        id: 'CWE-22',
        name: 'Path Traversal',
        category: 'Input Validation',
        description: 'Improper limitation of a pathname to a restricted directory',
        baseScore: 7.5,
        impact: 'High'
      },
      'CWE-798': {
        id: 'CWE-798',
        name: 'Hardcoded Credentials',
        category: 'Authentication',
        description: 'Use of hard-coded credentials',
        baseScore: 7.8,
        impact: 'High'
      },
      'CWE-327': {
        id: 'CWE-327',
        name: 'Weak Cryptography',
        category: 'Cryptographic Issues',
        description: 'Use of a broken or risky cryptographic algorithm',
        baseScore: 7.4,
        impact: 'High'
      },
      'CWE-200': {
        id: 'CWE-200',
        name: 'Information Exposure',
        category: 'Information Disclosure',
        description: 'Exposure of sensitive information to an unauthorized actor',
        baseScore: 5.3,
        impact: 'Medium'
      },
      'CWE-352': {
        id: 'CWE-352',
        name: 'Cross-Site Request Forgery (CSRF)',
        category: 'Authentication',
        description: 'Cross-site request forgery',
        baseScore: 8.8,
        impact: 'High'
      },
      'CWE-502': {
        id: 'CWE-502',
        name: 'Deserialization of Untrusted Data',
        category: 'Input Validation',
        description: 'Deserialization of untrusted data',
        baseScore: 9.8,
        impact: 'Critical'
      },
      'CWE-611': {
        id: 'CWE-611',
        name: 'XML External Entity (XXE)',
        category: 'Input Validation',
        description: 'Improper restriction of XML external entity reference',
        baseScore: 8.2,
        impact: 'High'
      },
      'CWE-20': {
        id: 'CWE-20',
        name: 'Improper Input Validation',
        category: 'Input Validation',
        description: 'The product receives input or data, but does not validate it properly',
        baseScore: 6.5,
        impact: 'Medium'
      },
      'CWE-287': {
        id: 'CWE-287',
        name: 'Improper Authentication',
        category: 'Authentication',
        description: 'When an actor claims to have a given identity, the software does not prove or insufficiently proves that the claim is correct',
        baseScore: 7.0,
        impact: 'High'
      },
      'CWE-863': {
        id: 'CWE-863',
        name: 'Incorrect Authorization',
        category: 'Authorization',
        description: 'The software performs an authorization check when an actor attempts to access a resource, but it does not correctly perform the check',
        baseScore: 7.5,
        impact: 'High'
      },
      'CWE-434': {
        id: 'CWE-434',
        name: 'Unrestricted File Upload',
        category: 'Input Validation',
        description: 'The software allows the attacker to upload or transfer files of dangerous types',
        baseScore: 8.1,
        impact: 'High'
      },
      'CWE-319': {
        id: 'CWE-319',
        name: 'Cleartext Transmission',
        category: 'Cryptographic Issues',
        description: 'The software transmits sensitive or security-critical data in cleartext',
        baseScore: 8.2,
        impact: 'High'
      },
      'CWE-338': {
        id: 'CWE-338',
        name: 'Weak PRNG',
        category: 'Cryptographic Issues',
        description: 'Use of cryptographically weak pseudo-random number generator',
        baseScore: 6.8,
        impact: 'Medium'
      },
      'CWE-613': {
        id: 'CWE-613',
        name: 'Insufficient Session Expiration',
        category: 'Session Management',
        description: 'Insufficient session expiration by the application',
        baseScore: 6.3,
        impact: 'Medium'
      },
      'CWE-918': {
        id: 'CWE-918',
        name: 'Server-Side Request Forgery (SSRF)',
        category: 'Input Validation',
        description: 'The web server receives a URL or similar request from an upstream component and retrieves the contents of this URL',
        baseScore: 8.5,
        impact: 'High'
      },
      'CWE-134': {
        id: 'CWE-134',
        name: 'Format String Vulnerability',
        category: 'Input Validation',
        description: 'Use of externally-controlled format string',
        baseScore: 7.3,
        impact: 'High'
      }
    };
  }

  /**
   * Initialize OWASP Top 10 mapping
   * 🔧 STATIC: OWASP classification rules
   */
  initializeOWASPMapping() {
    return {
      'Input Validation': 'A03:2021 – Injection',
      'Authentication': 'A07:2021 – Identification and Authentication Failures',
      'Authorization': 'A01:2021 – Broken Access Control',
      'Cryptographic Issues': 'A02:2021 – Cryptographic Failures',
      'Information Disclosure': 'A01:2021 – Broken Access Control',
      'Session Management': 'A07:2021 – Identification and Authentication Failures',
      'General': 'A06:2021 – Vulnerable and Outdated Components'
    };
  }

  /**
   * Map CWE category to OWASP Top 10
   * 🔧 STATIC: Category mapping
   */
  mapToOWASP(cweCategory) {
    return this.owaspMapping[cweCategory] || 'A06:2021 – Vulnerable and Outdated Components';
  }

  /**
   * Generate unique finding ID
   * 🔧 STATIC: ID generation
   */
  generateFindingId(finding) {
    const file = finding.path || finding.scannerData?.location?.file || 'unknown';
    const line = finding.start?.line || finding.scannerData?.location?.line || 0;
    const rule = finding.check_id || finding.ruleId || 'unknown';
    
    // Create a shorter, cleaner ID
    const cleanFile = this.extractFileName(file).replace(/[^a-zA-Z0-9]/g, '_');
    const cleanRule = rule.split('.').pop() || rule;
    
    return `${cleanRule}-${cleanFile}-${line}`;
  }

  /**
   * Determine final severity based on adjusted CVSS score
   * 🔧 STATIC: Severity classification
   */
  determineFinalSeverity(adjustedScore) {
    return classifySeverity(adjustedScore);
  }

  /**
   * Generate AI-friendly metadata for enhanced explanations
   * 🤖 AI PREPARATION: This metadata helps AI generate contextual explanations
   */
  generateAIMetadata(finding, context, cweInfo) {
    return {
      // Static rule-based data (🔧 STATIC)
      rulePattern: finding.check_id || finding.ruleId,
      cweCategory: cweInfo.category,
      vulnerabilityType: cweInfo.name,
      
      // Environmental context for AI (🤖 AI INPUT)
      environmentalContext: {
        systemType: this.inferSystemType(context),
        riskAmplifiers: this.identifyRiskAmplifiers(context),
        businessContext: this.extractBusinessContext(context),
        complianceRequirements: context.regulatoryRequirements || []
      },
      
      // Code context for AI explanations (🤖 AI INPUT)
      codeContext: {
        language: this.inferLanguage(finding.path),
        framework: this.inferFramework(finding),
        codePattern: finding.extractedCode || finding.extra?.lines || '',
        isLegacyCode: this.assessLegacyStatus(finding, context)
      },
      
      // Audience targeting hints (🤖 AI INPUT)
      audienceHints: {
        technicalComplexity: this.assessTechnicalComplexity(cweInfo),
        businessImpactArea: this.identifyBusinessImpactArea(cweInfo, context),
        urgencyIndicators: this.calculateUrgencyIndicators(finding, context)
      }
    };
  }

  /**
   * Assess business impact based on vulnerability and context
   * 🔧 STATIC: Rule-based business impact assessment
   */
  assessBusinessImpact(finding, context, cvssInfo) {
    const baseImpact = this.getBaseBusinessImpact(cvssInfo.baseScore);
    const contextMultiplier = this.calculateContextMultiplier(context);
    const adjustedImpact = baseImpact.level * contextMultiplier;

    return {
      level: this.classifyBusinessImpact(adjustedImpact),
      description: this.generateBusinessImpactDescription(finding, context, adjustedImpact),
      financialRisk: this.estimateFinancialRisk(adjustedImpact, context),
      reputationalRisk: this.assessReputationalRisk(finding, context)
    };
  }

  /**
   * Aggregate risk scores for multiple findings
   * 🔧 STATIC: Mathematical risk aggregation
   */
  aggregateRiskScore(findings, context) {
    if (!findings || findings.length === 0) {
      return {
        riskScore: 0,
        riskLevel: 'None',
        confidence: 'High',
        summary: 'No security vulnerabilities detected'
      };
    }

    console.log(`🔧 STATIC: Aggregating risk for ${findings.length} findings`);

    // Calculate weighted risk score
    const weightedScores = findings.map(f => {
      const weight = getSeverityWeight(f.severity);
      const environmentalMultiplier = context.environmentMultiplier || 1.0;
      return f.cvss.adjustedScore * weight * environmentalMultiplier;
    });

    const totalWeightedScore = weightedScores.reduce((sum, score) => sum + score, 0);
    const averageScore = totalWeightedScore / findings.length;
    
    // Apply finding count multiplier (more findings = higher risk)
    const countMultiplier = Math.min(1 + (findings.length - 1) * 0.1, 2.0);
    const finalScore = Math.min(averageScore * countMultiplier, 10.0);

    const aggregatedRisk = {
      riskScore: parseFloat(finalScore.toFixed(1)),
      riskLevel: this.classifyRiskLevel(finalScore),
      confidence: this.calculateConfidence(findings),
      findingsBreakdown: this.generateFindingsBreakdown(findings),
      // 🤖 AI will provide detailed analysis of this aggregated risk
      aiAnalysisRequired: true,
      environmentalContext: context
    };

    console.log(`🔧 STATIC: Final risk score: ${aggregatedRisk.riskScore} (${aggregatedRisk.riskLevel})`);
    return aggregatedRisk;
  }

  // Helper methods for static analysis
  inferSystemType(context) {
    if (context.handlesFinancialData) return 'financial-system';
    if (context.handlesHealthData) return 'healthcare-system';
    if (context.handlesPersonalData) return 'data-processing-system';
    return 'business-application';
  }

  identifyRiskAmplifiers(context) {
    const amplifiers = [];
    if (context.isInternetFacing) amplifiers.push('public-exposure');
    if (context.handlesPersonalData) amplifiers.push('personal-data');
    if (context.isProduction) amplifiers.push('production-environment');
    if (context.regulatoryRequirements?.length > 0) amplifiers.push('regulatory-compliance');
    return amplifiers;
  }

  extractBusinessContext(context) {
    return {
      industry: this.inferIndustry(context),
      dataTypes: this.identifyDataTypes(context),
      riskTolerance: this.assessRiskTolerance(context),
      complianceRequirements: context.regulatoryRequirements || []
    };
  }

  inferLanguage(filePath) {
    if (!filePath) return 'unknown';
    const ext = filePath.split('.').pop()?.toLowerCase();
    const langMap = {
      'js': 'javascript', 'py': 'python', 'java': 'java',
      'php': 'php', 'rb': 'ruby', 'go': 'go', 'cs': 'csharp',
      'cpp': 'cpp', 'c': 'c', 'ts': 'typescript'
    };
    return langMap[ext] || 'unknown';
  }

  inferFramework(finding) {
    const code = finding.extractedCode || finding.extra?.lines || '';
    if (code.includes('express') || code.includes('app.')) return 'express';
    if (code.includes('django') || code.includes('from django')) return 'django';
    if (code.includes('spring') || code.includes('@Controller')) return 'spring';
    return 'generic';
  }

  assessLegacyStatus(finding, context) {
    return context.isLegacy || false;
  }

  assessTechnicalComplexity(cweInfo) {
    const complexityMap = {
      'SQL Injection': 'high',
      'OS Command Injection': 'high',
      'Deserialization of Untrusted Data': 'very-high',
      'Cross-Site Scripting (XSS)': 'medium',
      'Hardcoded Credentials': 'low',
      'Information Exposure': 'low'
    };
    return complexityMap[cweInfo.name] || 'medium';
  }

  identifyBusinessImpactArea(cweInfo, context) {
    if (context.handlesFinancialData) return 'financial-operations';
    if (context.handlesPersonalData) return 'data-privacy';
    if (context.isInternetFacing) return 'customer-facing';
    return 'internal-operations';
  }

  calculateUrgencyIndicators(finding, context) {
    const indicators = [];
    if (context.isProduction) indicators.push('production-system');
    if (context.isInternetFacing) indicators.push('public-exposure');
    if (context.regulatoryRequirements?.length > 0) indicators.push('compliance-critical');
    return indicators;
  }

  // Business impact assessment methods
  getBaseBusinessImpact(cvssScore) {
    if (cvssScore >= 9.0) return { level: 4, category: 'Critical' };
    if (cvssScore >= 7.0) return { level: 3, category: 'High' };
    if (cvssScore >= 4.0) return { level: 2, category: 'Medium' };
    return { level: 1, category: 'Low' };
  }

  calculateContextMultiplier(context) {
    let multiplier = 1.0;
    
    if (context.isProduction) multiplier *= 1.5;
    if (context.isInternetFacing) multiplier *= 1.3;
    if (context.handlesPersonalData) multiplier *= 1.4;
    if (context.handlesFinancialData) multiplier *= 1.6;
    if (context.handlesHealthData) multiplier *= 1.8;
    if (context.regulatoryRequirements?.includes('PCI-DSS')) multiplier *= 1.5;
    if (context.regulatoryRequirements?.includes('HIPAA')) multiplier *= 1.7;
    if (context.regulatoryRequirements?.includes('GDPR')) multiplier *= 1.4;
    
    return Math.min(multiplier, 3.0);
  }

  classifyBusinessImpact(adjustedImpact) {
    if (adjustedImpact >= 8) return 'Critical';
    if (adjustedImpact >= 6) return 'High';
    if (adjustedImpact >= 3) return 'Medium';
    return 'Low';
  }

  generateBusinessImpactDescription(finding, context, adjustedImpact) {
    const cweId = finding.cwe?.id || finding.cwe;
    const systemType = this.inferSystemType(context);
    
    const impactTemplates = {
      'CWE-89': `SQL injection vulnerability could allow unauthorized database access in ${systemType}`,
      'CWE-798': `Hardcoded credentials create authentication bypass risk in ${systemType}`,
      'CWE-79': `Cross-site scripting vulnerability could compromise user sessions in ${systemType}`,
      'default': `Security vulnerability poses ${this.classifyBusinessImpact(adjustedImpact).toLowerCase()} risk to ${systemType}`
    };
    
    return impactTemplates[cweId] || impactTemplates.default;
  }

  estimateFinancialRisk(adjustedImpact, context) {
    const baseRisk = adjustedImpact * 100000; // Base $100K per impact point
    const industryMultiplier = context.handlesFinancialData ? 2.0 : 1.0;
    return Math.round(baseRisk * industryMultiplier);
  }

  assessReputationalRisk(finding, context) {
    if (context.isInternetFacing && context.handlesPersonalData) return 'High';
    if (context.isProduction) return 'Medium';
    return 'Low';
  }

  // Exploitability assessment
  assessExploitability(finding, context) {
    const baseExploitability = 5.0; // Default medium exploitability
    let multiplier = 1.0;
    
    if (context.isInternetFacing) multiplier *= 1.5;
    if (context.hasNetworkAccess && !context.isInternetFacing) multiplier *= 1.2;
    
    const adjustedScore = baseExploitability * multiplier;
    
    return {
      score: Math.min(adjustedScore, 10.0),
      level: adjustedScore >= 7 ? 'High' : adjustedScore >= 4 ? 'Medium' : 'Low',
      factors: {
        networkAccess: context.isInternetFacing,
        authenticationRequired: this.requiresAuthentication(finding)
      }
    };
  }

  requiresAuthentication(finding) {
    const authPatterns = ['login', 'auth', 'session', 'token'];
    const code = finding.extractedCode || finding.extra?.lines || '';
    return authPatterns.some(pattern => code.toLowerCase().includes(pattern));
  }

  // Remediation guidance
  generateRemediationGuidance(cweInfo, context) {
    const templates = {
      'CWE-798': {
        immediate: 'Remove hardcoded credentials and rotate affected passwords',
        shortTerm: 'Implement environment variables and secure credential storage',
        longTerm: 'Deploy enterprise secrets management system'
      },
      'CWE-89': {
        immediate: 'Implement input validation and parameterized queries',
        shortTerm: 'Deploy database access controls and monitoring',
        longTerm: 'Implement comprehensive input sanitization framework'
      },
      'CWE-79': {
        immediate: 'Implement output encoding and input validation',
        shortTerm: 'Deploy Content Security Policy (CSP)',
        longTerm: 'Implement comprehensive XSS prevention framework'
      },
      'CWE-78': {
        immediate: 'Sanitize command inputs or use safer APIs',
        shortTerm: 'Implement command injection prevention controls',
        longTerm: 'Migrate to secure programming patterns'
      },
      'default': {
        immediate: 'Apply security patches and implement temporary mitigations',
        shortTerm: 'Implement proper security controls for this vulnerability type',
        longTerm: 'Integrate security testing into development lifecycle'
      }
    };
    
    const guidance = templates[cweInfo.id] || templates.default;
    return {
      ...guidance,
      aiEnhancementNeeded: true // Flag for AI to provide detailed plans
    };
  }

  assessRemediationComplexity(finding, context) {
    let complexity = 3; // Base medium complexity
    
    if (context.isLegacy) complexity += 2;
    if (context.isProduction) complexity += 1;
    if (context.hasNetworkAccess) complexity += 1;
    
    return {
      score: Math.min(complexity, 10),
      level: complexity >= 7 ? 'High' : complexity >= 4 ? 'Medium' : 'Low',
      factors: {
        legacySystem: context.isLegacy,
        productionDeployment: context.isProduction,
        networkDependencies: context.hasNetworkAccess
      }
    };
  }

  // Environmental factors analysis
  analyzeEnvironmentalFactors(context) {
    return {
      deployment: {
        type: context.isInternetFacing ? 'internet-facing' : 'internal',
        riskMultiplier: context.isInternetFacing ? 1.5 : 1.0
      },
      dataClassification: {
        level: this.classifyDataSensitivity(context),
        riskMultiplier: this.getDataSensitivityMultiplier(context)
      },
      systemCriticality: {
        level: context.isProduction ? 'critical' : 'standard',
        riskMultiplier: context.isProduction ? 1.3 : 0.8
      }
    };
  }

  // Compliance mapping
  mapToCompliance(cweInfo, context) {
    const mappings = [];
    
    mappings.push({
      framework: 'OWASP Top 10',
      category: this.mapToOWASP(cweInfo.category),
      severity: 'Required'
    });
    
    if (context.regulatoryRequirements?.includes('PCI-DSS')) {
      mappings.push({
        framework: 'PCI-DSS',
        requirement: this.mapToPCIDSS(cweInfo.id),
        severity: 'Critical'
      });
    }
    
    return mappings;
  }

  mapToPCIDSS(cweId) {
    const pciMapping = {
      'CWE-798': 'Requirement 8.2 - User Authentication',
      'CWE-89': 'Requirement 6.5 - Application Vulnerabilities',
      'CWE-79': 'Requirement 6.5 - Application Vulnerabilities',
      'default': 'Requirement 6.5 - Application Vulnerabilities'
    };
    return pciMapping[cweId] || pciMapping.default;
  }

  // Data sensitivity classification
  classifyDataSensitivity(context) {
    if (context.handlesHealthData) return 'highly-sensitive';
    if (context.handlesFinancialData || context.handlesPersonalData) return 'sensitive';
    return 'standard';
  }

  getDataSensitivityMultiplier(context) {
    if (context.handlesHealthData) return 1.8;
    if (context.handlesFinancialData) return 1.6;
    if (context.handlesPersonalData) return 1.4;
    return 1.0;
  }

  // Risk level classification
  classifyRiskLevel(score) {
    if (score >= 8.0) return 'Critical';
    if (score >= 6.0) return 'High';
    if (score >= 4.0) return 'Medium';
    if (score >= 2.0) return 'Low';
    return 'Minimal';
  }

  // Confidence calculation
  calculateConfidence(findings) {
    const severityConsistency = this.assessSeverityConsistency(findings);
    const findingCount = findings.length;
    
    if (findingCount >= 10 && severityConsistency > 0.8) return 'Very High';
    if (findingCount >= 5 && severityConsistency > 0.6) return 'High';
    if (findingCount >= 2) return 'Medium';
    return 'Low';
  }

  generateFindingsBreakdown(findings) {
    const breakdown = { Critical: 0, High: 0, Medium: 0, Low: 0 };
    findings.forEach(f => {
      if (breakdown.hasOwnProperty(f.severity)) {
        breakdown[f.severity]++;
      }
    });
    return breakdown;
  }

  assessSeverityConsistency(findings) {
    if (findings.length <= 1) return 1.0;
    
    const severityLevels = findings.map(f => getSeverityLevel(f.severity));
    const avgLevel = severityLevels.reduce((sum, level) => sum + level, 0) / severityLevels.length;
    const variance = severityLevels.reduce((sum, level) => sum + Math.pow(level - avgLevel, 2), 0) / severityLevels.length;
    
    return Math.max(0, 1 - (variance / 4));
  }

  // Industry and context inference
  inferIndustry(context) {
    if (context.handlesFinancialData) return 'financial-services';
    if (context.handlesHealthData) return 'healthcare';
    if (context.regulatoryRequirements?.includes('GDPR')) return 'data-processing';
    return 'general-business';
  }

  identifyDataTypes(context) {
    const types = [];
    if (context.handlesPersonalData) types.push('personal-data');
    if (context.handlesFinancialData) types.push('financial-data');
    if (context.handlesHealthData) types.push('health-data');
    return types.length > 0 ? types : ['business-data'];
  }

  assessRiskTolerance(context) {
    if (context.handlesHealthData || context.handlesFinancialData) return 'low';
    if (context.isProduction && context.isInternetFacing) return 'medium';
    return 'standard';
  }
}

/**
 * CVSS Calculator for environmental scoring
 * 🔧 STATIC: Mathematical CVSS calculations
 */
class CVSSCalculator {
  calculate(finding, context) {
    const baseScore = this.getBaseScore(finding);
    const environmentalScore = this.calculateEnvironmentalScore(baseScore, context);
    const adjustedScore = Math.min(baseScore * environmentalScore, 10.0);
    
    console.log(`🔧 STATIC: CVSS calculation - Base: ${baseScore}, Environmental: ${environmentalScore}, Final: ${adjustedScore}`);
    
    return {
      baseScore: parseFloat(baseScore.toFixed(1)),
      environmentalScore: parseFloat(environmentalScore.toFixed(2)),
      adjustedScore: parseFloat(adjustedScore.toFixed(1)),
      vector: this.generateCVSSVector(finding, context),
      severity: classifySeverity(adjustedScore)
    };
  }

  getBaseScore(finding) {
    // Try to extract from finding metadata first
    if (finding.cvss?.baseScore) return finding.cvss.baseScore;
    if (finding.cvssScore) return finding.cvssScore;
    
    // Fallback to CWE-based scoring
    const cweId = finding.cwe?.id || finding.cwe;
    return this.getCWEBaseScore(cweId);
  }

  getCWEBaseScore(cweId) {
    const cweScores = {
      'CWE-89': 9.8,  // SQL Injection
      'CWE-78': 9.8,  // Command Injection  
      'CWE-502': 9.8, // Deserialization
      'CWE-94': 9.3,  // Code Injection
      'CWE-918': 8.5, // SSRF
      'CWE-352': 8.8, // CSRF
      'CWE-611': 8.2, // XXE
      'CWE-434': 8.1, // File Upload
      'CWE-319': 8.2, // Cleartext Transmission
      'CWE-798': 7.8, // Hardcoded Credentials
      'CWE-22': 7.5,  // Path Traversal
      'CWE-327': 7.4, // Weak Crypto
      'CWE-134': 7.3, // Format String
      'CWE-287': 7.0, // Authentication
      'CWE-863': 7.5, // Authorization
      'CWE-338': 6.8, // Weak PRNG
      'CWE-20': 6.5,  // Input Validation
      'CWE-613': 6.3, // Session Expiration
      'CWE-79': 6.1,  // XSS
      'CWE-200': 5.3  // Information Disclosure
    };
    
    return cweScores[cweId] || 5.0; // Default medium score
  }

  calculateEnvironmentalScore(baseScore, context) {
    let multiplier = 1.0;
    
    // Confidentiality, Integrity, Availability requirements
    if (context.handlesFinancialData) multiplier *= 1.3;
    if (context.handlesPersonalData) multiplier *= 1.2;
    if (context.handlesHealthData) multiplier *= 1.4;
    
    // Modified attack vector based on deployment
    if (context.isInternetFacing) multiplier *= 1.4;
    if (context.hasNetworkAccess && !context.isInternetFacing) multiplier *= 1.1;
    
    // Modified attack complexity based on environment
    if (context.isProduction) multiplier *= 1.2;
    if (context.isLegacy) multiplier *= 0.9;
    
    return Math.min(multiplier, 2.0); // Cap environmental multiplier
  }

  generateCVSSVector(finding, context) {
    // Simplified CVSS vector generation
    const av = context.isInternetFacing ? 'N' : 'A'; // Network vs Adjacent
    const ac = 'L'; // Attack Complexity - assume Low
    const pr = 'N'; // Privileges Required - assume None
    const ui = 'N'; // User Interaction - assume None
    const s = 'U';  // Scope - assume Unchanged
    const c = context.handlesPersonalData ? 'H' : 'L'; // Confidentiality impact
    const i = 'L';  // Integrity impact
    const a = 'N';  // Availability impact
    
    return `CVSS:3.1/AV:${av}/AC:${ac}/PR:${pr}/UI:${ui}/S:${s}/C:${c}/I:${i}/A:${a}`;
  }
}

module.exports = { SecurityClassificationSystem };