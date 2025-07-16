/**
 * Enterprise Security Classification & Scoring System
 * 
 * PURPOSE: Transform raw security scanner findings into standardized,
 * business-ready vulnerability assessments using industry standards.
 * 
 * STANDARDS INTEGRATION:
 * - CWE (Common Weakness Enumeration) → Precise weakness categorization
 * - CVSS (Common Vulnerability Scoring System) → Severity scoring (0.0-10.0)
 * - OWASP Top 10 → Business risk category mapping
 * 
 * DESIGNED FOR: Enterprise environments requiring compliance and standardization
 */

export class SecurityClassificationSystem {
  
  constructor() {
    this.initializeClassificationDatabase();
    this.initializeScoringEngine();
    this.initializeMappingLogic();
  }

  /**
   * ================================================================
   * SECTION 1: CLASSIFICATION DATABASE
   * Maps scanner findings to security standards (CWE, OWASP, CVSS)
   * ================================================================
   */
  
  initializeClassificationDatabase() {
    // Comprehensive mapping: Scanner Rule ID → Security Standards
    this.securityStandards = {
      
      // === INJECTION VULNERABILITIES ===
      'python.lang.security.audit.formatted-sql-query.formatted-sql-query': {
        cwe: {
          id: 'CWE-89',
          name: 'SQL Injection',
          description: 'Improper neutralization of special elements used in SQL commands'
        },
        owasp: {
          category: 'A03:2021',
          title: 'Injection',
          businessRisk: 'Data breach, unauthorized access, data manipulation'
        },
        cvss: {
          baseScore: 8.1,
          vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N',
          reasoning: 'Network accessible, low complexity, requires low privileges'
        }
      },
      
      'javascript.lang.security.detect-child-process.detect-child-process': {
        cwe: {
          id: 'CWE-78',
          name: 'OS Command Injection',
          description: 'Improper neutralization of special elements used in OS commands'
        },
        owasp: {
          category: 'A03:2021',
          title: 'Injection',
          businessRisk: 'System compromise, data theft, service disruption'
        },
        cvss: {
          baseScore: 8.2,
          vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L',
          reasoning: 'Remote code execution capability'
        }
      },
      
      // === CRYPTOGRAPHIC FAILURES ===
      'python.lang.security.audit.md5-used-as-password.md5-used-as-password': {
        cwe: {
          id: 'CWE-327',
          name: 'Broken or Risky Crypto Algorithm',
          description: 'Use of a broken or risky cryptographic algorithm'
        },
        owasp: {
          category: 'A02:2021',
          title: 'Cryptographic Failures',
          businessRisk: 'Password cracking, authentication bypass'
        },
        cvss: {
          baseScore: 7.5,
          vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
          reasoning: 'High confidentiality impact due to weak hashing'
        }
      },
      
      'python.lang.security.audit.weak-random.weak-random': {
        cwe: {
          id: 'CWE-338',
          name: 'Weak PRNG',
          description: 'Use of cryptographically weak pseudo-random number generator'
        },
        owasp: {
          category: 'A02:2021',
          title: 'Cryptographic Failures',
          businessRisk: 'Predictable tokens, session hijacking'
        },
        cvss: {
          baseScore: 5.9,
          vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N',
          reasoning: 'High attack complexity but potential for token prediction'
        }
      },
      
      // === AUTHENTICATION FAILURES ===
      'python.lang.security.audit.hardcoded-password.hardcoded-password': {
        cwe: {
          id: 'CWE-798',
          name: 'Hardcoded Credentials',
          description: 'Use of hard-coded credentials for authentication'
        },
        owasp: {
          category: 'A07:2021',
          title: 'Identification and Authentication Failures',
          businessRisk: 'Unauthorized access, credential exposure'
        },
        cvss: {
          baseScore: 9.8,
          vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
          reasoning: 'Critical - immediate access without authentication'
        }
      },
      
      // === BROKEN ACCESS CONTROL ===
      'python.lang.security.audit.path-traversal.path-traversal': {
        cwe: {
          id: 'CWE-22',
          name: 'Path Traversal',
          description: 'Improper limitation of pathname to restricted directory'
        },
        owasp: {
          category: 'A01:2021',
          title: 'Broken Access Control',
          businessRisk: 'Unauthorized file access, information disclosure'
        },
        cvss: {
          baseScore: 6.4,
          vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N',
          reasoning: 'High confidentiality impact, requires low privileges'
        }
      },
      
      // === XSS VULNERABILITIES ===
      'javascript.browser.security.insecure-document-method.insecure-document-method': {
        cwe: {
          id: 'CWE-79',
          name: 'Cross-Site Scripting',
          description: 'Improper neutralization of input during web page generation'
        },
        owasp: {
          category: 'A03:2021',
          title: 'Injection',
          businessRisk: 'Session hijacking, data theft, malicious actions'
        },
        cvss: {
          baseScore: 6.1,
          vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
          reasoning: 'Network accessible, requires user interaction, scope change'
        }
      }
    };
  }

  /**
   * ================================================================
   * SECTION 2: CVSS SCORING ENGINE
   * Calculates severity scores using CVSS 3.1 methodology
   * ================================================================
   */
  
  initializeScoringEngine() {
    // CVSS 3.1 Base Score Calculation Logic
    this.cvssMetrics = {
      // Attack Vector (AV)
      attackVector: {
        'Network': { value: 0.85, description: 'Remotely exploitable' },
        'Adjacent': { value: 0.62, description: 'Adjacent network access' },
        'Local': { value: 0.55, description: 'Local access required' },
        'Physical': { value: 0.20, description: 'Physical access required' }
      },
      
      // Attack Complexity (AC)
      attackComplexity: {
        'Low': { value: 0.77, description: 'Specialized conditions not required' },
        'High': { value: 0.44, description: 'Specialized conditions required' }
      },
      
      // Privileges Required (PR)
      privilegesRequired: {
        'None': { value: 0.85, description: 'No privileges required' },
        'Low': { value: 0.62, description: 'Low-level privileges required' },
        'High': { value: 0.27, description: 'High-level privileges required' }
      },
      
      // User Interaction (UI)
      userInteraction: {
        'None': { value: 0.85, description: 'No user interaction required' },
        'Required': { value: 0.62, description: 'User interaction required' }
      },
      
      // Impact Metrics (Confidentiality, Integrity, Availability)
      impact: {
        'None': { value: 0.0, description: 'No impact' },
        'Low': { value: 0.22, description: 'Limited impact' },
        'High': { value: 0.56, description: 'Total impact' }
      }
    };
  }

  /**
   * ================================================================
   * SECTION 3: MAPPING LOGIC
   * Core algorithms for finding classification and scoring
   * ================================================================
   */
  
  initializeMappingLogic() {
    // CWE to OWASP Top 10 mapping for comprehensive coverage
    this.cweToOwaspMapping = {
      // Injection
      'CWE-89': 'A03:2021',  // SQL Injection
      'CWE-78': 'A03:2021',  // Command Injection
      'CWE-79': 'A03:2021',  // XSS
      'CWE-94': 'A03:2021',  // Code Injection
      
      // Cryptographic Failures
      'CWE-327': 'A02:2021', // Broken Crypto
      'CWE-338': 'A02:2021', // Weak Random
      'CWE-319': 'A02:2021', // Cleartext Transmission
      'CWE-326': 'A02:2021', // Inadequate Encryption
      
      // Authentication Failures
      'CWE-798': 'A07:2021', // Hardcoded Credentials
      'CWE-287': 'A07:2021', // Improper Authentication
      'CWE-613': 'A07:2021', // Insufficient Session Expiration
      
      // Broken Access Control
      'CWE-22': 'A01:2021',  // Path Traversal
      'CWE-200': 'A01:2021', // Information Exposure
      'CWE-863': 'A01:2021', // Incorrect Authorization
      
      // Security Misconfiguration
      'CWE-16': 'A05:2021',  // Configuration
      'CWE-209': 'A05:2021', // Information Exposure through Error Messages
      
      // Vulnerable Components
      'CWE-1104': 'A06:2021', // Use of Unmaintained Third Party Components
      
      // Software Integrity Failures
      'CWE-502': 'A08:2021', // Deserialization of Untrusted Data
      
      // Security Logging Failures
      'CWE-778': 'A09:2021', // Insufficient Logging
      
      // SSRF
      'CWE-918': 'A10:2021'  // Server-Side Request Forgery
    };
  }

  /**
   * ================================================================
   * SECTION 4: CORE CLASSIFICATION METHODS
   * Transform scanner findings into standardized classifications
   * ================================================================
   */
  
  /**
   * Maps a scanner finding to security standards
   * @param {Object} scannerFinding - Raw finding from security scanner
   * @returns {Object} Standardized classification
   */
  classifyFinding(scannerFinding) {
    // DEBUG: Log raw finding before processing
    console.log("Raw finding before processing:", JSON.stringify(scannerFinding, null, 2));
    
    const ruleId = scannerFinding.check_id || scannerFinding.rule_id;
    
    // Step 1: Direct mapping from database
    let classification = this.securityStandards[ruleId];
    
    // Step 2: Fallback classification if not in database
    if (!classification) {
      classification = this.generateFallbackClassification(scannerFinding);
    }
    
    // Step 3: Environmental adjustment
    const adjustedScore = this.adjustCVSSForEnvironment(
      classification.cvss.baseScore, 
      scannerFinding.context
    );
    
    return {
      // Core identification
      id: this.generateFindingId(scannerFinding),
      ruleId: ruleId,
      title: classification.cwe.name,
      
      // CWE Classification
      cwe: classification.cwe,
      
      // CVSS Scoring
      cvss: {
        baseScore: classification.cvss.baseScore,
        adjustedScore: adjustedScore,
        vector: classification.cvss.vector,
        severity: this.getCVSSSeverityLevel(adjustedScore),
        reasoning: classification.cvss.reasoning
      },
      
      // OWASP Top 10 Mapping
      owasp: classification.owasp,
      owaspCategory: `${classification.owasp.category} – ${classification.owasp.title}`,
      
      // Standard fields for UI compatibility
      severity: this.getCVSSSeverityLevel(adjustedScore),
      description: classification.cwe.description || 
                   scannerFinding.message || 
                   this.generateFallbackDescription(ruleId),
      remediation: `Address ${classification.cwe.name}: ${classification.owasp.businessRisk}`,
      impact: classification.owasp.businessRisk,
      line: scannerFinding.start?.line || 0,
      codeSnippet: this.extractRealCodeSnippet(scannerFinding),
      confidence: this.calculateClassificationConfidence(scannerFinding),
      
      // Raw scanner data
      scannerData: {
        tool: scannerFinding.tool || 'semgrep',
        severity: scannerFinding.severity,
        confidence: scannerFinding.extra?.severity || 'MEDIUM',
        location: {
          file: scannerFinding.path,
          line: scannerFinding.start?.line,
          column: scannerFinding.start?.col
        },
        codeSnippet: this.extractRealCodeSnippet(scannerFinding)
      },
      
      // Metadata
      classification: {
        timestamp: new Date().toISOString(),
        version: '1.0',
        confidence: this.calculateClassificationConfidence(scannerFinding)
      }
    };
  }

  /**
   * ================================================================
   * SECTION 5: CVSS SCORING ALGORITHMS
   * Calculate and adjust CVSS scores based on context
   * ================================================================
   */
  
  /**
   * Adjusts CVSS base score based on environmental factors
   * @param {number} baseScore - Original CVSS base score
   * @param {Object} context - Environmental context
   * @returns {number} Adjusted CVSS score
   */
  adjustCVSSForEnvironment(baseScore, context = {}) {
    let adjustedScore = baseScore;
    
    // Environmental adjustments
    if (context.isProduction) {
      adjustedScore += 0.5; // Production systems are higher risk
    }
    
    if (context.hasNetworkAccess) {
      adjustedScore += 0.3; // Network accessible increases risk
    }
    
    if (context.handlesPersonalData) {
      adjustedScore += 0.4; // PII handling increases impact
    }
    
    if (context.isLegacySystem) {
      adjustedScore += 0.2; // Legacy systems harder to patch
    }
    
    if (context.hasHighAvailabilityRequirement) {
      adjustedScore += 0.3; // High availability systems
    }
    
    // Regulatory compliance adjustments
    if (context.regulatoryRequirements?.includes('PCI DSS')) {
      adjustedScore += 0.5;
    }
    
    if (context.regulatoryRequirements?.includes('HIPAA')) {
      adjustedScore += 0.6;
    }
    
    // Cap at 10.0
    return Math.min(adjustedScore, 10.0);
  }

  /**
   * Converts CVSS score to severity level
   * @param {number} score - CVSS score (0.0-10.0)
   * @returns {string} Severity level
   */
  getCVSSSeverityLevel(score) {
    if (score >= 9.0) return 'Critical';
    if (score >= 7.0) return 'High';
    if (score >= 4.0) return 'Medium';
    if (score >= 0.1) return 'Low';
    return 'None';
  }

  /**
   * ================================================================
   * SECTION 6: DUPLICATE HANDLING & AGGREGATION
   * Handle overlapping findings and calculate risk scores
   * ================================================================
   */
  
  /**
   * Identifies and handles duplicate or overlapping findings
   * @param {Array} findings - Array of classified findings
   * @returns {Array} Deduplicated findings
   */
  deduplicateFindings(findings) {
    const groups = new Map();
    
    // Group findings by similarity
    findings.forEach(finding => {
      const key = this.generateDeduplicationKey(finding);
      
      if (!groups.has(key)) {
        groups.set(key, []);
      }
      groups.get(key).push(finding);
    });
    
    // For each group, keep the highest severity finding
    const deduplicated = [];
    
    groups.forEach(group => {
      if (group.length === 1) {
        deduplicated.push(group[0]);
      } else {
        // Multiple findings - merge intelligently
        const merged = this.mergeOverlappingFindings(group);
        deduplicated.push(merged);
      }
    });
    
    return deduplicated;
  }

  /**
   * Generates a key for deduplication logic
   * @param {Object} finding - Classified finding
   * @returns {string} Deduplication key
   */
  generateDeduplicationKey(finding) {
    // Group by: CWE + File + approximate line range
    const lineRange = Math.floor(finding.scannerData.location.line / 5) * 5;
    return `${finding.cwe.id}:${finding.scannerData.location.file}:${lineRange}`;
  }

  /**
   * Merges overlapping findings intelligently
   * @param {Array} overlappingFindings - Findings that overlap
   * @returns {Object} Merged finding
   */
  mergeOverlappingFindings(overlappingFindings) {
    // Take the highest CVSS score
    const highestSeverity = overlappingFindings.reduce((max, current) => 
      current.cvss.adjustedScore > max.cvss.adjustedScore ? current : max
    );
    
    // Merge scanner data
    const allScanners = overlappingFindings.map(f => f.scannerData.tool);
    const uniqueScanners = [...new Set(allScanners)];
    
    return {
      ...highestSeverity,
      scannerData: {
        ...highestSeverity.scannerData,
        detectedBy: uniqueScanners,
        confirmationCount: overlappingFindings.length
      },
      classification: {
        ...highestSeverity.classification,
        merged: true,
        sourceFindings: overlappingFindings.length
      }
    };
  }

  /**
   * ================================================================
   * SECTION 7: RISK AGGREGATION
   * Calculate overall risk scores for software components
   * ================================================================
   */
  
  /**
   * Aggregates findings into component-level risk score
   * @param {Array} classifiedFindings - Array of classified findings
   * @param {Object} componentContext - Context about the software component
   * @returns {Object} Aggregated risk assessment
   */
  aggregateRiskScore(classifiedFindings, componentContext = {}) {
    const deduplicatedFindings = this.deduplicateFindings(classifiedFindings);
    
    // Calculate base risk using weighted severity
    const severityWeights = {
      'Critical': 25,
      'High': 15,
      'Medium': 8,
      'Low': 3,
      'None': 0
    };
    
    let totalRiskScore = 0;
    const severityCounts = { Critical: 0, High: 0, Medium: 0, Low: 0, None: 0 };
    const owaspCategories = new Set();
    const cweTypes = new Set();
    
    deduplicatedFindings.forEach(finding => {
      const severity = finding.cvss.severity;
      const weight = severityWeights[severity];
      
      // Base score contribution
      totalRiskScore += weight;
      
      // Count by severity
      severityCounts[severity]++;
      
      // Track coverage
      owaspCategories.add(finding.owasp.category);
      cweTypes.add(finding.cwe.id);
    });
    
    // Apply multipliers for systemic risk
    const owaspCoverageMultiplier = Math.min(owaspCategories.size * 0.1, 0.5);
    const diversityMultiplier = Math.min(cweTypes.size * 0.05, 0.3);
    
    totalRiskScore *= (1 + owaspCoverageMultiplier + diversityMultiplier);
    
    // Environmental risk adjustments
    if (componentContext.isInternetFacing) {
      totalRiskScore *= 1.3;
    }
    
    if (componentContext.handlesFinancialData) {
      totalRiskScore *= 1.4;
    }
    
    if (componentContext.hasPrivilegedAccess) {
      totalRiskScore *= 1.2;
    }
    
    // Cap at 100
    const finalScore = Math.min(totalRiskScore, 100);
    
    return {
      // Overall assessment
      riskScore: finalScore,
      riskLevel: this.getRiskLevel(finalScore),
      findings: deduplicatedFindings,
      
      // Detailed breakdown
      summary: {
        total: deduplicatedFindings.length,
        critical: severityCounts.Critical,
        high: severityCounts.High,
        medium: severityCounts.Medium,
        low: severityCounts.Low,
        bySeverity: severityCounts,
        byOWASP: this.groupFindingsByOWASP(deduplicatedFindings),
        byCWE: this.groupFindingsByCWE(deduplicatedFindings),
        owaspCategories: [...owaspCategories]
      },
      
      // Risk factors
      riskFactors: {
        diversityRisk: cweTypes.size,
        owaspCoverage: owaspCategories.size,
        environmentalRisk: this.assessEnvironmentalRisk(componentContext)
      },
      
      // Compliance implications
      compliance: {
        owaspTop10Coverage: [...owaspCategories],
        highestCVSS: Math.max(...deduplicatedFindings.map(f => f.cvss.adjustedScore)),
        requiresImmediate: deduplicatedFindings.filter(f => f.cvss.severity === 'Critical').length > 0
      },
      
      // Metadata
      assessment: {
        timestamp: new Date().toISOString(),
        findings: deduplicatedFindings,
        methodology: 'CVSS 3.1 + OWASP + Environmental Factors'
      }
    };
  }

  /**
   * ================================================================
   * SECTION 8: UTILITY METHODS
   * Supporting functions for classification and scoring
   * ================================================================
   */
  
  getRiskLevel(score) {
    if (score >= 80) return 'Critical';
    if (score >= 60) return 'High';
    if (score >= 40) return 'Medium';
    if (score >= 20) return 'Low';
    return 'Minimal';
  }

  groupFindingsByOWASP(findings) {
    const groups = {};
    findings.forEach(finding => {
      const category = finding.owasp.category;
      if (!groups[category]) {
        groups[category] = [];
      }
      groups[category].push(finding);
    });
    return groups;
  }

  groupFindingsByCWE(findings) {
    const groups = {};
    findings.forEach(finding => {
      const cwe = finding.cwe.id;
      if (!groups[cwe]) {
        groups[cwe] = [];
      }
      groups[cwe].push(finding);
    });
    return groups;
  }

  assessEnvironmentalRisk(context) {
    let risk = 0;
    if (context.isInternetFacing) risk += 20;
    if (context.handlesPersonalData) risk += 15;
    if (context.hasPrivilegedAccess) risk += 10;
    if (context.isLegacySystem) risk += 10;
    return Math.min(risk, 50);
  }

  generateFindingId(scannerFinding) {
    const content = `${scannerFinding.check_id}:${scannerFinding.path}:${scannerFinding.start?.line}`;
    // Simple hash function for browser compatibility
    let hash = 0;
    for (let i = 0; i < content.length; i++) {
      const char = content.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32bit integer
    }
    return Math.abs(hash).toString(16).substring(0, 8);
  }

  // Extract meaningful code snippet with comprehensive field checking
  extractRealCodeSnippet(finding) {
    console.log("Extracting code from:", {
      extractedCode: finding.extractedCode,
      extraLines: finding.extra?.lines,
      extraRendered: finding.extra?.rendered_text,
      message: finding.message,
      allExtraKeys: Object.keys(finding.extra || {}),
      allFindingKeys: Object.keys(finding)
    });

    // Try fields in priority order - backend provides extractedCode
    if (finding.extractedCode) {
      console.log("Using extractedCode:", finding.extractedCode);
      return finding.extractedCode.trim();
    }
    
    if (finding.extra?.lines) {
      console.log("Using extra.lines:", finding.extra.lines);
      return finding.extra.lines.trim();
    }
    
    if (finding.extra?.rendered_text) {
      console.log("Using extra.rendered_text:", finding.extra.rendered_text);
      return finding.extra.rendered_text.trim();
    }
    
    if (finding.extra?.dataflow_trace?.taint_source?.content) {
      console.log("Using dataflow_trace content:", finding.extra.dataflow_trace.taint_source.content);
      return finding.extra.dataflow_trace.taint_source.content.trim();
    }
    
    if (finding.path && finding.start?.line) {
      return `${finding.path}:${finding.start.line}`;
    }
    
    console.log("No code found, using fallback");
    return "Code extraction failed";
  }

  calculateClassificationConfidence(scannerFinding) {
    // Base confidence from scanner
    let confidence = 0.7;
    
    if (scannerFinding.extra?.severity === 'HIGH') confidence += 0.2;
    if (scannerFinding.extra?.lines) confidence += 0.1; // Has code snippet
    
    return Math.min(confidence, 1.0);
  }

  generateFallbackClassification(scannerFinding) {
    // Intelligent fallback for unknown rules
    const ruleId = scannerFinding.check_id;
    
    // Pattern matching for classification
    if (ruleId.includes('sql') || ruleId.includes('injection')) {
      return {
        cwe: { id: 'CWE-89', name: 'SQL Injection', description: 'Improper neutralization of SQL commands' },
        owasp: { category: 'A03:2021', title: 'Injection', businessRisk: 'Data manipulation' },
        cvss: { baseScore: 7.0, vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N', reasoning: 'Estimated based on injection pattern' }
      };
    }
    
    // Default fallback
    return {
      cwe: { id: 'CWE-200', name: 'Information Exposure', description: 'Security vulnerability detected' },
      owasp: { category: 'A05:2021', title: 'Security Misconfiguration', businessRisk: 'Security weakness' },
      cvss: { baseScore: 5.0, vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N', reasoning: 'Conservative estimate for unknown vulnerability' }
    };
  }

  /**
   * Generates a fallback description when finding.message is undefined
   * @param {string} ruleId - The rule ID to generate description for
   * @returns {string} Fallback description
   */
  generateFallbackDescription(ruleId) {
    if (!ruleId) return 'Security vulnerability detected';
    
    // Extract meaningful description from rule ID
    const parts = ruleId.split('.');
    const lastPart = parts[parts.length - 1] || ruleId;
    
    // Convert kebab-case or snake_case to readable format
    const readable = lastPart
      .replace(/[-_]/g, ' ')
      .replace(/\b\w/g, l => l.toUpperCase());
    
    return `Security issue: ${readable}`;
  }
}

