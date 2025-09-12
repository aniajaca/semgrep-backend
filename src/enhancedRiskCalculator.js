// enhancedRiskCalculator.js - Security-focused version (no business/compliance)
const crypto = require('crypto');
const { CustomEnvironmentalFactorSystem } = require('./customEnvironmentalFactors');

class EnhancedRiskCalculator {
  constructor(config = {}) {
    // Initialize the custom factor system
    this.factorSystem = new CustomEnvironmentalFactorSystem();
    
    // Base configuration for risk calculation (configurable)
    this.baseConfig = {
      fileLevel: {
        // Points per severity (your specification)
        severityPoints: config.severityPoints || {
          critical: 25,
          high: 15,
          medium: 8,
          low: 3,
          info: 1
        },
        // Risk level thresholds (normalized to 0-100 scale)
        riskThresholds: config.riskThresholds || {
          critical: 80,  // 80-100: Critical
          high: 60,      // 60-79: High
          medium: 40,    // 40-59: Medium
          low: 20,       // 20-39: Low
          minimal: 0     // 0-19: Minimal
        },
        // Normalization configuration (dynamic)
        normalization: {
          maxExpectedVulns: config.maxExpectedVulns || 50,
          // Dynamically calculate max possible score
          get maxPossibleScore() {
            const points = this.parent.severityPoints;
            return points.critical * this.maxExpectedVulns;
          },
          parent: null // Will be set in constructor
        }
      },
      vulnerabilityLevel: {
        // CVSS to severity mapping
        severityThresholds: {
          critical: 9.0,  // 9.0-10.0: Critical
          high: 7.0,      // 7.0-8.9: High
          medium: 4.0,    // 4.0-6.9: Medium
          low: 0.1,       // 0.1-3.9: Low
          info: 0         // 0: Info
        },
        // Whether to allow multipliers on vulnerability level
        allowMultipliers: config.allowVulnMultipliers !== false  // Default true
      }
    };
    
    // Set parent reference for dynamic calculation
    this.baseConfig.fileLevel.normalization.parent = this.baseConfig.fileLevel;

    // CWE Category Mapping for security remediation
    this.cweCategories = {
      'injection': {
        cwes: ['CWE-89', 'CWE-78', 'CWE-90', 'CWE-94', 'CWE-1236', 'CWE-77', 'CWE-91', 'CWE-564'],
        remediation: 'Use parameterized queries, avoid dynamic command construction, validate all inputs',
        validation: 'Test with injection payloads, use automated scanning tools, code review',
        risk: 'Can lead to complete system compromise, data breach, or service disruption'
      },
      'authentication': {
        cwes: ['CWE-798', 'CWE-287', 'CWE-306', 'CWE-307', 'CWE-620', 'CWE-521', 'CWE-522'],
        remediation: 'Implement strong authentication, use secure credential storage, enforce MFA',
        validation: 'Verify authentication flows, test session management, audit access controls',
        risk: 'Unauthorized access to system and data, identity theft, privilege escalation'
      },
      'cryptography': {
        cwes: ['CWE-327', 'CWE-328', 'CWE-326', 'CWE-759', 'CWE-760', 'CWE-329', 'CWE-330'],
        remediation: 'Use modern crypto algorithms (AES-256, SHA-256+), proper key management',
        validation: 'Review crypto implementations, verify algorithm strength, test key storage',
        risk: 'Data exposure, compromised confidentiality'
      },
      'xss': {
        cwes: ['CWE-79', 'CWE-80', 'CWE-81', 'CWE-82', 'CWE-83', 'CWE-84', 'CWE-85'],
        remediation: 'Encode output, implement CSP, validate and sanitize input',
        validation: 'XSS testing with various payloads, browser security testing',
        risk: 'Client-side attacks, session hijacking, data theft, defacement'
      },
      'pathTraversal': {
        cwes: ['CWE-22', 'CWE-23', 'CWE-35', 'CWE-73', 'CWE-98', 'CWE-36', 'CWE-37'],
        remediation: 'Validate file paths, use safe APIs, implement access controls',
        validation: 'Test with traversal sequences, verify file access boundaries',
        risk: 'Unauthorized file access, information disclosure, system compromise'
      },
      'deserialization': {
        cwes: ['CWE-502', 'CWE-915', 'CWE-1279', 'CWE-134'],
        remediation: 'Avoid deserializing untrusted data, use safe formats (JSON), validate schemas',
        validation: 'Test with malicious payloads, review deserialization points',
        risk: 'Remote code execution, denial of service, privilege escalation'
      },
      'dos': {
        cwes: ['CWE-400', 'CWE-770', 'CWE-920', 'CWE-1050', 'CWE-399', 'CWE-405'],
        remediation: 'Implement rate limiting, resource controls, timeouts',
        validation: 'Load testing, resource monitoring, stress testing',
        risk: 'Service availability impact'
      },
      'accessControl': {
        cwes: ['CWE-284', 'CWE-285', 'CWE-862', 'CWE-863', 'CWE-639', 'CWE-732'],
        remediation: 'Implement proper authorization, principle of least privilege',
        validation: 'Test access controls, verify permission boundaries',
        risk: 'Unauthorized access, privilege escalation, data breach'
      }
    };

    // Cache configuration
    this.cacheConfig = {
      enabled: config.cacheEnabled !== false,  // Default true
      ttl: config.cacheTTL || 300000,         // 5 minutes default
      maxSize: config.cacheMaxSize || 100,
      useHash: true  // Use SHA-256 for cache keys
    };
    this.calculationCache = new Map();
    
    // Memoization for heavy operations (capped at 1000 entries)
    this.memoCache = new Map();
    this.memoCacheMaxSize = 1000;
  }

  /**
   * Normalize severity string
   */
  normalizeSeverity(severity) {
    if (!severity) return 'medium';
    
    const normalized = severity.toString().toLowerCase().trim();
    const validSeverities = ['critical', 'high', 'medium', 'low', 'info'];
    
    // Handle common variations
    const mappings = {
      'crit': 'critical',
      'hi': 'high',
      'med': 'medium',
      'lo': 'low',
      'information': 'info',
      'informational': 'info',
      'unknown': 'medium'
    };
    
    const mapped = mappings[normalized] || normalized;
    return validSeverities.includes(mapped) ? mapped : 'medium';
  }

  /**
   * Normalize boolean values (handles strings, numbers, etc.)
   */
  normalizeBoolean(value) {
    if (value === true || value === 1) return true;
    if (value === false || value === 0) return false;
    
    if (typeof value === 'string') {
      const lower = value.toLowerCase().trim();
      return lower === 'true' || lower === '1' || lower === 'yes';
    }
    
    return false;
  }

  /**
   * Get CWE category
   */
  getCweCategory(cwe) {
    if (!cwe) return 'unknown';
    
    const cweUpper = cwe.toUpperCase();
    for (const [category, data] of Object.entries(this.cweCategories)) {
      if (data.cwes.includes(cweUpper)) {
        return category;
      }
    }
    
    // Fallback: try to guess from CWE number ranges
    const cweNum = parseInt(cweUpper.replace('CWE-', ''));
    if (cweNum >= 77 && cweNum <= 91) return 'injection';
    if (cweNum >= 287 && cweNum <= 308) return 'authentication';
    if (cweNum >= 310 && cweNum <= 330) return 'cryptography';
    if (cweNum >= 284 && cweNum <= 285) return 'accessControl';
    
    return 'unknown';
  }

  /**
   * Calculate normalized file score (0-100 scale)
   * THIS is the single source of truth for file scoring
   */
  calculateNormalizedFileScore(severityDistribution) {
    let rawScore = 0;
    const points = this.baseConfig.fileLevel.severityPoints;
    
    Object.keys(severityDistribution).forEach(severity => {
      rawScore += (severityDistribution[severity] || 0) * (points[severity] || 0);
    });
    
    // Dynamic max score calculation
    const maxPossibleScore = this.baseConfig.fileLevel.normalization.maxPossibleScore;
    
    // Normalize to 0-100 with logarithmic scaling for outliers
    // This prevents volume alone from making everything "critical"
    let normalizedScore;
    if (rawScore <= maxPossibleScore) {
      normalizedScore = (rawScore / maxPossibleScore) * 100;
    } else {
      // Log scaling adds max 20 points for extreme outliers
      const excess = rawScore - maxPossibleScore;
      const logScale = Math.log10(excess + 1) / Math.log10(maxPossibleScore) * 20;
      normalizedScore = 80 + logScale;
    }
    
    return {
      raw: rawScore,
      normalized: Math.min(100, Math.round(normalizedScore * 10) / 10),
      scale: '0-100'
    };
  }

  /**
   * Create cache key using SHA-256 hash for stability
   */
  createCacheKey(data, context) {
    if (!this.cacheConfig.useHash) {
      return JSON.stringify({ data, context });
    }
    
    // Sort vulnerabilities for consistent hashing
    const sortedData = Array.isArray(data) 
      ? [...data].sort((a, b) => {
          const keyA = `${a.file || ''}-${a.line || 0}-${a.cwe || ''}`;
          const keyB = `${b.file || ''}-${b.line || 0}-${b.cwe || ''}`;
          return keyA.localeCompare(keyB);
        })
      : data;
    
    const payload = JSON.stringify({ data: sortedData, context });
    const hash = crypto.createHash('sha256').update(payload).digest('hex');
    return hash.substring(0, 16); // Use first 16 chars for efficiency
  }

  /**
   * Get from cache
   */
  getFromCache(key) {
    if (!this.cacheConfig.enabled) return null;
    
    const cached = this.calculationCache.get(key);
    if (!cached) return null;
    
    // Check TTL
    if (Date.now() - cached.timestamp > this.cacheConfig.ttl) {
      this.calculationCache.delete(key);
      return null;
    }
    
    return cached.data;
  }

  /**
   * Set cache
   */
  setCache(key, data) {
    if (!this.cacheConfig.enabled) return;
    
    // Enforce max size
    if (this.calculationCache.size >= this.cacheConfig.maxSize) {
      const firstKey = this.calculationCache.keys().next().value;
      this.calculationCache.delete(firstKey);
    }
    
    this.calculationCache.set(key, {
      data,
      timestamp: Date.now()
    });
  }

  /**
   * Memoized vulnerability risk calculation
   */
  memoizedVulnerabilityRisk(vulnerability, context) {
    // Create hash key for memoization
    const contextHash = crypto.createHash('sha256')
      .update(JSON.stringify(context))
      .digest('hex')
      .substring(0, 8);
    
    const key = `${vulnerability.cwe}-${vulnerability.cvss?.baseScore || 0}-${vulnerability.severity}-${contextHash}`;
    
    if (this.memoCache.has(key)) {
      return this.memoCache.get(key);
    }
    
    const result = this.calculateVulnerabilityRisk(vulnerability, context);
    
    // Cap memo cache size
    if (this.memoCache.size >= this.memoCacheMaxSize) {
      this.memoCache.clear();
    }
    
    this.memoCache.set(key, result);
    return result;
  }

  /**
   * Main entry point for file-level risk calculation
   */
  calculateFileRisk(vulnerabilities, context = {}) {
    // Check cache
    const cacheKey = this.createCacheKey(vulnerabilities, context);
    const cached = this.getFromCache(cacheKey);
    if (cached) return cached;
    
    const startTime = Date.now();
    
    // Normalize vulnerabilities
    const normalizedVulns = vulnerabilities.map(v => ({
      ...v,
      severity: this.normalizeSeverity(v.severity),
      cwe: v.cwe || v.cweId || 'CWE-1'
    }));
    
    // Step 1: Count vulnerabilities by severity
    const severityDistribution = this.countVulnerabilitiesBySeverity(normalizedVulns);
    
    // Step 2: Calculate normalized score (SINGLE SOURCE OF TRUTH)
    const scoreData = this.calculateNormalizedFileScore(severityDistribution);
    
    // Step 3: Get enabled factors
    const enabledFactors = this.prepareEnabledFactors(context, 'fileLevel');
    
    // Step 4: Get ONLY multiplier from factorSystem (NOT using finalScore)
    const factorCalculation = this.factorSystem.calculateWithCustomFactors(
      normalizedVulns,
      'fileLevel',
      enabledFactors
    );
    // IMPORTANT: We use our own normalized score, not factorCalculation.finalScore
    
    // Step 5: Apply multipliers to OUR normalized score
    const finalScore = Math.min(100, scoreData.normalized * (factorCalculation.totalMultiplier || 1));
    const roundedFinalScore = Math.round(finalScore * 10) / 10;
    
    // Step 6: Determine risk level and priority
    const riskLevel = this.determineFileRiskLevel(roundedFinalScore);
    const priority = this.determineFilePriority(roundedFinalScore, riskLevel);
    
    // Step 7: Generate recommendations
    const recommendations = this.generateFileRecommendations(
      roundedFinalScore,
      riskLevel,
      severityDistribution,
      context
    );

    const result = {
      // Core metrics
      score: {
        raw: scoreData.raw,
        normalized: scoreData.normalized,
        multiplier: factorCalculation.totalMultiplier || 1,
        final: roundedFinalScore,
        scale: '0-100'
      },
      
      // Risk assessment
      risk: {
        level: riskLevel,
        priority: priority,
        confidence: this.calculateConfidence(normalizedVulns, context)
      },
      
      // Vulnerability breakdown
      vulnerabilities: {
        total: normalizedVulns.length,
        distribution: severityDistribution,
        topRisks: this.identifyTopRisks(normalizedVulns, context)
      },
      
      // Applied factors
      factors: {
        applied: factorCalculation.appliedFactors || [],
        context: context,
        explanation: this.explainFactors(factorCalculation.appliedFactors)
      },
      
      // Actionable guidance
      recommendations: recommendations,
      
      // Metadata
      metadata: {
        calculationTime: Date.now() - startTime,
        timestamp: new Date().toISOString(),
        calculator: 'NEPERIA Risk Calculator v2.2'
      }
    };
    
    // Cache result
    this.setCache(cacheKey, result);
    
    return result;
  }

  /**
   * Main entry point for vulnerability-level risk calculation
   */
  calculateVulnerabilityRisk(vulnerability, context = {}) {
    const startTime = Date.now();
    
    // Normalize vulnerability
    const normalizedVuln = {
      ...vulnerability,
      severity: this.normalizeSeverity(vulnerability.severity),
      cwe: vulnerability.cwe || vulnerability.cweId || 'CWE-1'
    };
    
    // Step 1: Get base CVSS score
    const baseCVSS = normalizedVuln.cvss?.baseScore || this.estimateCVSS(normalizedVuln);
    
    // Step 2: Get enabled factors
    const enabledFactors = this.prepareEnabledFactors(context, 'vulnerabilityLevel');
    
    // Step 3: Calculate with custom factors
    const factorCalculation = this.factorSystem.calculateWithCustomFactors(
      normalizedVuln,
      'vulnerabilityLevel',
      enabledFactors
    );
    
    // Step 4: Calculate adjusted score
    let adjustedScore = baseCVSS + (factorCalculation.totalAdditive || 0);
    
    // Apply multipliers if enabled
    if (this.baseConfig.vulnerabilityLevel.allowMultipliers && factorCalculation.totalMultiplier) {
      adjustedScore *= factorCalculation.totalMultiplier;
    }
    
    // Cap at 10.0
    adjustedScore = Math.min(10.0, adjustedScore);
    adjustedScore = Math.round(adjustedScore * 10) / 10;
    
    // Step 5: Determine adjusted severity and priority
    const adjustedSeverity = this.scoreToSeverity(adjustedScore);
    const cweCategory = this.getCweCategory(normalizedVuln.cwe);
    const remediationPriority = this.determineVulnerabilityPriority(
      adjustedScore, 
      normalizedVuln.cwe,
      cweCategory
    );
    
    // Step 6: Generate remediation guidance
    const remediation = this.generateRemediationGuidance(
      normalizedVuln,
      adjustedScore,
      adjustedSeverity,
      cweCategory,
      context
    );

    return {
      // Original assessment
      original: {
        cvss: baseCVSS,
        severity: normalizedVuln.severity,
        vector: normalizedVuln.cvss?.vector || 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N'
      },
      
      // Adjusted assessment
      adjusted: {
        score: adjustedScore,
        severity: adjustedSeverity,
        priority: remediationPriority,
        adjustments: {
          additive: factorCalculation.totalAdditive || 0,
          multiplier: factorCalculation.totalMultiplier || 1
        }
      },
      
      // CWE Information
      cwe: {
        id: normalizedVuln.cwe,
        category: cweCategory
      },
      
      // Applied factors
      factors: {
        applied: factorCalculation.appliedFactors || [],
        explanation: this.explainVulnerabilityAdjustment(
          normalizedVuln.cwe,
          cweCategory,
          factorCalculation.appliedFactors
        )
      },
      
      // Remediation guidance
      remediation: remediation,
      
      // Metadata
      metadata: {
        calculationTime: Date.now() - startTime,
        timestamp: new Date().toISOString()
      }
    };
  }

  /**
   * Prepare enabled factors from context (FIXED canonical mappings)
   */
  prepareEnabledFactors(context, level) {
    const enabledFactors = {};
    
    // Canonical mappings with lowercase keys (FIX APPLIED)
    const canonicalMappings = {
      'handlespersonaldata': 'handlesPI',
      'handlespi': 'handlesPI',
      'legacysystem': 'legacyCode',
      'legacy': 'legacyCode',
      'production': 'production',
      'internetfacing': 'internetFacing',
      'internet-facing': 'internetFacing',
      'compliance': 'compliance'
    };
    
    // Normalize context keys and values
    const normalizedContext = {};
    Object.keys(context).forEach(key => {
      const lowerKey = key.toLowerCase(); // Apply toLowerCase before lookup
      const canonical = canonicalMappings[lowerKey] || key;
      
      // Normalize boolean values
      let value = context[key];
      if (typeof value === 'boolean' || typeof value === 'string' || typeof value === 'number') {
        value = this.normalizeBoolean(value);
      }
      
      normalizedContext[canonical] = value;
    });
    
    // Get all available factors
    const allFactors = this.factorSystem.getAllFactors(level);
    
    // Process normalized context
    Object.keys(allFactors).forEach(factorId => {
      if (normalizedContext[factorId] === true) {
        enabledFactors[factorId] = { 
          enabled: true, 
          value: allFactors[factorId]?.value 
        };
      }
    });
    
    // Add any custom factors from context
    if (normalizedContext.customFactors) {
      Object.assign(enabledFactors, normalizedContext.customFactors);
    }
    
    return enabledFactors;
  }

  /**
   * Identify top risks (sorted by adjusted score)
   */
  identifyTopRisks(vulnerabilities, context) {
    // For very large inputs, could use min-heap for O(n*log(k)) instead of O(n*log(n))
    // For now, using memoization is sufficient for most cases
    
    const vulnsWithScores = vulnerabilities.map(v => {
      const riskCalc = this.memoizedVulnerabilityRisk(v, context);
      return {
        vulnerability: v,
        adjustedScore: riskCalc.adjusted.score,
        adjustedSeverity: riskCalc.adjusted.severity
      };
    });
    
    // Sort by adjusted score descending
    vulnsWithScores.sort((a, b) => b.adjustedScore - a.adjustedScore);
    
    // Return top 5
    return vulnsWithScores.slice(0, 5).map(item => ({
      cwe: item.vulnerability.cwe,
      severity: item.adjustedSeverity,
      adjustedScore: item.adjustedScore,
      message: item.vulnerability.message || item.vulnerability.description || 'Security vulnerability detected',
      location: {
        file: item.vulnerability.file || 'unknown',
        line: item.vulnerability.line || 0
      }
    }));
  }

  /**
   * Count vulnerabilities by severity
   */
  countVulnerabilitiesBySeverity(vulnerabilities) {
    const count = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0
    };
    
    if (!vulnerabilities || vulnerabilities.length === 0) return count;
    
    vulnerabilities.forEach(vuln => {
      const severity = this.normalizeSeverity(vuln?.severity);
      count[severity] = (count[severity] || 0) + 1;
    });
    
    return count;
  }

  /**
   * Calculate confidence level
   */
  calculateConfidence(vulnerabilities, context) {
    if (!vulnerabilities || vulnerabilities.length === 0) return 0.3;
    
    let confidence = 0.5; // Base confidence
    
    // More vulnerabilities = higher confidence
    if (vulnerabilities.length > 20) confidence += 0.2;
    else if (vulnerabilities.length > 10) confidence += 0.1;
    
    // Context provided = higher confidence
    if (context && Object.keys(context).length > 3) confidence += 0.2;
    
    // High severity issues = higher confidence
    const criticalCount = vulnerabilities.filter(v => 
      this.normalizeSeverity(v?.severity) === 'critical'
    ).length;
    if (criticalCount > 0) confidence += 0.1;
    
    return Math.min(1.0, Math.round(confidence * 100) / 100);
  }

  /**
   * Determine file risk level
   */
  determineFileRiskLevel(score) {
    const thresholds = this.baseConfig.fileLevel.riskThresholds;
    
    if (score >= thresholds.critical) return 'critical';
    if (score >= thresholds.high) return 'high';
    if (score >= thresholds.medium) return 'medium';
    if (score >= thresholds.low) return 'low';
    return 'minimal';
  }

  /**
   * Determine file priority
   */
  determineFilePriority(score, riskLevel) {
    const priorities = {
      critical: {
        level: 'P0',
        action: 'Fix immediately',
        timeframe: 'Today',
        description: 'Drop everything and address now'
      },
      high: {
        level: 'P1',
        action: 'Fix this week',
        timeframe: '48-72 hours',
        description: 'Schedule urgent remediation'
      },
      medium: {
        level: 'P2',
        action: 'Plan in sprint',
        timeframe: '2 weeks',
        description: 'Include in next development cycle'
      },
      low: {
        level: 'P3',
        action: 'Schedule later',
        timeframe: '30 days',
        description: 'Add to technical debt backlog'
      },
      minimal: {
        level: 'P4',
        action: 'Monitor',
        timeframe: '90 days',
        description: 'Track but no immediate action'
      }
    };
    
    return priorities[riskLevel] || priorities.minimal;
  }

  /**
   * Score to severity conversion
   */
  scoreToSeverity(score) {
    const thresholds = this.baseConfig.vulnerabilityLevel.severityThresholds;
    
    if (score >= thresholds.critical) return 'critical';
    if (score >= thresholds.high) return 'high';
    if (score >= thresholds.medium) return 'medium';
    if (score >= thresholds.low) return 'low';
    return 'info';
  }

  /**
   * Estimate CVSS from severity
   */
  estimateCVSS(vulnerability) {
    if (vulnerability?.cvss?.baseScore) {
      return vulnerability.cvss.baseScore;
    }
    
    const severity = this.normalizeSeverity(vulnerability?.severity);
    const estimates = {
      critical: 9.0,
      high: 7.5,
      medium: 5.0,
      low: 3.0,
      info: 0.0
    };
    
    return estimates[severity] || 5.0;
  }

  /**
   * Determine vulnerability priority
   */
  determineVulnerabilityPriority(score, cwe, category) {
    // Critical categories that need urgent attention
    const criticalCategories = ['injection', 'deserialization', 'authentication'];
    const isCriticalCategory = criticalCategories.includes(category);
    
    // Adjust priority based on category
    if (score >= 9.0 || (score >= 7.0 && isCriticalCategory)) {
      return {
        priority: 'P0',
        action: 'Fix immediately',
        sla: '4 hours'
      };
    } else if (score >= 7.0) {
      return {
        priority: 'P1',
        action: 'Fix within 48 hours',
        sla: '48 hours'
      };
    } else if (score >= 4.0) {
      return {
        priority: 'P2',
        action: 'Fix in next sprint',
        sla: '2 weeks'
      };
    } else {
      return {
        priority: 'P3',
        action: 'Track and monitor',
        sla: '90 days'
      };
    }
  }

  /**
   * Generate remediation guidance (security-focused)
   */
  generateRemediationGuidance(vulnerability, score, severity, category, context) {
    const categoryInfo = this.cweCategories[category] || {
      remediation: 'Review code and apply security best practices',
      validation: 'Perform security testing',
      risk: 'Potential security vulnerability'
    };
    
    return {
      priority: this.determineVulnerabilityPriority(score, vulnerability.cwe, category),
      timeline: this.determineRemediationTimeline(score, context),
      approach: categoryInfo.remediation,
      validation: categoryInfo.validation,
      risk: categoryInfo.risk,
      resources: {
        documentation: `https://cwe.mitre.org/data/definitions/${vulnerability.cwe.replace('CWE-', '')}.html`,
        owaspGuide: 'https://owasp.org/www-project-top-ten/',
        category: `Security Category: ${category}`
      },
      preventionMeasures: [
        'Implement secure coding standards',
        'Add security linting rules',
        'Include security testing in CI/CD',
        'Conduct regular security training',
        'Perform periodic security audits'
      ]
    };
  }

  /**
   * Determine remediation timeline
   */
  determineRemediationTimeline(score, context) {
    if (score >= 9.0 && this.normalizeBoolean(context.production)) {
      return 'Immediate - Emergency patch required';
    } else if (score >= 7.0) {
      return '48 hours - High priority fix';
    } else if (score >= 4.0) {
      return '2 weeks - Include in next sprint';
    }
    return '30 days - Schedule with regular maintenance';
  }

  /**
   * Generate file recommendations (security-focused)
   */
  generateFileRecommendations(score, riskLevel, distribution, context) {
    const recommendations = [];
    
    // Empty input check
    if (!distribution || Object.values(distribution).every(v => v === 0)) {
      return [{
        priority: 'ONGOING',
        action: 'Continue security best practices',
        detail: 'No vulnerabilities detected, maintain security standards'
      }];
    }
    
    // Priority-based recommendations
    if (riskLevel === 'critical') {
      recommendations.push({
        priority: 'IMMEDIATE',
        action: 'Initiate security response protocol',
        detail: 'Address critical vulnerabilities immediately'
      });
    }
    
    // Severity-based recommendations
    if (distribution.critical > 0) {
      recommendations.push({
        priority: 'HIGH',
        action: `Fix ${distribution.critical} critical vulnerabilities`,
        detail: 'These pose immediate risk to system security'
      });
    }
    
    if (distribution.high > 2) {
      recommendations.push({
        priority: 'HIGH',
        action: `Address ${distribution.high} high-severity issues`,
        detail: 'Schedule remediation within 48 hours'
      });
    }
    
    // Context-based security recommendations
    if (this.normalizeBoolean(context.production) && score >= 40) {
      recommendations.push({
        priority: 'MEDIUM',
        action: 'Review production security controls',
        detail: 'Strengthen security gates before production deployment'
      });
    }
    
    if (this.normalizeBoolean(context.internetFacing) && distribution.high > 0) {
      recommendations.push({
        priority: 'HIGH',
        action: 'Implement additional network security',
        detail: 'Add WAF or additional security layers for internet-facing services'
      });
    }
    
    // Always include ongoing security recommendations
    recommendations.push({
      priority: 'ONGOING',
      action: 'Maintain secure coding practices',
      detail: 'Continue security training and code reviews'
    });
    
    return recommendations;
  }

  /**
   * Explain applied factors
   */
  explainFactors(appliedFactors) {
    if (!appliedFactors || appliedFactors.length === 0) {
      return 'No environmental factors applied';
    }
    
    return appliedFactors
      .map(f => `${f.name}: ${f.impact}`)
      .join(', ');
  }

  /**
   * Explain vulnerability adjustment
   */
  explainVulnerabilityAdjustment(cwe, category, appliedFactors) {
    const explanations = [];
    
    // Category-based explanations
    if (category === 'injection' && appliedFactors.some(f => f.id === 'production')) {
      explanations.push(`${category} vulnerabilities in production are extremely critical`);
    }
    
    if (category === 'xss' && appliedFactors.some(f => f.id === 'internetFacing')) {
      explanations.push('XSS vulnerability exposed to internet users');
    }
    
    if (appliedFactors.length > 0) {
      explanations.push(`${appliedFactors.length} environmental factors applied`);
    }
    
    return explanations.join('. ') || 'Standard risk assessment applied';
  }

  /**
   * Clear all caches
   */
  clearCache() {
    this.calculationCache.clear();
    this.memoCache.clear();
  }
}

// Export the calculator
module.exports = EnhancedRiskCalculator;

// Also export as singleton for convenience
module.exports.calculator = new EnhancedRiskCalculator();