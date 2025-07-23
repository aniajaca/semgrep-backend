// src/SecurityClassificationSystem.js - Complete and correct implementation
const { getSeverityWeight, getSeverityLevel, classifySeverity } = require('./utils');

/**
 * Enhanced Security Classification System with AI integration and contextual analysis
 * 🔧 STATIC: This class provides rule-based vulnerability classification
 */
class SecurityClassificationSystem {
  constructor() {
    this.cweDatabase = this.initializeCWEDatabase();
    this.owaspMapping = this.initializeOWASPMapping();
    this.cvssCalculator = new CVSSCalculator();
    console.log('🔧 STATIC: SecurityClassificationSystem v2.0 initialized');
  }

  /**
   * Classify a security finding with enhanced context and AI-ready metadata
   * 🔧 STATIC: Rule-based classification with AI metadata preparation
   * @param {Object} finding - Raw finding from Semgrep
   * @returns {Object} Enhanced classified finding
   */
  classifyFinding(finding) {
    const context = finding.context || {};
    
    console.log('🔧 STATIC: Classifying finding:', finding.check_id);
    
    // Extract basic information
    const basicInfo = this.extractBasicInfo(finding);
    
    // Get CWE information (🔧 STATIC)
    const cweInfo = this.getCWEInfo(basicInfo.cweId);
    
    // Map to OWASP category (🔧 STATIC)
    const owaspCategory = this.mapToOWASP(cweInfo.category);
    
    // Calculate CVSS score with environmental adjustments (🔧 STATIC)
    const cvssInfo = this.cvssCalculator.calculate(finding, context);
    
    // Determine final severity (🔧 STATIC)
    const finalSeverity = this.determineFinalSeverity(cvssInfo.adjustedScore);
    
    // Generate AI-friendly metadata (🤖 AI PREPARATION)
    const aiMetadata = this.generateAIMetadata(finding, context, cweInfo);
    
    // Create business impact assessment (🔧 STATIC)
    const businessImpact = this.assessBusinessImpact(finding, context, cvssInfo);
    
    console.log(`🔧 STATIC: Classified as ${finalSeverity} severity (CVSS: ${cvssInfo.adjustedScore})`);
    
    return {
      // Core identification
      id: this.generateFindingId(finding),
      ruleId: basicInfo.ruleId,
      title: this.generateTitle(finding, cweInfo),
      
      // Classification (🔧 STATIC)
      severity: finalSeverity,
      cwe: {
        id: cweInfo.id,
        name: cweInfo.name,
        category: cweInfo.category,
        description: cweInfo.description
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
        confidence: finding.extra?.confidence || 'medium'
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
      
      // Timestamps and metadata
      classifiedAt: new Date().toISOString(),
      classificationVersion: '2.0'
    };
  }

  /**
   * Extract basic information from raw finding
   * 🔧 STATIC: Data extraction and normalization
   */
  extractBasicInfo(finding) {
    return {
      ruleId: finding.check_id || finding.ruleId || 'unknown-rule',
      cweId: this.extractCWEId(finding),
      message: finding.message || finding.title || 'No description available',
      severity: finding.severity || 'medium'
    };
  }

  /**
   * Extract CWE ID from various possible formats
   * 🔧 STATIC: Pattern matching and inference
   */
  extractCWEId(finding) {
    // Try different ways to extract CWE
    if (finding.cwe?.id) return finding.cwe.id;
    if (finding.cwe && typeof finding.cwe === 'string') {
      const match = finding.cwe.match(/CWE-(\d+)/i);
      return match ? `CWE-${match[1]}` : finding.cwe;
    }
    if (finding.extra?.metadata?.cwe) return finding.extra.metadata.cwe;
    
    // Fallback: try to infer from rule ID or message
    return this.inferCWEFromRule(finding.check_id || finding.ruleId);
  }

  /**
   * Infer CWE from rule patterns
   * 🔧 STATIC: Rule-based CWE inference
   */
  inferCWEFromRule(ruleId) {
    const rulePatterns = {
      'sql-injection': 'CWE-89',
      'xss': 'CWE-79',
      'hardcoded-password': 'CWE-798',
      'command-injection': 'CWE-78',
      'path-traversal': 'CWE-22',
      'weak-crypto': 'CWE-327',
      'insecure-random': 'CWE-338',
      'xxe': 'CWE-611',
      'deserialization': 'CWE-502',
      'csrf': 'CWE-352'
    };

    for (const [pattern, cwe] of Object.entries(rulePatterns)) {
      if (ruleId && ruleId.toLowerCase().includes(pattern)) {
        return cwe;
      }
    }
    
    return 'CWE-200'; // Generic information exposure
  }

  /**
   * Initialize CWE database with common vulnerabilities
   * 🔧 STATIC: Vulnerability knowledge base
   */
  initializeCWEDatabase() {
    return {
      'CWE-79': {
        id: 'CWE-79',
        name: 'Cross-site Scripting (XSS)',
        category: 'Input Validation',
        description: 'Improper neutralization of input during web page generation',
        baseScore: 6.1,
        impact: 'High'
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
        name: 'Command Injection',
        category: 'Input Validation',
        description: 'Improper neutralization of special elements used in an OS command',
        baseScore: 9.8,
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
      }
    };
  }

  /**
   * Get CWE information with fallback
   * 🔧 STATIC: Database lookup
   */
  getCWEInfo(cweId) {
    return this.cweDatabase[cweId] || {
      id: cweId || 'CWE-200',
      name: 'Security Issue',
      category: 'General',
      description: 'Security vulnerability detected',
      baseScore: 5.0,
      impact: 'Medium'
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
      'Cryptographic Issues': 'A02:2021 – Cryptographic Failures',
      'Information Disclosure': 'A01:2021 – Broken Access Control',
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
    return `${rule}-${file.replace(/[^a-zA-Z0-9]/g, '_')}-${line}`;
  }

  /**
   * Generate human-readable title
   * 🔧 STATIC: Title generation
   */
  generateTitle(finding, cweInfo) {
    const location = finding.path || finding.scannerData?.location?.file || 'unknown file';
    return `${cweInfo.name} in ${location}`;
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
      'Command Injection': 'high',
      'Deserialization of Untrusted Data': 'very-high',
      'Cross-site Scripting (XSS)': 'medium',
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
      'CWE-79': 6.1,  // XSS
      'CWE-611': 8.2, // XXE
      'CWE-352': 8.8, // CSRF
      'CWE-798': 7.8, // Hardcoded Credentials
      'CWE-327': 7.4, // Weak Crypto
      'CWE-22': 7.5,  // Path Traversal
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