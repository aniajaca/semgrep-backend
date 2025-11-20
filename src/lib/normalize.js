// lib/normalize.js - Consolidated utilities for normalizing, enriching, and analyzing findings
// Taxonomy is not needed for basic enrichment
// const Taxonomy = require('../../data/taxonomy');

// ============================================================================
// DATA MODEL FUNCTIONS (from dataModels.js)
// ============================================================================

/**
 * Normalize severity string to lowercase standard format
 */
function normalizeSeverity(severity) {
  if (!severity) return 'medium';
  
  const normalized = severity.toString().toLowerCase().trim();
  
  const mappings = {
    'critical': 'critical',
    'crit': 'critical',
    'very_high': 'critical',
    'high': 'high',
    'hi': 'high',
    'error': 'high',
    'medium': 'medium',
    'med': 'medium',
    'moderate': 'medium',
    'warning': 'medium',
    'warn': 'medium',
    'low': 'low',
    'lo': 'low',
    'note': 'low',
    'info': 'info',
    'informational': 'info',
    'information': 'info',
    'unknown': 'medium'
  };
  
  return mappings[normalized] || 'medium';
}

/**
 * Create a normalized risk context object
 */
function createRiskContext(context = {}) {
  const normalized = {};
  
  // Boolean context flags
  const booleanFlags = [
    'internetFacing',
    'production',
    'handlesPI',
    'handlesFinancialData',
    'handlesHealthData',
    'legacyCode',
    'businessCritical',
    'regulated',
    'compliance',
    'thirdPartyIntegration',
    'complexAuth',
    'userBaseLarge',
    'kevListed',
    'publicExploit',
    'exploitAvailable',
    'hasControls'
  ];
  
  // Normalize boolean flags
  booleanFlags.forEach(flag => {
    if (context[flag] !== undefined) {
      normalized[flag] = normalizeBoolean(context[flag]);
    }
  });
  
  // String context values
  const stringValues = ['assetCriticality', 'fixEffort', 'dataClassification'];
  stringValues.forEach(key => {
    if (context[key]) {
      normalized[key] = context[key].toString().toLowerCase();
    }
  });
  
  // Numeric values
  if (context.epss !== undefined) {
    let epss = parseFloat(context.epss);
    if (epss > 1) epss = epss / 100; // Convert percentage to decimal
    normalized.epss = Math.min(1, Math.max(0, epss));
  }
  
  // Array values
  if (context.compliance && Array.isArray(context.compliance)) {
    normalized.compliance = context.compliance;
  }
  
  // Pass through custom factors
  if (context.customFactors) {
    normalized.customFactors = context.customFactors;
  }
  
  return normalized;
}

/**
 * Normalize boolean values (handles strings, numbers, etc.)
 */
function normalizeBoolean(value) {
  if (value === true || value === 1) return true;
  if (value === false || value === 0) return false;
  
  if (typeof value === 'string') {
    const lower = value.toLowerCase().trim();
    return lower === 'true' || lower === '1' || lower === 'yes' || lower === 'on';
  }
  
  return Boolean(value);
}

/**
 * Calculate risk statistics from findings
 */
function calculateRiskStatistics(findings) {
  const stats = {
    total: findings.length,
    distribution: {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0
    },
    categories: {},
    averageScore: 0,
    maxScore: 0,
    minScore: 100
  };
  
  if (!findings || findings.length === 0) {
    return stats;
  }
  
  let totalScore = 0;
  
  findings.forEach(finding => {
    // Count by severity
    const severity = normalizeSeverity(finding.severity);
    if (stats.distribution[severity] !== undefined) {
      stats.distribution[severity]++;
    }
    
    // Count by category
    const category = finding.category || 'unknown';
    stats.categories[category] = (stats.categories[category] || 0) + 1;
    
    // Calculate score statistics
    const score = finding.score || finding.cvss || 0;
    totalScore += score;
    stats.maxScore = Math.max(stats.maxScore, score);
    stats.minScore = Math.min(stats.minScore, score);
  });
  
  stats.averageScore = totalScore / findings.length;
  
  return stats;
}

// ============================================================================
// NORMALIZATION FUNCTIONS (original normalize.js)
// ============================================================================

/**
 * Normalize findings from different scanners to consistent format
 * @param {Array} findings - Raw findings from various scanners
 * @returns {Array} Normalized findings
 */
function normalizeFindings(findings) {
  if (!Array.isArray(findings)) {
    return [];
  }
  
  return findings.map(finding => {
    // Ensure consistent severity format
    const severity = normalizeSeverity(finding.severity);
    
    // Ensure CWE and OWASP are arrays
    const cwe = Array.isArray(finding.cwe) ? finding.cwe : 
                (finding.cwe ? [finding.cwe] : []);
    const owasp = Array.isArray(finding.owasp) ? finding.owasp : 
                  (finding.owasp ? [finding.owasp] : []);
    
    return {
      engine: finding.engine || 'unknown',
      ruleId: finding.ruleId || finding.rule_id || finding.check_id || 'unknown',
      category: finding.category || 'sast',
      severity: severity.toUpperCase(), // Keep uppercase for API compatibility
      message: finding.message || 'Security issue detected',
      cwe: cwe,
      owasp: owasp,
      file: finding.file || finding.path || 'unknown',
      startLine: finding.startLine || finding.line || 0,
      endLine: finding.endLine || finding.startLine || finding.line || 0,
      startColumn: finding.startColumn || finding.column || 0,
      endColumn: finding.endColumn || finding.startColumn || finding.column || 0,
      snippet: finding.snippet || finding.code || '',
      confidence: finding.confidence || 'MEDIUM',
      impact: finding.impact || 'MEDIUM',
      likelihood: finding.likelihood || 'MEDIUM'
    };
  });
}

/**
 * Enrich findings with taxonomy data
 * @param {Array} findings - Normalized findings
 * @returns {Array} Enriched findings
 */
function enrichFindings(findings) {
  // ✅ INPUT VALIDATION
  if (!Array.isArray(findings)) {
    console.warn('enrichFindings expects an array');
    return [];
  }

 
  
  return findings.map(finding => {
    // ✅ ENSURE REQUIRED FIELDS EXIST
    const enriched = { 
      ...finding,
      cwe: Array.isArray(finding.cwe) ? finding.cwe : [],
      owasp: Array.isArray(finding.owasp) ? finding.owasp : [],
      file: finding.file || 'unknown',
      startLine: finding.startLine || 0
    };
    
    // If we have CWE, enrich with taxonomy data
    if (enriched.cwe && enriched.cwe.length > 0) {
      const primaryCwe = enriched.cwe[0];
       
    }
    
    return enriched;
  });
}

/**
 * Map custom scanner rule IDs to CWE
 * @param {string} ruleId - Rule identifier
 * @returns {string|null} CWE identifier
 */
function mapRuleToCWE(ruleId) {
  const ruleMap = {
    'sqlInjection': 'CWE-89',
    'commandInjection': 'CWE-78',
    'xss': 'CWE-79',
    'hardcodedSecrets': 'CWE-798',
    'pathTraversal': 'CWE-22',
    'weakCrypto': 'CWE-327',
    'dangerousEval': 'CWE-94',
    'ssrf': 'CWE-918',
    'insecureDeserialization': 'CWE-502',
    'prototypePollution': 'CWE-1321',
    'insecureLogging': 'CWE-532',
    'nosqlInjection': 'CWE-943',
    'xxe': 'CWE-611',
    'ldapInjection': 'CWE-90'
  };
  
  return ruleMap[ruleId] || null;
}

/**
 * Deduplicate findings
 * @param {Array} findings - Findings to deduplicate
 * @returns {Array} Deduplicated findings
 */
function deduplicateFindings(findings) {
  const seen = new Map();
  
  return findings.filter(finding => {
    // Create a unique key for the finding
    const key = `${finding.file}:${finding.startLine}:${finding.ruleId}:${finding.severity}`;
    
    if (seen.has(key)) {
      // Merge information if needed
      const existing = seen.get(key);

      // ✅ NULL-SAFE CWE MERGE
      if (Array.isArray(finding.cwe) && finding.cwe.length > 0 && 
          (!existing.cwe || existing.cwe.length === 0)) {
        existing.cwe = finding.cwe;
      }

      // ✅ NULL-SAFE OWASP MERGE
      if (Array.isArray(finding.owasp) && finding.owasp.length > 0 && 
          (!existing.owasp || existing.owasp.length === 0)) {
        existing.owasp = finding.owasp;
      }
      return false;
    }
    
    seen.set(key, finding);
    return true;
  });
}
// ============================================================================
// ADDITIONAL UTILITY FUNCTIONS
// ============================================================================

/**
 * Create empty risk result structure
 */
function createEmptyRiskResult() {
  return {
    summary: {
      totalFindings: 0,
      riskScore: 0,
      riskLevel: 'none',
      grade: 'A',
      confidence: 1.0
    },
    distribution: {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0
    },
    statistics: {
      total: 0,
      averageScore: 0,
      maxScore: 0,
      minScore: 0
    },
    topRisks: [],
    recommendations: [],
    metadata: {
      calculatedAt: new Date().toISOString()
    }
  };
}

/**
 * Map risk score to risk level
 */
function scoreToRiskLevel(score) {
  if (score >= 80) return 'critical';
  if (score >= 60) return 'high';
  if (score >= 40) return 'medium';
  if (score >= 20) return 'low';
  return 'minimal';
}

/**
 * Map risk score to grade
 */
function scoreToGrade(score) {
  const invertedScore = 100 - score;
  
  if (invertedScore >= 85) return 'A';
  if (invertedScore >= 70) return 'B';
  if (invertedScore >= 55) return 'C';
  if (invertedScore >= 40) return 'D';
  return 'F';
}

/**
 * Calculate confidence score from multiple sources
 */
function calculateConfidence(sources = []) {
  if (sources.length === 0) return 0.5;
  
  const weights = {
    semgrep: 0.9,
    ast: 0.7,
    custom: 0.6,
    manual: 0.5
  };
  
  let totalWeight = 0;
  let weightedSum = 0;
  
  sources.forEach(source => {
    const weight = weights[source.engine] || 0.5;
    const confidence = source.confidence || 0.7;
    
    weightedSum += weight * confidence;
    totalWeight += weight;
  });
  
  return totalWeight > 0 ? weightedSum / totalWeight : 0.5;
}

// ============================================================================
// EXPORTS
// ============================================================================

module.exports = {
  // Normalization functions
  normalizeFindings,
  normalizeSeverity,
  enrichFindings,
  deduplicateFindings,
  mapRuleToCWE,
  
  // Data model functions
  createRiskContext,
  normalizeBoolean,
  calculateRiskStatistics,
  createEmptyRiskResult,
  
  // Utility functions
  scoreToRiskLevel,
  scoreToGrade,
  calculateConfidence
};