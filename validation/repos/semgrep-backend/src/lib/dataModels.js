// lib/dataModels.js - Data models and utility functions for risk calculation

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

module.exports = {
  normalizeSeverity,
  createRiskContext,
  normalizeBoolean,
  calculateRiskStatistics,
  createEmptyRiskResult,
  scoreToRiskLevel,
  scoreToGrade,
  calculateConfidence
};