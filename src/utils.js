// utils.js

/**
 * Get numeric weight for severity level
 */
function getSeverityWeight(severity) {
  const weights = {
    'critical': 10,
    'high': 7,
    'medium': 4,
    'low': 2,
    'info': 1
  };
  return weights[severity?.toLowerCase()] || 1;
}

/**
 * Get numeric level for severity comparison
 */
function getSeverityLevel(severity) {
  const levels = {
    'critical': 5,
    'high': 4,
    'medium': 3,
    'low': 2,
    'info': 1
  };
  return levels[severity?.toLowerCase()] || 0;
}

/**
 * Classify severity based on CVSS score
 */
function classifySeverity(cvssScore) {
  if (cvssScore >= 9.0) return 'critical';
  if (cvssScore >= 7.0) return 'high';
  if (cvssScore >= 4.0) return 'medium';
  if (cvssScore >= 0.1) return 'low';
  return 'info';
}

module.exports = {
  getSeverityWeight,
  getSeverityLevel,
  classifySeverity
};