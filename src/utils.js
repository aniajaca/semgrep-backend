// src/utils.js

/**
 * Assign a weight multiplier based on severity.
 * @param {string} severity - Textual severity ('Critical','High','Medium','Low').
 * @returns {number} Weight multiplier.
 */
function getSeverityWeight(severity) {
  switch (severity.toLowerCase()) {
    case 'critical': return 1.5;
    case 'high':     return 1.2;
    case 'medium':   return 1.0;
    case 'low':      return 0.8;
    default:         return 0.5;
  }
}

/**
 * Numeric level for severity to compare maxima.
 * @param {string} severity - Textual severity.
 * @returns {number} Numeric level (0–4).
 */
function getSeverityLevel(severity) {
  switch (severity.toLowerCase()) {
    case 'critical': return 4;
    case 'high':     return 3;
    case 'medium':   return 2;
    case 'low':      return 1;
    default:         return 0;
  }
}

/**
 * Classify a numeric risk score into a severity label.
 * @param {number} score - Adjusted risk score (0.0–10.0).
 * @returns {string} Severity label ('Critical','High','Medium','Low').
 */
function classifySeverity(score) {
  if (score >= 9.0) return 'Critical';
  if (score >= 7.0) return 'High';
  if (score >= 4.0) return 'Medium';
  return 'Low';
}

module.exports = {
  getSeverityWeight,
  getSeverityLevel,
  classifySeverity
};
