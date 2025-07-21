// utils.js

/**
 * Assign a weight multiplier based on severity.
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

module.exports = { getSeverityWeight, getSeverityLevel };
