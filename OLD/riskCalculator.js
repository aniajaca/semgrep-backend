// riskCalculator.js

const { getSeverityWeight } = require('./OLD/utils');

/**
 * Example: complexity = (# distinct files) / (# findings) + 1
 */
function calculateComplexityMultiplier(findings) {
  if (findings.length === 0) return 1;
  const files = new Set(findings.map(f => f.locations?.[0].file || f.path || f.file));
  return Math.min(2, files.size / findings.length + 1);
}

/**
 * Example: density = (findings per file) / 5 + 1
 */
function calculateDensityMultiplier(findings) {
  if (findings.length === 0) return 1;
  const fileCount = new Set(findings.map(f => f.locations?.[0].file || f.path || f.file)).size;
  const perFile = findings.length / fileCount;
  return Math.min(2, perFile / 5 + 1);
}

/**
 * Combines weights and CVSS to a 0–100 score, plus breakdown & multipliers.
 */
function calculateRiskScore(findings) {
  let total = 0;
  const breakdown = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };

  findings.forEach(f => {
    const sev = f.maxSeverity || f.severity || 'info';
    const weight = getSeverityWeight(sev);
    const score  = f.maxCvssScore || f.cvss?.baseScore || f.cvssScore || 0;
    total += weight * score;
    const key = sev.toLowerCase();
    breakdown[key] = (breakdown[key] || 0) + 1;
  });

  const finalScore = Math.min(100, Math.round(total));
  return {
    finalScore,
    severityBreakdown: breakdown,
    multipliers: {
      complexity: calculateComplexityMultiplier(findings),
      density: calculateDensityMultiplier(findings)
    }
  };
}

module.exports = { calculateRiskScore };
