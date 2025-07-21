// findingDeduplicator.js

const { getSeverityLevel } = require('./utils');

/**
 * Groups findings by CWE + OWASP category, counts occurrences,
 * tracks locations, and keeps highest-severity/CVSS.
 */
function deduplicateFindings(findings) {
  const groups = {};

  findings.forEach(f => {
    const cweId = f.cwe?.id || f.cwe || 'UNKNOWN';
    const owaspCat = f.owasp?.category || f.owaspCategory || 'UNKNOWN';
    const key = `${cweId}::${owaspCat}`;

    if (!groups[key]) {
      groups[key] = {
        ...f,
        occurrences: 1,
        locations: [{ file: f.path || f.file, line: f.start?.line || f.line }],
        maxSeverity: f.severity,
        maxCvssScore: f.cvss?.baseScore || f.cvssScore || 0
      };
    } else {
      const g = groups[key];
      g.occurrences++;
      g.locations.push({ file: f.path || f.file, line: f.start?.line || f.line });

      // update max severity + CVSS
      if (getSeverityLevel(f.severity) > getSeverityLevel(g.maxSeverity)) {
        g.maxSeverity = f.severity;
        g.maxCvssScore = f.cvss?.baseScore || f.cvssScore || 0;
      }
    }
  });

  return Object.values(groups);
}

module.exports = { deduplicateFindings };
