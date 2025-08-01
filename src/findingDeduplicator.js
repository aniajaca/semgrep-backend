// findingDeduplicator.js

const { getSeverityLevel } = require('./utils');

/**
 * Groups findings by CWE + OWASP category, counts occurrences,
 * tracks locations, and keeps highest-severity/CVSS.
 */
function deduplicateFindings(findings) {
  if (!findings || findings.length === 0) {
    return [];
  }

  console.log(`Starting deduplication of ${findings.length} findings`);
  
  const groups = {};

  findings.forEach(f => {
    const cweId = f.cwe?.id || f.cwe || 'UNKNOWN';
    const owaspCat = f.owasp?.category || f.owaspCategory || 'UNKNOWN';
    const key = `${cweId}::${owaspCat}`;

    if (!groups[key]) {
      groups[key] = {
        ...f,
        occurrences: 1,
        locations: [{ 
          file: f.path || f.file || 'unknown', 
          line: f.start?.line || f.line || 0 
        }],
        maxSeverity: f.severity || 'info',
        maxCvssScore: f.cvss?.baseScore || f.cvssScore || 0
      };
    } else {
      const g = groups[key];
      g.occurrences++;
      g.locations.push({ 
        file: f.path || f.file || 'unknown', 
        line: f.start?.line || f.line || 0 
      });

      // Update max severity + CVSS
      if (getSeverityLevel(f.severity) > getSeverityLevel(g.maxSeverity)) {
        g.maxSeverity = f.severity;
        g.maxCvssScore = f.cvss?.baseScore || f.cvssScore || 0;
      }
    }
  });

  const deduplicated = Object.values(groups);
  console.log(`Deduplicated to ${deduplicated.length} unique findings`);
  
  return deduplicated;
}

module.exports = { deduplicateFindings };