// findingDeduplicator.js - Enhanced for classified findings

const { getSeverityLevel } = require('./utils');

/**
 * Groups findings by CWE + OWASP category, counts occurrences,
 * tracks locations, and keeps highest-severity/CVSS.
 * Now works with classified findings from SecurityClassificationSystem
 */
function deduplicateFindings(findings) {
  if (!findings || findings.length === 0) {
    return [];
  }

  console.log(`Starting deduplication of ${findings.length} findings`);
  
  const groups = {};

  findings.forEach(f => {
    // Use the classified CWE and OWASP data
    const cweId = f.cwe?.id || 'UNKNOWN';
    const owaspCat = f.owasp?.category || 'UNKNOWN';
    const key = `${cweId}::${owaspCat}`;

    if (!groups[key]) {
      // First occurrence - keep all the rich classification data
      groups[key] = {
        ...f,
        occurrences: 1,
        locations: [{ 
          file: f.location?.file || f.path || f.file || 'unknown', 
          line: f.location?.line || f.start?.line || f.line || 0,
          column: f.location?.column || 0
        }],
        allCodeSnippets: [f.code || f.extractedCode || ''],
        maxSeverity: f.severity || 'info',
        maxCvssScore: f.cvss?.adjustedScore || f.cvss?.baseScore || 0
      };
    } else {
      const g = groups[key];
      g.occurrences++;
      
      // Add new location
      g.locations.push({ 
        file: f.location?.file || f.path || f.file || 'unknown', 
        line: f.location?.line || f.start?.line || f.line || 0,
        column: f.location?.column || 0
      });
      
      // Collect code snippets
      const codeSnippet = f.code || f.extractedCode || '';
      if (codeSnippet && !g.allCodeSnippets.includes(codeSnippet)) {
        g.allCodeSnippets.push(codeSnippet);
      }

      // Update max severity + CVSS if this instance is more severe
      if (getSeverityLevel(f.severity) > getSeverityLevel(g.maxSeverity)) {
        g.maxSeverity = f.severity;
        g.maxCvssScore = f.cvss?.adjustedScore || f.cvss?.baseScore || 0;
        
        // Update other severity-dependent fields
        g.cvss = f.cvss;
        g.businessImpact = f.businessImpact;
        g.remediation = f.remediation;
      }
    }
  });

  // Convert groups to array and enhance with deduplication metadata
  const deduplicated = Object.values(groups).map(group => {
    // Sort locations for consistent display
    group.locations.sort((a, b) => {
      if (a.file !== b.file) return a.file.localeCompare(b.file);
      return a.line - b.line;
    });

    // Create a summary of affected files
    const affectedFiles = [...new Set(group.locations.map(l => l.file))];
    
    // Add deduplication metadata
    group.deduplication = {
      isDeduplicated: group.occurrences > 1,
      occurrenceCount: group.occurrences,
      affectedFiles: affectedFiles,
      fileCount: affectedFiles.length,
      locationSummary: generateLocationSummary(group.locations)
    };

    // Update title to show occurrence count
    if (group.occurrences > 1) {
      group.title = `${group.title} (${group.occurrences} occurrences)`;
    }

    // Clean up temporary fields
    delete group.allCodeSnippets;

    return group;
  });

  console.log(`Deduplicated to ${deduplicated.length} unique findings`);
  
  // Sort by severity and CVSS score
  deduplicated.sort((a, b) => {
    const severityDiff = getSeverityLevel(b.maxSeverity || b.severity) - 
                         getSeverityLevel(a.maxSeverity || a.severity);
    if (severityDiff !== 0) return severityDiff;
    
    // If same severity, sort by CVSS score
    const scoreA = a.maxCvssScore || a.cvss?.adjustedScore || 0;
    const scoreB = b.maxCvssScore || b.cvss?.adjustedScore || 0;
    return scoreB - scoreA;
  });
  
  return deduplicated;
}

/**
 * Generate a human-readable location summary
 */
function generateLocationSummary(locations) {
  if (locations.length === 1) {
    const loc = locations[0];
    return `${loc.file}:${loc.line}`;
  }
  
  // Group by file
  const fileGroups = locations.reduce((groups, loc) => {
    const file = loc.file;
    if (!groups[file]) groups[file] = [];
    groups[file].push(loc.line);
    return groups;
  }, {});
  
  // Generate summary
  const summaries = Object.entries(fileGroups).map(([file, lines]) => {
    const uniqueLines = [...new Set(lines)].sort((a, b) => a - b);
    if (uniqueLines.length <= 3) {
      return `${file}:${uniqueLines.join(',')}`;
    } else {
      return `${file}:${uniqueLines[0]}-${uniqueLines[uniqueLines.length - 1]} (${uniqueLines.length} locations)`;
    }
  });
  
  return summaries.join('; ');
}

/**
 * Get deduplication statistics
 */
function getDeduplicationStats(originalFindings, deduplicatedFindings) {
  const originalCount = originalFindings.length;
  const deduplicatedCount = deduplicatedFindings.length;
  const reductionPercentage = originalCount > 0 
    ? Math.round(((originalCount - deduplicatedCount) / originalCount) * 100)
    : 0;
  
  const duplicateGroups = deduplicatedFindings.filter(f => 
    f.deduplication?.isDeduplicated && f.deduplication?.occurrenceCount > 1
  );
  
  const totalOccurrences = deduplicatedFindings.reduce((sum, f) => 
    sum + (f.deduplication?.occurrenceCount || 1), 0
  );
  
  return {
    originalCount,
    deduplicatedCount,
    duplicatesRemoved: originalCount - deduplicatedCount,
    reductionPercentage,
    duplicateGroups: duplicateGroups.length,
    totalOccurrences,
    averageOccurrences: deduplicatedCount > 0 
      ? (totalOccurrences / deduplicatedCount).toFixed(1) 
      : 0,
    efficiency: reductionPercentage > 0 ? 'Effective' : 'No duplicates found'
  };
}

module.exports = { 
  deduplicateFindings,
  getDeduplicationStats
};