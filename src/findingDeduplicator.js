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
// src/findingDeduplicator.js - Intelligent finding deduplication for Neperia Security Scanner

const { getSeverityLevel } = require('./utils');

/**
 * Deduplicate security findings by grouping similar vulnerabilities
 * Groups by: CWE + File + Vulnerability Type
 * Keeps: Highest severity, all locations, occurrence count
 * 🔧 STATIC: Rule-based deduplication logic
 * 
 * @param {Array} findings - Array of classified security findings
 * @returns {Array} Deduplicated findings with aggregated data
 */
function deduplicateFindings(findings) {
  if (!findings || findings.length === 0) {
    return [];
  }

  console.log(`🔧 STATIC: Starting deduplication of ${findings.length} findings`);
  
  const groups = {};
  
  findings.forEach(finding => {
    // Generate unique key for grouping similar findings
    const groupKey = generateFindingKey(finding);
    
    if (!groups[groupKey]) {
      // First occurrence - create new group
      groups[groupKey] = {
        ...finding,
        occurrences: 1,
        locations: [extractLocation(finding)],
        maxSeverity: finding.severity,
        maxCvssScore: extractCvssScore(finding),
        allFindings: [finding] // Keep reference to all original findings
      };
    } else {
      // Duplicate found - merge into existing group
      const group = groups[groupKey];
      group.occurrences++;
      group.locations.push(extractLocation(finding));
      group.allFindings.push(finding);
      
      // Update to highest severity/CVSS
      if (getSeverityLevel(finding.severity) > getSeverityLevel(group.maxSeverity)) {
        group.maxSeverity = finding.severity;
        group.maxCvssScore = extractCvssScore(finding);
        group.severity = finding.severity; // Update main severity
        group.cvss = finding.cvss; // Update main CVSS
      }
    }
  });

  const deduplicated = Object.values(groups);
  
  // Enhance deduplicated findings with aggregation metadata
  const enhanced = deduplicated.map(group => enhanceDuplicatedFinding(group));
  
  console.log(`🔧 STATIC: Deduplication complete - ${findings.length} → ${enhanced.length} findings`);
  
  return enhanced;
}

/**
 * Generate a unique key for grouping similar findings
 * 🔧 STATIC: Intelligent grouping logic
 */
function generateFindingKey(finding) {
  const cweId = finding.cwe?.id || finding.cwe || 'UNKNOWN';
  const file = extractFileName(finding);
  const rulePattern = extractRulePattern(finding);
  
  // Group by: CWE + File + Rule Pattern
  // This groups similar vulnerabilities in the same file
  return `${cweId}::${file}::${rulePattern}`;
}

/**
 * Extract clean file name from various path formats
 * 🔧 STATIC: Path normalization
 */
function extractFileName(finding) {
  const filePath = finding.path || 
                   finding.scannerData?.location?.file || 
                   finding.location?.file || 
                   'unknown';
  
  if (filePath === 'unknown') return filePath;
  
  // Extract just the filename (not full path)
  const parts = filePath.replace(/\\/g, '/').split('/');
  return parts[parts.length - 1] || 'unknown';
}

/**
 * Extract rule pattern for grouping
 * 🔧 STATIC: Rule categorization
 */
function extractRulePattern(finding) {
  const ruleId = finding.ruleId || finding.check_id || '';
  
  // Extract the main vulnerability type from rule ID
  if (ruleId.includes('sql')) return 'sql-injection';
  if (ruleId.includes('xss')) return 'cross-site-scripting';
  if (ruleId.includes('command') || ruleId.includes('exec')) return 'command-injection';
  if (ruleId.includes('path')) return 'path-traversal';
  if (ruleId.includes('crypto') || ruleId.includes('hash')) return 'cryptographic';
  if (ruleId.includes('hardcode')) return 'hardcoded-secrets';
  if (ruleId.includes('csrf')) return 'csrf';
  if (ruleId.includes('deserial')) return 'deserialization';
  
  // Fallback: use the main rule category
  const parts = ruleId.split('.');
  return parts[parts.length - 1] || 'generic';
}

/**
 * Extract location information from finding
 * 🔧 STATIC: Location normalization
 */
function extractLocation(finding) {
  return {
    file: finding.path || finding.scannerData?.location?.file || 'unknown',
    line: finding.start?.line || finding.scannerData?.location?.line || 0,
    column: finding.start?.col || finding.scannerData?.location?.column || 0,
    codeSnippet: finding.codeSnippet || finding.extractedCode || ''
  };
}

/**
 * Extract CVSS score from various finding formats
 * 🔧 STATIC: Score extraction
 */
function extractCvssScore(finding) {
  return finding.cvss?.adjustedScore || 
         finding.cvss?.baseScore || 
         finding.cvssScore || 
         0;
}

/**
 * Enhance deduplicated finding with aggregation metadata
 * 🔧 STATIC: Metadata enhancement
 */
function enhanceDuplicatedFinding(group) {
  const enhanced = {
    ...group,
    
    // Update title to reflect multiple occurrences
    title: group.occurrences > 1 
      ? `${group.title} (${group.occurrences} occurrences)`
      : group.title,
    
    // Enhanced description with occurrence info
    description: generateAggregatedDescription(group),
    
    // Location summary
    locationSummary: generateLocationSummary(group.locations),
    
    // Risk aggregation
    aggregatedRisk: calculateAggregatedRisk(group),
    
    // Deduplication metadata
    deduplication: {
      isDeduplicated: group.occurrences > 1,
      originalCount: group.occurrences,
      affectedFiles: [...new Set(group.locations.map(l => l.file))].length,
      affectedLines: group.locations.map(l => l.line),
      groupKey: generateFindingKey(group)
    }
  };
  
  // Clean up internal fields
  delete enhanced.allFindings;
  
  return enhanced;
}

/**
 * Generate aggregated description for multiple occurrences
 * 🔧 STATIC: Description generation
 */
function generateAggregatedDescription(group) {
  const baseDescription = group.cwe?.description || 'Security vulnerability detected';
  
  if (group.occurrences === 1) {
    return baseDescription;
  }
  
  const fileCount = [...new Set(group.locations.map(l => l.file))].length;
  const occurrenceText = group.occurrences === 1 ? 'occurrence' : 'occurrences';
  const fileText = fileCount === 1 ? 'file' : 'files';
  
  return `${baseDescription}. Found ${group.occurrences} ${occurrenceText} across ${fileCount} ${fileText}.`;
}

/**
 * Generate location summary for multiple occurrences
 * 🔧 STATIC: Location aggregation
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
  
  // Generate summary like "file1.py:10,15,20; file2.js:5,8"
  return Object.entries(fileGroups)
    .map(([file, lines]) => `${file}:${lines.sort((a, b) => a - b).join(',')}`)
    .join('; ');
}

/**
 * Calculate aggregated risk for multiple occurrences
 * 🔧 STATIC: Risk calculation
 */
function calculateAggregatedRisk(group) {
  const baseRisk = group.maxCvssScore;
  
  // Increase risk based on occurrence count and file spread
  const occurrenceMultiplier = Math.min(2.0, 1 + (group.occurrences - 1) * 0.1);
  const fileSpreadMultiplier = [...new Set(group.locations.map(l => l.file))].length > 1 ? 1.2 : 1.0;
  
  const aggregatedScore = Math.min(10.0, baseRisk * occurrenceMultiplier * fileSpreadMultiplier);
  
  return {
    baseScore: baseRisk,
    aggregatedScore: parseFloat(aggregatedScore.toFixed(1)),
    occurrenceMultiplier,
    fileSpreadMultiplier,
    riskIncrease: aggregatedScore > baseRisk
  };
}

/**
 * Get deduplication statistics
 * 🔧 STATIC: Analytics helper
 */
function getDeduplicationStats(originalFindings, deduplicatedFindings) {
  const originalCount = originalFindings.length;
  const deduplicatedCount = deduplicatedFindings.length;
  const reductionPercentage = originalCount > 0 
    ? Math.round(((originalCount - deduplicatedCount) / originalCount) * 100)
    : 0;
  
  const duplicateGroups = deduplicatedFindings.filter(f => f.deduplication?.isDeduplicated);
  
  return {
    originalCount,
    deduplicatedCount,
    duplicatesRemoved: originalCount - deduplicatedCount,
    reductionPercentage,
    duplicateGroups: duplicateGroups.length,
    efficiency: reductionPercentage > 0 ? 'Effective' : 'No duplicates found'
  };
}

module.exports = { 
  deduplicateFindings,
  getDeduplicationStats
};