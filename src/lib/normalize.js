// lib/normalize.js - Utilities for normalizing and enriching findings
const Taxonomy = require('../taxonomy');

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
      severity: severity,
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
 * Normalize severity to consistent format
 * @param {string} severity - Severity in various formats
 * @returns {string} Normalized severity
 */
function normalizeSeverity(severity) {
  if (!severity) return 'MEDIUM';
  
  const normalized = severity.toString().toUpperCase();
  
  // Map common variations
  const severityMap = {
    'CRITICAL': 'CRITICAL',
    'CRIT': 'CRITICAL',
    'VERY_HIGH': 'CRITICAL',
    'HIGH': 'HIGH',
    'HI': 'HIGH',
    'ERROR': 'HIGH',
    'MEDIUM': 'MEDIUM',
    'MED': 'MEDIUM',
    'MODERATE': 'MEDIUM',
    'WARNING': 'MEDIUM',
    'WARN': 'MEDIUM',
    'LOW': 'LOW',
    'LO': 'LOW',
    'NOTE': 'LOW',
    'INFO': 'LOW',
    'INFORMATIONAL': 'LOW',
    'INFORMATION': 'LOW'
  };
  
  return severityMap[normalized] || 'MEDIUM';
}

/**
 * Enrich findings with taxonomy data
 * @param {Array} findings - Normalized findings
 * @returns {Array} Enriched findings
 */
function enrichFindings(findings) {
  return findings.map(finding => {
    const enriched = { ...finding };
    
    // If we have CWE, enrich with taxonomy data
    if (finding.cwe && finding.cwe.length > 0) {
      const primaryCwe = finding.cwe[0];
      const taxonomyData = Taxonomy.getByCwe(primaryCwe);
      
      if (taxonomyData) {
        // Add taxonomy information
        enriched.cweTitle = taxonomyData.title;
        enriched.category = taxonomyData.category || finding.category;
        
        // Add OWASP if not present
        if (taxonomyData.owasp && !enriched.owasp.includes(taxonomyData.owasp)) {
          enriched.owasp.push(taxonomyData.owasp);
        }
        
        // Use taxonomy severity if not set
        if (!enriched.severity || enriched.severity === 'MEDIUM') {
          enriched.severity = normalizeSeverity(taxonomyData.defaultSeverity);
        }
      }
    }
    
    // Map rule ID to CWE if possible (for custom scanner)
    if (enriched.engine === 'custom' && enriched.ruleId && enriched.cwe.length === 0) {
      const cweFromRule = mapRuleToCWE(enriched.ruleId);
      if (cweFromRule) {
        enriched.cwe.push(cweFromRule);
      }
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
      if (finding.cwe.length > 0 && existing.cwe.length === 0) {
        existing.cwe = finding.cwe;
      }
      if (finding.owasp.length > 0 && existing.owasp.length === 0) {
        existing.owasp = finding.owasp;
      }
      return false;
    }
    
    seen.set(key, finding);
    return true;
  });
}

module.exports = {
  normalizeFindings,
  normalizeSeverity,
  enrichFindings,
  deduplicateFindings,
  mapRuleToCWE
};