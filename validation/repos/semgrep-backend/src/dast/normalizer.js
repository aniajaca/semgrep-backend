// src/dast/normalizer.js
// Convert DASTFinding to NormalizedFinding schema for pipeline integration

/**
 * Normalize DAST finding to unified schema
 * @param {Object} dastFinding - Raw DAST finding
 * @returns {Object} NormalizedFinding
 */
function normalizeDAST(dastFinding) {
  return {
    // Core fields (match SAST schema)
    type: 'vulnerability',
    source: 'dast',
    tool: 'neperia-dast',
    ruleId: `dast-${dastFinding.type.toLowerCase()}`,
    severity: determineSeverity(dastFinding),
    confidence: dastFinding.confidence,
    message: generateMessage(dastFinding),
    
    // Location (DAST has no line numbers)
    location: {
      file: dastFinding.targetUrl,
      line: 0,
      column: 0,
      endLine: 0,
      endColumn: 0
    },

    // DAST-specific metadata
    metadata: {
      // Target information
      targetUrl: dastFinding.targetUrl,
      parameter: dastFinding.vulnerableParameter,
      httpMethod: dastFinding.httpMethod || 'GET',
      
      // Detection information
      detectionMethod: dastFinding.detectionMethod,
      testPayload: dastFinding.testPayload,
      evidence: dastFinding.evidence,
      verified: dastFinding.verified || true,
      
      // Optional fields
      dbms: dastFinding.dbms || null,
      statusCode: dastFinding.statusCode || null,
      responseTime: dastFinding.responseTime || null,
      
      // Compliance mappings
      cwe: getCWE(dastFinding.type),
      owasp: getOWASP(dastFinding.type),
      pciDss: getPCIDSS(dastFinding.type),
      
      // Context hints for risk calculator
      runtime_verified: true, // DAST always verifies at runtime
      exploitability: 'high', // Runtime detection = confirmed exploitable
      attack_vector: dastFinding.httpMethod === 'GET' ? 'network' : 'network_with_interaction'
    }
  };
}

/**
 * Determine severity based on vulnerability type and detection method
 */
function determineSeverity(finding) {
  // SQL Injection is always CRITICAL (data breach risk)
  if (finding.type === 'SQL_INJECTION') {
    // Timing-based has slightly lower confidence but same severity
    return 'CRITICAL';
  }

  // XSS severity depends on storage and context
  if (finding.type === 'XSS') {
    if (finding.detectionMethod === 'stored') {
      return 'HIGH'; // Persistent XSS affects all users
    }
    if (finding.detectionMethod === 'dom_based') {
      return 'MEDIUM'; // DOM XSS requires specific user actions
    }
    return 'MEDIUM'; // Reflected XSS
  }

  // Path Traversal
  if (finding.type === 'PATH_TRAVERSAL') {
    return 'HIGH'; // File system access
  }

  // Default
  return 'MEDIUM';
}

/**
 * Generate human-readable message
 */
function generateMessage(finding) {
  const paramName = finding.vulnerableParameter;
  const method = finding.detectionMethod;
  const url = new URL(finding.targetUrl);
  const path = url.pathname;

  if (finding.type === 'SQL_INJECTION') {
    if (method === 'error_based') {
      return `SQL Injection vulnerability detected in parameter '${paramName}' at ${path} (error-based detection${finding.dbms ? `, ${finding.dbms} DBMS` : ''})`;
    }
    if (method === 'timing_based') {
      return `SQL Injection vulnerability detected in parameter '${paramName}' at ${path} (blind/timing-based detection, ${finding.responseTime}ms delay)`;
    }
    return `SQL Injection vulnerability detected in parameter '${paramName}' at ${path}`;
  }

  if (finding.type === 'XSS') {
    const xssType = method === 'stored' ? 'Stored' : method === 'dom_based' ? 'DOM-based' : 'Reflected';
    return `${xssType} Cross-Site Scripting (XSS) vulnerability detected in parameter '${paramName}' at ${path}`;
  }

  if (finding.type === 'PATH_TRAVERSAL') {
    return `Path Traversal vulnerability detected in parameter '${paramName}' at ${path}`;
  }

  return `${finding.type} vulnerability detected in parameter '${paramName}'`;
}

/**
 * Map vulnerability type to CWE
 */
function getCWE(type) {
  const mapping = {
    'SQL_INJECTION': 'CWE-89',
    'XSS': 'CWE-79',
    'PATH_TRAVERSAL': 'CWE-22',
    'CSRF': 'CWE-352',
    'COMMAND_INJECTION': 'CWE-78',
    'XXE': 'CWE-611'
  };
  return mapping[type] || 'CWE-1035'; // Generic weakness
}

/**
 * Map vulnerability type to OWASP Top 10 2021
 */
function getOWASP(type) {
  const mapping = {
    'SQL_INJECTION': 'A03:2021-Injection',
    'XSS': 'A03:2021-Injection',
    'COMMAND_INJECTION': 'A03:2021-Injection',
    'PATH_TRAVERSAL': 'A01:2021-Broken Access Control',
    'CSRF': 'A01:2021-Broken Access Control',
    'XXE': 'A05:2021-Security Misconfiguration'
  };
  return mapping[type] || 'A00:2021-Unknown';
}

/**
 * Map vulnerability type to PCI DSS requirements
 */
function getPCIDSS(type) {
  const mapping = {
    'SQL_INJECTION': '6.5.1',
    'XSS': '6.5.7',
    'COMMAND_INJECTION': '6.5.1',
    'PATH_TRAVERSAL': '6.5.8',
    'CSRF': '6.5.9'
  };
  return mapping[type] || null;
}

/**
 * Batch normalize multiple findings
 */
function normalizeMany(dastFindings) {
  return dastFindings.map(normalizeDAST);
}

/**
 * Extract summary statistics from findings
 */
function summarizeFindings(findings) {
  const summary = {
    total: findings.length,
    bySeverity: {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0
    },
    byType: {},
    byDetectionMethod: {}
  };

  findings.forEach(finding => {
    // Count by severity
    const severity = finding.severity || 'MEDIUM';
    summary.bySeverity[severity] = (summary.bySeverity[severity] || 0) + 1;

    // Count by type
    const type = finding.metadata?.type || 'UNKNOWN';
    summary.byType[type] = (summary.byType[type] || 0) + 1;

    // Count by detection method
    const method = finding.metadata?.detectionMethod || 'unknown';
    summary.byDetectionMethod[method] = (summary.byDetectionMethod[method] || 0) + 1;
  });

  return summary;
}

module.exports = {
  normalizeDAST,
  normalizeMany,
  summarizeFindings,
  // Export helper functions for testing
  determineSeverity,
  generateMessage,
  getCWE,
  getOWASP,
  getPCIDSS
};