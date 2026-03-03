/**
 * SARIF 2.1.0 Formatter
 * Converts Neperia findings to SARIF 2.1.0 per OASIS standard.
 * Maps to: Architecture §4.6, Appendix D.2, TRS FR-7
 */
const SARIF_SCHEMA = 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json';

function mapSeverityToLevel(severity) {
  const map = { critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note' };
  return map[(severity || '').toLowerCase()] || 'warning';
}

function mapPriorityToLevel(priority) {
  const band = typeof priority === 'string' ? priority : priority?.level || priority?.priority;
  return { P0: 'error', P1: 'error', P2: 'warning', P3: 'note' }[band] || 'warning';
}

function findingToSarifResult(finding) {
  return {
    ruleId: finding.ruleId || finding.rule || 'unknown',
    level: mapPriorityToLevel(finding.priority) || mapSeverityToLevel(finding.severity),
    message: { text: finding.message || `${finding.category || 'Security'} vulnerability detected` },
    locations: [{
      physicalLocation: {
        artifactLocation: { uri: (finding.file || 'unknown').replace(/\\/g, '/'), uriBaseId: '%SRCROOT%' },
        region: { startLine: finding.startLine || finding.line || 1, endLine: finding.endLine || finding.startLine || finding.line || 1 }
      }
    }],
    properties: {
      'neperia/bts': finding.cvssBase || null,
      'neperia/crs': finding.crs || finding.adjustedScore || null,
      'neperia/priority': typeof finding.priority === 'object' ? finding.priority.priority : finding.priority || null,
      'neperia/sla': finding.sla || finding.remediation?.priority?.sla || null,
      'neperia/contextFactors': finding.environmentalFactors || finding.inferredFactors || []
    }
  };
}

function buildRuleDescriptors(findings) {
  const rulesMap = new Map();
  findings.forEach(f => {
    const ruleId = f.ruleId || f.rule || 'unknown';
    if (!rulesMap.has(ruleId)) {
      rulesMap.set(ruleId, {
        id: ruleId, name: f.category || ruleId,
        shortDescription: { text: f.message || `Rule: ${ruleId}` },
        defaultConfiguration: { level: mapSeverityToLevel(f.severity) },
        properties: { tags: [...(f.cwe ? [String(f.cwe)] : []), ...(f.owasp || []), f.engine || 'unknown'] }
      });
    }
  });
  return Array.from(rulesMap.values());
}

function toSARIF(scanResult, options = {}) {
  const findings = scanResult.findings || [];
  const meta = scanResult.provenance || scanResult.metadata || {};
  return {
    version: '2.1.0',
    $schema: SARIF_SCHEMA,
    runs: [{
      tool: {
        driver: {
          name: 'Neperia Security Scanner', version: options.version || '2.0.0',
          informationUri: 'https://scanner.neperia.dev',
          rules: buildRuleDescriptors(findings)
        }
      },
      taxonomies: [{ name: 'CWE', version: '4.13', informationUri: 'https://cwe.mitre.org', organization: 'MITRE', shortDescription: { text: 'Common Weakness Enumeration' } }],
      results: findings.map(findingToSarifResult),
      invocations: [{ executionSuccessful: true, startTimeUtc: meta.timestamp || new Date().toISOString(), properties: { 'neperia/profileId': meta.profileId || 'default' } }],
      properties: { 'neperia/overallRisk': scanResult.overallRisk || null, 'neperia/projectRisk': scanResult.projectRisk || null }
    }]
  };
}

function toSARIFString(scanResult, options = {}) {
  return JSON.stringify(toSARIF(scanResult, options), null, 2);
}

module.exports = { toSARIF, toSARIFString };