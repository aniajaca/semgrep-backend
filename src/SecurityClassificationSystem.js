// SecurityClassificationSystem.js
// Bulletproof implementation for robust CWE extraction and real vulnerability details

const { classifySeverity } = require('./utils');

class SecurityClassificationSystem {
  constructor() {
    // --- CWE definitions (copy yours here, as before) ---
    this.cweDatabase = {
      'CWE-89': {
        name: 'SQL Injection',
        description: 'The software constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command.',
        category: 'Injection',
        owasp: 'A03:2021',
        cvss: { baseScore: 8.1, vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N' },
        remediation: 'Use parameterized queries, stored procedures, or prepared statements. Validate and sanitize all user inputs.',
        businessImpact: 'Data breach, unauthorized access to sensitive information, potential complete system compromise'
      },
      'CWE-798': {
        name: 'Hardcoded Credentials',
        description: 'The software contains hard-coded credentials, such as a password or cryptographic key, which it uses for its own inbound authentication, outbound communication to external components, or encryption of internal data.',
        category: 'Authentication',
        owasp: 'A07:2021',
        cvss: { baseScore: 9.8, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' },
        remediation: 'Store credentials in secure configuration files or environment variables. Use secure credential management systems.',
        businessImpact: 'Complete system compromise, unauthorized access to all resources, severe compliance violations'
      },
      'CWE-327': {
        name: 'Use of Broken or Risky Cryptographic Algorithm',
        description: 'The use of a broken or risky cryptographic algorithm is an unnecessary risk that may result in the exposure of sensitive information.',
        category: 'Cryptography',
        owasp: 'A02:2021',
        cvss: { baseScore: 7.5, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N' },
        remediation: 'Replace weak algorithms (MD5, SHA1) with strong alternatives (SHA-256, bcrypt, Argon2). Use industry-standard cryptographic libraries.',
        businessImpact: 'Compromised data confidentiality, potential exposure of passwords and sensitive data'
      },
      'CWE-338': {
        name: 'Use of Cryptographically Weak Pseudo-Random Number Generator',
        description: 'The product uses a Pseudo-Random Number Generator (PRNG) in a security context, but the PRNG is not cryptographically strong.',
        category: 'Cryptography',
        owasp: 'A02:2021',
        cvss: { baseScore: 5.9, vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N' },
        remediation: 'Use cryptographically secure random number generators like crypto.randomBytes() in Node.js or SecureRandom in Java.',
        businessImpact: 'Predictable tokens leading to session hijacking, compromised authentication systems'
      },
      'CWE-22': {
        name: 'Path Traversal',
        description: 'The software uses external input to construct a pathname that is intended to identify a file or directory that is located underneath a restricted parent directory, but the software does not properly neutralize special elements.',
        category: 'Access Control',
        owasp: 'A01:2021',
        cvss: { baseScore: 6.4, vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N' },
        remediation: 'Validate and sanitize file paths. Use a whitelist of allowed files. Avoid user input in file operations.',
        businessImpact: 'Unauthorized access to sensitive files, potential data leakage, system configuration exposure'
      },
      'CWE-79': {
        name: 'Cross-Site Scripting (XSS)',
        description: 'The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.',
        category: 'Injection',
        owasp: 'A03:2021',
        cvss: { baseScore: 6.1, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N' },
        remediation: 'Encode all user input before output. Use Content Security Policy (CSP). Validate input on both client and server side.',
        businessImpact: 'Account takeover, data theft, malware distribution to users'
      },
      'CWE-78': {
        name: 'OS Command Injection',
        description: 'The software constructs all or part of an OS command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended OS command.',
        category: 'Injection',
        owasp: 'A03:2021',
        cvss: { baseScore: 9.8, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' },
        remediation: 'Avoid system calls with user input. Use language-specific APIs instead of OS commands. If necessary, use strict input validation.',
        businessImpact: 'Complete system compromise, arbitrary code execution, data destruction'
      },
      'CWE-94': {
        name: 'Code Injection',
        description: 'The software constructs all or part of a code segment using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the syntax or behavior of the intended code segment.',
        category: 'Injection',
        owasp: 'A03:2021',
        cvss: { baseScore: 9.8, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' },
        remediation: 'Never use eval() or similar functions with user input. Use safe alternatives for dynamic functionality.',
        businessImpact: 'Remote code execution, complete system compromise, data theft'
      },
      'CWE-502': {
        name: 'Deserialization of Untrusted Data',
        description: 'The application deserializes untrusted data without sufficiently verifying that the resulting data will be valid.',
        category: 'Software Integrity',
        owasp: 'A08:2021',
        cvss: { baseScore: 8.1, vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H' },
        remediation: 'Avoid deserializing untrusted data. Use JSON instead of native serialization. Implement integrity checks.',
        businessImpact: 'Remote code execution, denial of service, privilege escalation'
      },
      'CWE-287': {
        name: 'Improper Authentication',
        description: 'When an actor claims to have a given identity, the software does not prove or insufficiently proves that the claim is correct.',
        category: 'Authentication',
        owasp: 'A07:2021',
        cvss: { baseScore: 8.1, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N' },
        remediation: 'Implement proper authentication mechanisms. Use multi-factor authentication. Follow OWASP authentication guidelines.',
        businessImpact: 'Unauthorized access, identity theft, compliance violations'
      },
      'CWE-200': {
        name: 'Information Exposure',
        description: 'The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information.',
        category: 'Access Control',
        owasp: 'A01:2021',
        cvss: { baseScore: 5.3, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N' },
        remediation: 'Implement proper access controls. Remove sensitive data from error messages. Use secure logging practices.',
        businessImpact: 'Data leakage, privacy violations, competitive disadvantage'
      },
      'CWE-918': {
        name: 'Server-Side Request Forgery (SSRF)',
        description: 'The web server receives a URL or similar request from an upstream component and retrieves the contents of this URL, but it does not sufficiently ensure that the request is being sent to the expected destination.',
        category: 'Request Forgery',
        owasp: 'A10:2021',
        cvss: { baseScore: 7.5, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N' },
        remediation: 'Validate and whitelist allowed URLs. Use allow-lists for domains. Disable unnecessary URL schemas.',
        businessImpact: 'Internal network scanning, access to cloud metadata, potential data exfiltration'
      }
    };

    // --- Rule to CWE mapping (substring match) ---
    this.ruleToCweMap = {
      'hardcoded-password': 'CWE-798', 'hardcoded-secret': 'CWE-798', 'hardcoded-credential': 'CWE-798', 'password': 'CWE-798',
      'sql-injection': 'CWE-89', 'formatted-sql-query': 'CWE-89', 'tainted-sql-query': 'CWE-89', 'select-where': 'CWE-89',
      'weak-crypto': 'CWE-327', 'weak-hash': 'CWE-327', 'md5-used': 'CWE-327', 'sha1-used': 'CWE-327', 'md5': 'CWE-327', 'sha1': 'CWE-327',
      'node.crypto.createHash.md5': 'CWE-327', 'weak-random': 'CWE-338', 'math-random-used': 'CWE-338',
      'path-traversal': 'CWE-22', 'dangerous-file-open': 'CWE-22', 'directory-traversal': 'CWE-22',
      'xss': 'CWE-79', 'reflected-xss': 'CWE-79', 'stored-xss': 'CWE-79',
      'command-injection': 'CWE-78', 'shell-injection': 'CWE-78',
      'code-injection': 'CWE-94', 'eval-injection': 'CWE-94', 'eval': 'CWE-94',
      'deserialization': 'CWE-502', 'unsafe-deserialization': 'CWE-502',
      'broken-auth': 'CWE-287', 'missing-auth': 'CWE-287',
      'info-exposure': 'CWE-200', 'leak': 'CWE-200',
      'ssrf': 'CWE-918'
    };
  }

  classifyFinding(finding, context = {}) {
    // --- CWE Extraction ---
    const cweId = this.extractCweId(finding);
    const cweInfo = this.cweDatabase[cweId] || this.getDefaultCwe();

    // --- Defensive: always have CVSS and other properties ---
    const cvss = cweInfo.cvss || { baseScore: 5.0, vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N' };
    const cvssScores = this.calculateCvssScores({ cvss }, context);
    const name = cweInfo.name || 'Unclassified Security Issue';
    const category = cweInfo.category || 'Other';
    const owasp = cweInfo.owasp || 'A05:2021';

    const severity = this.determineSeverity(cvssScores.adjustedScore);
    const id = this.generateFindingId(finding);

    // Defensive: CWE can be array sometimes
    let cweMetaId = cweId;
    if (Array.isArray(cweId)) cweMetaId = cweId[0];

    return {
      id,
      title: name,
      description: cweInfo.description || 'Potential security issue.',
      severity,
      cwe: { id: cweMetaId, name, category },
      owasp: { category: owasp, title: this.getOwaspTitle(owasp) },
      cvss: {
        baseScore: cvssScores.baseScore,
        adjustedScore: cvssScores.adjustedScore,
        vector: cvss.vector || 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N',
        environmental: cvssScores.environmental
      },
      remediation: {
        strategy: cweInfo.remediation || 'Review the code for security issues and apply appropriate fixes.',
        priority: this.calculatePriority(severity, context),
        effort: this.estimateRemediationEffort(cweMetaId)
      },
      businessImpact: {
        description: cweInfo.businessImpact || 'Potential security vulnerability with unknown impact',
        financialRisk: this.calculateFinancialRisk(severity),
        reputationRisk: this.calculateReputationRisk(severity),
        complianceRisk: this.assessComplianceRisk(cweMetaId, context)
      },
      location: {
        file: finding.path || finding.file || 'unknown',
        line: finding.start?.line || finding.line || 0,
        column: finding.start?.col || 0
      },
      code: (finding.extra?.lines || finding.extractedCode || finding.code || ''),
      scannerData: finding
    };
  }

  extractCweId(finding) {
    if (finding.cwe?.id) return finding.cwe.id;
    const metaCwe = finding.extra?.metadata?.cwe;
    if (metaCwe) {
      if (Array.isArray(metaCwe)) {
        const match = String(metaCwe[0]).match(/CWE-\d+/);
        if (match) return match[0];
      } else if (typeof metaCwe === 'string') {
        const match = metaCwe.match(/CWE-\d+/);
        if (match) return match[0];
      }
    }
    const checkId = finding.check_id || finding.ruleId || '';
    const cweMatch = checkId.match(/CWE[- ]?(\d+)/i);
    if (cweMatch) return `CWE-${cweMatch[1]}`;
    for (const [pattern, cwe] of Object.entries(this.ruleToCweMap)) {
      if (checkId.toLowerCase().includes(pattern)) return cwe;
    }
    return 'CWE-1';
  }

  calculateCvssScores(cweInfo, context) {
    let baseScore = cweInfo.cvss?.baseScore || 5.0;
    let adjustedScore = baseScore;
    const environmental = { production: 0, internetFacing: 0, dataHandling: 0, legacy: 0, compliance: 0 };
    if (context.isProduction || context.environment === 'production') { adjustedScore += 0.5; environmental.production = 0.5; }
    if (context.isInternetFacing || context.deployment === 'internet-facing') { adjustedScore += 0.3; environmental.internetFacing = 0.3; }
    if (context.handlesFinancialData || context.dataHandling?.financialData) { adjustedScore += 0.4; environmental.dataHandling = 0.4; }
    else if (context.handlesPersonalData || context.dataHandling?.personalData) { adjustedScore += 0.3; environmental.dataHandling = 0.3; }
    if (context.isLegacySystem) { adjustedScore += 0.2; environmental.legacy = 0.2; }
    if (context.regulatoryRequirements?.includes('PCI-DSS')) { adjustedScore += 0.5; environmental.compliance = Math.max(environmental.compliance, 0.5); }
    if (context.regulatoryRequirements?.includes('HIPAA')) { adjustedScore += 0.6; environmental.compliance = Math.max(environmental.compliance, 0.6); }
    if (context.regulatoryRequirements?.includes('GDPR')) { adjustedScore += 0.4; environmental.compliance = Math.max(environmental.compliance, 0.4); }
    adjustedScore = Math.min(10.0, adjustedScore);
    return {
      baseScore: Math.round(baseScore * 10) / 10,
      adjustedScore: Math.round(adjustedScore * 10) / 10,
      environmental
    };
  }

  determineSeverity(cvssScore) {
    if (cvssScore >= 9.0) return 'critical';
    if (cvssScore >= 7.0) return 'high';
    if (cvssScore >= 4.0) return 'medium';
    if (cvssScore >= 0.1) return 'low';
    return 'info';
  }

  getOwaspTitle(category) {
    const owaspTitles = {
      'A01:2021': 'Broken Access Control',
      'A02:2021': 'Cryptographic Failures',
      'A03:2021': 'Injection',
      'A04:2021': 'Insecure Design',
      'A05:2021': 'Security Misconfiguration',
      'A06:2021': 'Vulnerable and Outdated Components',
      'A07:2021': 'Identification and Authentication Failures',
      'A08:2021': 'Software and Data Integrity Failures',
      'A09:2021': 'Security Logging and Monitoring Failures',
      'A10:2021': 'Server-Side Request Forgery'
    };
    return owaspTitles[category] || 'Unknown Category';
  }

  calculatePriority(severity, context) {
    const basePriority = {
      'critical': 'immediate',
      'high': 'urgent',
      'medium': 'normal',
      'low': 'backlog',
      'info': 'optional'
    };
    let priority = basePriority[severity];
    if ((context.isProduction || context.regulatoryRequirements?.length > 0) && priority === 'normal') {
      priority = 'urgent';
    }
    return priority;
  }

  estimateRemediationEffort(cweId) {
    const effortMap = {
      'CWE-798': 'low',
      'CWE-89': 'medium',
      'CWE-327': 'medium',
      'CWE-78': 'high',
      'CWE-94': 'high',
      'CWE-502': 'high'
    };
    return effortMap[cweId] || 'medium';
  }

  calculateFinancialRisk(severity) {
    const riskMap = {
      'critical': '$1M+',
      'high': '$100K-$1M',
      'medium': '$10K-$100K',
      'low': '$1K-$10K',
      'info': '<$1K'
    };
    return riskMap[severity];
  }

  calculateReputationRisk(severity) {
    const riskMap = {
      'critical': 'severe',
      'high': 'major',
      'medium': 'moderate',
      'low': 'minor',
      'info': 'minimal'
    };
    return riskMap[severity];
  }

  assessComplianceRisk(cweId, context) {
    const complianceMap = {
      'CWE-798': ['PCI-DSS', 'HIPAA', 'SOX'],
      'CWE-89': ['PCI-DSS', 'GDPR'],
      'CWE-327': ['PCI-DSS', 'HIPAA', 'GDPR'],
      'CWE-200': ['GDPR', 'HIPAA']
    };
    const relevantCompliance = complianceMap[cweId] || [];
    const violations = relevantCompliance.filter(reg => context.regulatoryRequirements?.includes(reg));
    return {
      frameworks: relevantCompliance,
      violations: violations,
      risk: violations.length > 0 ? 'high' : 'low'
    };
  }

  generateFindingId(finding) {
    const file = (finding.path || finding.file || 'unknown').replace(/[^a-zA-Z0-9]/g, '-');
    const line = finding.start?.line || finding.line || 0;
    const checkId = (finding.check_id || finding.ruleId || 'unknown').substring(0, 20);
    return `${checkId}-${file}-${line}-${Date.now()}`.substring(0, 50);
  }

  getDefaultCwe() {
    return {
      name: 'Unclassified Security Issue',
      description: 'A potential security issue was detected but could not be classified into a specific category.',
      category: 'Other',
      owasp: 'A05:2021',
      cvss: { baseScore: 5.0, vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N' },
      remediation: 'Review the code for security issues and apply appropriate fixes.',
      businessImpact: 'Potential security vulnerability with unknown impact'
    };
  }

  // You can also include aggregateRiskScore and other methods if used elsewhere
}

module.exports = { SecurityClassificationSystem };
