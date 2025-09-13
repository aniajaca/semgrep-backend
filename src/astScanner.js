// astScanner.js - AST-based vulnerability scanner for code analysis

class ASTVulnerabilityScanner {
  constructor() {
    // Initialize vulnerability patterns
    this.patterns = {
      javascript: {
        // SQL Injection patterns
        sqlInjection: [
          /query\s*\(\s*[`"'].*\$\{.*\}.*[`"']/gi,
          /query\s*\(\s*[`"'].*\+.*[`"']/gi,
          /execute\s*\(\s*[`"'].*\$\{.*\}.*[`"']/gi,
        ],
        // Command injection patterns
        commandInjection: [
          /exec\s*\(\s*[`"'].*\$\{.*\}.*[`"']/gi,
          /execSync\s*\(\s*[`"'].*\$\{.*\}.*[`"']/gi,
          /spawn\s*\(\s*[`"'].*\$\{.*\}.*[`"']/gi,
        ],
        // XSS patterns
        xss: [
          /innerHTML\s*=\s*[^'"`]/gi,
          /document\.write\s*\(/gi,
          /\.html\s*\(\s*[^'"`]/gi,
        ],
        // Hardcoded credentials
        hardcodedSecrets: [
          /(?:api[_-]?key|apikey|secret|password|pwd|token|auth)\s*[:=]\s*["'][\w\-]{10,}/gi,
          /(?:AWS|aws)[_-]?(?:ACCESS|access)[_-]?(?:KEY|key)[_-]?(?:ID|id)?\s*[:=]\s*["'][A-Z0-9]{20}/gi,
        ],
        // Path traversal
        pathTraversal: [
          /readFile(?:Sync)?\s*\([^)]*\+[^)]*\)/gi,
          /require\s*\([^)]*\+[^)]*\)/gi,
        ],
        // Weak crypto
        weakCrypto: [
          /createHash\s*\(\s*["'](?:md5|sha1)["']\s*\)/gi,
          /crypto\.(?:createCipher|createDecipher)\s*\(/gi,
        ],
        // Eval usage
        dangerousEval: [
          /eval\s*\(/gi,
          /Function\s*\(\s*["'][^"']*["']\s*\)/gi,
          /setTimeout\s*\([^,]*,\s*0\s*\)/gi,
        ]
      }
    };
  }

  /**
   * Main scanning method
   */
  scan(code, filename = 'unknown', language = 'javascript') {
    const findings = [];
    
    if (!code || typeof code !== 'string') {
      return findings;
    }

    // Get patterns for the specified language
    const languagePatterns = this.patterns[language.toLowerCase()] || this.patterns.javascript;
    
    // Split code into lines for line number tracking
    const lines = code.split('\n');
    
    // Check each pattern category
    Object.entries(languagePatterns).forEach(([category, patterns]) => {
      patterns.forEach(pattern => {
        // Reset regex state
        pattern.lastIndex = 0;
        
        let match;
        while ((match = pattern.exec(code)) !== null) {
          // Find line number
          const position = match.index;
          let lineNumber = 1;
          let charCount = 0;
          
          for (let i = 0; i < lines.length; i++) {
            charCount += lines[i].length + 1; // +1 for newline
            if (charCount > position) {
              lineNumber = i + 1;
              break;
            }
          }
          
          // Create finding
          const finding = this.createFinding(
            category,
            match[0],
            filename,
            lineNumber,
            language
          );
          
          findings.push(finding);
        }
      });
    });
    
    // Additional heuristic checks
    this.performHeuristicChecks(code, filename, language, findings);
    
    // Deduplicate findings
    return this.deduplicateFindings(findings);
  }

  /**
   * Create a finding object
   */
  createFinding(category, matchedCode, filename, line, language) {
    const categoryMappings = {
      sqlInjection: {
        cwe: 'CWE-89',
        title: 'SQL Injection',
        severity: 'critical',
        owasp: { category: 'A03:2021 - Injection' }
      },
      commandInjection: {
        cwe: 'CWE-78',
        title: 'OS Command Injection',
        severity: 'critical',
        owasp: { category: 'A03:2021 - Injection' }
      },
      xss: {
        cwe: 'CWE-79',
        title: 'Cross-Site Scripting (XSS)',
        severity: 'high',
        owasp: { category: 'A03:2021 - Injection' }
      },
      hardcodedSecrets: {
        cwe: 'CWE-798',
        title: 'Use of Hard-coded Credentials',
        severity: 'high',
        owasp: { category: 'A07:2021 - Identification and Authentication Failures' }
      },
      pathTraversal: {
        cwe: 'CWE-22',
        title: 'Path Traversal',
        severity: 'high',
        owasp: { category: 'A01:2021 - Broken Access Control' }
      },
      weakCrypto: {
        cwe: 'CWE-327',
        title: 'Use of Broken or Weak Cryptographic Algorithm',
        severity: 'medium',
        owasp: { category: 'A02:2021 - Cryptographic Failures' }
      },
      dangerousEval: {
        cwe: 'CWE-94',
        title: 'Code Injection',
        severity: 'high',
        owasp: { category: 'A03:2021 - Injection' }
      }
    };
    
    const mapping = categoryMappings[category] || {
      cwe: 'CWE-1',
      title: 'Security Issue',
      severity: 'medium',
      owasp: { category: 'A06:2021 - Vulnerable and Outdated Components' }
    };
    
    return {
      id: `${category}-${filename}-${line}`,
      file: filename,
      line: line,
      column: 0,
      severity: mapping.severity,
      title: mapping.title,
      message: `${mapping.title} vulnerability detected`,
      description: `Potential ${mapping.title} vulnerability found in ${filename} at line ${line}`,
      cwe: mapping.cwe,
      cweId: mapping.cwe,
      owasp: mapping.owasp,
      check_id: category,
      snippet: matchedCode.substring(0, 100),
      language: language,
      cvss: this.estimateCVSS(mapping.severity),
      remediation: this.getRemediation(mapping.cwe)
    };
  }

  /**
   * Perform additional heuristic checks
   */
  performHeuristicChecks(code, filename, language, findings) {
    // Check for missing input validation
    if (language === 'javascript') {
      // Check for Express routes without validation
      if (code.includes('app.post') || code.includes('app.put')) {
        if (!code.includes('express-validator') && !code.includes('joi') && !code.includes('yup')) {
          findings.push({
            id: 'missing-validation-' + filename,
            file: filename,
            line: 0,
            severity: 'medium',
            title: 'Missing Input Validation',
            message: 'API endpoints detected without explicit input validation',
            description: 'Consider using express-validator, joi, or yup for input validation',
            cwe: 'CWE-20',
            owasp: { category: 'A03:2021 - Injection' },
            cvss: { baseScore: 5.3 }
          });
        }
      }
      
      // Check for missing security headers
      if (code.includes('express()') && !code.includes('helmet')) {
        findings.push({
          id: 'missing-helmet-' + filename,
          file: filename,
          line: 0,
          severity: 'low',
          title: 'Missing Security Headers',
          message: 'Express app without Helmet security headers',
          description: 'Consider using helmet middleware to set security headers',
          cwe: 'CWE-693',
          owasp: { category: 'A05:2021 - Security Misconfiguration' },
          cvss: { baseScore: 3.1 }
          });
      }
    }
  }

  /**
   * Deduplicate findings
   */
  deduplicateFindings(findings) {
    const seen = new Set();
    return findings.filter(finding => {
      const key = `${finding.file}-${finding.line}-${finding.cwe}`;
      if (seen.has(key)) {
        return false;
      }
      seen.add(key);
      return true;
    });
  }

  /**
   * Estimate CVSS score based on severity
   */
  estimateCVSS(severity) {
    const scores = {
      critical: { baseScore: 9.8, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' },
      high: { baseScore: 7.5, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N' },
      medium: { baseScore: 5.3, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N' },
      low: { baseScore: 3.1, vector: 'CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N' },
      info: { baseScore: 0.0, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N' }
    };
    
    return scores[severity] || scores.medium;
  }

  /**
   * Get remediation advice
   */
  getRemediation(cwe) {
    const remediations = {
      'CWE-89': 'Use parameterized queries or prepared statements',
      'CWE-78': 'Avoid shell commands or use safe alternatives like spawn with argument arrays',
      'CWE-79': 'Encode output and implement Content Security Policy',
      'CWE-798': 'Use environment variables or secure vaults for credentials',
      'CWE-22': 'Validate and sanitize file paths, use path.join()',
      'CWE-327': 'Use strong cryptographic algorithms (SHA-256, AES-256)',
      'CWE-94': 'Avoid eval() and Function constructor, use JSON.parse() for data',
      'CWE-20': 'Implement input validation for all user inputs',
      'CWE-693': 'Configure security headers and follow security best practices'
    };
    
    return remediations[cwe] || 'Review and apply security best practices';
  }
}

module.exports = { ASTVulnerabilityScanner };