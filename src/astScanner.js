// astScanner.js - Enhanced AST-based vulnerability scanner with comprehensive patterns

const remediationKnowledge = require('./remediationKnowledge');
const Taxonomy = require('./taxonomy');

class ASTVulnerabilityScanner {
  constructor() {
    // Initialize comprehensive vulnerability patterns
    this.patterns = {
      javascript: {
        // SQL Injection patterns
        sqlInjection: [
          /query\s*\(\s*[`"'].*\$\{.*\}.*[`"']/gi,
          /query\s*\(\s*[`"'].*\+.*[`"']/gi,
          /execute\s*\(\s*[`"'].*\$\{.*\}.*[`"']/gi,
          /raw\s*\(\s*[`"'].*\$\{.*\}.*[`"']/gi,
          /\.query\s*\(\s*["'`][^"'`]*\$\{[^}]+\}[^"'`]*["'`]\)/gi,
        ],
        // Command injection patterns
        commandInjection: [
          /exec\s*\(\s*[`"'].*\$\{.*\}.*[`"']/gi,
          /execSync\s*\(\s*[`"'].*\$\{.*\}.*[`"']/gi,
          /spawn\s*\(\s*[`"'].*\$\{.*\}.*[`"']/gi,
          /execFile\s*\([^,)]*\+[^,)]*\)/gi,
          /child_process\.[a-z]+\s*\([^)]*\$\{.*\}[^)]*\)/gi,
        ],
        // XSS patterns
        xss: [
          /innerHTML\s*=\s*[^'"`]/gi,
          /outerHTML\s*=\s*[^'"`]/gi,
          /document\.write\s*\(/gi,
          /\.html\s*\(\s*[^'"`]/gi,
          /insertAdjacentHTML\s*\([^,)]*,[^'"`]/gi,
          /dangerouslySetInnerHTML\s*=\s*\{/gi,
        ],
        // Hardcoded credentials (expanded)
        hardcodedSecrets: [
          /(?:api[_-]?key|apikey|secret|password|pwd|token|auth)\s*[:=]\s*["'][\w\-]{10,}/gi,
          /(?:AWS|aws)[_-]?(?:ACCESS|access)[_-]?(?:KEY|key)[_-]?(?:ID|id)?\s*[:=]\s*["'][A-Z0-9]{20}/gi,
          /(?:private[_-]?key|privatekey)\s*[:=]\s*["'][^"']{20,}/gi,
          /Bearer\s+[a-zA-Z0-9\-._~+/]+=*/gi,
          /mongodb(?:\+srv)?:\/\/[^:]+:[^@]+@/gi,
          /postgres:\/\/[^:]+:[^@]+@/gi,
        ],
        // Path traversal
        pathTraversal: [
          /readFile(?:Sync)?\s*\([^)]*\+[^)]*\)/gi,
          /require\s*\([^)]*\+[^)]*\)/gi,
          /createReadStream\s*\([^)]*\+[^)]*\)/gi,
          /sendFile\s*\([^)]*\+[^)]*\)/gi,
          /\.\.\/|\.\.\\\/gi,
        ],
        // Weak crypto
        weakCrypto: [
          /createHash\s*\(\s*["'](?:md5|sha1)["']\s*\)/gi,
          /crypto\.(?:createCipher|createDecipher)\s*\(/gi,
          /Math\.random\s*\(\s*\)/gi, // When used for security
          /DES|RC4|RC2|MD4/gi,
        ],
        // Eval and code injection
        dangerousEval: [
          /eval\s*\(/gi,
          /Function\s*\(\s*["'][^"']*["']\s*\)/gi,
          /setTimeout\s*\([^,)]*\$\{[^}]*\}[^,)]*,/gi,
          /setInterval\s*\([^,)]*\$\{[^}]*\}[^,)]*,/gi,
          /new\s+Function\s*\(/gi,
        ],
        // SSRF patterns (NEW)
        ssrf: [
          /(?:axios|fetch|request|http\.get)\s*\([^)]*\$\{[^}]*\}[^)]*\)/gi,
          /(?:axios|fetch|request)\s*\([^)]*\+[^)]*\)/gi,
          /url\s*=\s*[^'"`]*\$\{[^}]*\}/gi,
          /redirect\s*\([^)]*\$\{[^}]*\}[^)]*\)/gi,
        ],
        // Insecure deserialization (NEW)
        insecureDeserialization: [
          /JSON\.parse\s*\([^)]*\$\{[^}]*\}[^)]*\)/gi,
          /unserialize\s*\(/gi,
          /pickle\.loads\s*\(/gi,
          /readObject\s*\(\s*\)/gi,
          /yaml\.load\s*\([^,)]*\)/gi, // without safe_load
        ],
        // Prototype pollution (NEW)
        prototypePollution: [
          /__proto__/gi,
          /constructor\s*\[\s*["']prototype["']\s*\]/gi,
          /Object\.prototype/gi,
          /merge\s*\([^)]*req\.(body|query|params)[^)]*\)/gi,
          /assign\s*\([^)]*,\s*req\.(body|query|params)[^)]*\)/gi,
        ],
        // Insecure logging (NEW)
        insecureLogging: [
          /console\.(log|error|warn|info)\s*\([^)]*(?:password|token|secret|apikey|auth)[^)]*\)/gi,
          /logger\.(log|error|warn|info)\s*\([^)]*(?:password|token|secret|apikey|auth)[^)]*\)/gi,
          /fs\.writeFile[^(]*\([^)]*(?:password|token|secret)[^)]*\)/gi,
        ],
        // NoSQL injection (NEW)
        nosqlInjection: [
          /\$where\s*:\s*[^}]*\$\{[^}]*\}/gi,
          /\$regex\s*:\s*[^}]*\$\{[^}]*\}/gi,
          /find\s*\(\s*\{[^}]*\$\{[^}]*\}[^}]*\}\s*\)/gi,
          /\.find\s*\(\s*req\.(body|query|params)\s*\)/gi,
        ],
        // XXE patterns (NEW)
        xxe: [
          /noent\s*:\s*true/gi,
          /external_general_entities\s*:\s*true/gi,
          /load_external_dtd\s*:\s*true/gi,
          /DOMParser\s*\(\s*\)\.parseFromString\s*\([^)]*text\/xml/gi,
        ],
        // LDAP injection (NEW)
        ldapInjection: [
          /ldap.*search\s*\([^)]*\$\{[^}]*\}[^)]*\)/gi,
          /\(uid=.*\$\{[^}]*\}\)/gi,
          /searchFilter\s*=\s*[^;]*\$\{[^}]*\}/gi,
        ]
      }
    };
    
    // Track findings by function/route for better deduplication
    this.findingGroups = new Map();
  }

  /**
   * Main scanning method
   */
  scan(code, filename = 'unknown', language = 'javascript') {
    const findings = [];
    this.findingGroups.clear();
    
    if (!code || typeof code !== 'string') {
      return findings;
    }

    // Get patterns for the specified language
    const languagePatterns = this.patterns[language.toLowerCase()] || this.patterns.javascript;
    
    // Split code into lines for line number tracking
    const lines = code.split('\n');
    
    // Identify functions and routes for better grouping
    const functionMap = this.identifyFunctions(code, lines);
    
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
          
          // Find containing function
          const containingFunction = this.findContainingFunction(lineNumber, functionMap);
          
          // Create finding
          const finding = this.createFinding(
            category,
            match[0],
            filename,
            lineNumber,
            language,
            containingFunction
          );
          
          findings.push(finding);
        }
      });
    });
    
    // Additional heuristic checks
    this.performHeuristicChecks(code, filename, language, findings);
    
    // Smart deduplication with grouping
    return this.smartDeduplicateFindings(findings);
  }

  /**
   * Identify functions and routes in code
   */
  identifyFunctions(code, lines) {
    const functionMap = new Map();
    const patterns = [
      /function\s+(\w+)\s*\(/g,
      /const\s+(\w+)\s*=\s*(?:async\s+)?(?:function|\([^)]*\)\s*=>)/g,
      /app\.(get|post|put|delete|patch)\s*\(\s*["']([^"']+)["']/g,
      /router\.(get|post|put|delete|patch)\s*\(\s*["']([^"']+)["']/g,
    ];
    
    lines.forEach((line, index) => {
      patterns.forEach(pattern => {
        pattern.lastIndex = 0;
        const match = pattern.exec(line);
        if (match) {
          const funcName = match[2] || match[1] || `anonymous_${index}`;
          functionMap.set(index + 1, funcName);
        }
      });
    });
    
    return functionMap;
  }

  /**
   * Find containing function for a line number
   */
  findContainingFunction(lineNumber, functionMap) {
    let closestFunc = 'global';
    let closestLine = 0;
    
    for (const [line, func] of functionMap.entries()) {
      if (line <= lineNumber && line > closestLine) {
        closestLine = line;
        closestFunc = func;
      }
    }
    
    return closestFunc;
  }

  /**
   * Create a finding object with enhanced metadata
   */
  createFinding(category, matchedCode, filename, line, language, containingFunction = 'global') {
    // Get CWE ID from category
    const cweId = Taxonomy.getCweByCategory(category);
    
    // Get taxonomy information
    const t = Taxonomy.getByCwe(cweId) || {};
    const severity = t.defaultSeverity || 'medium';
    const owasp = t.owasp ? { category: t.owasp } : { category: 'A06:2021 - Vulnerable and Outdated Components' };
    
    // Get enhanced remediation from knowledge base
    const remediation = remediationKnowledge.getRemediation(cweId, language);
    
    return {
      id: `${category}-${filename}-${line}`,
      file: filename,
      line: line,
      column: 0,
      function: containingFunction,
      severity: severity,
      title: t.title || 'Security Issue',
      message: `${t.title || 'Security Issue'} vulnerability detected`,
      description: `Potential ${t.title || 'security issue'} found in ${filename} at line ${line}`,
      cwe: cweId,
      cweId: cweId,
      owasp: owasp,
      category: t.category || 'unknown',
      check_id: category,
      snippet: matchedCode.substring(0, 100),
      language: language,
      cvss: this.estimateCVSS(severity),
      remediation: remediation.languageSpecific || remediation,
      risk: remediation.risk,
      testing: remediation.testing
    };
  }

  /**
   * Perform additional heuristic checks
   */
  performHeuristicChecks(code, filename, language, findings) {
    if (language === 'javascript') {
      // Check for Express routes without validation
      if (code.includes('app.post') || code.includes('app.put')) {
        if (!code.includes('express-validator') && !code.includes('joi') && !code.includes('yup')) {
          findings.push({
            id: 'missing-validation-' + filename,
            file: filename,
            line: 0,
            function: 'global',
            severity: 'medium',
            title: 'Missing Input Validation',
            message: 'API endpoints detected without explicit input validation',
            description: 'Consider using express-validator, joi, or yup for input validation',
            cwe: 'CWE-20',
            owasp: { category: 'A03:2021 - Injection' },
            cvss: { baseScore: 5.3 },
            remediation: remediationKnowledge.getRemediation('CWE-20', language)
          });
        }
      }
      
      // Check for missing security headers
      if (code.includes('express()') && !code.includes('helmet')) {
        findings.push({
          id: 'missing-helmet-' + filename,
          file: filename,
          line: 0,
          function: 'global',
          severity: 'low',
          title: 'Missing Security Headers',
          message: 'Express app without Helmet security headers',
          description: 'Consider using helmet middleware to set security headers',
          cwe: 'CWE-693',
          owasp: { category: 'A05:2021 - Security Misconfiguration' },
          cvss: { baseScore: 3.1 },
          remediation: remediationKnowledge.getRemediation('CWE-693', language)
        });
      }
      
      // Check for missing CSRF protection
      if (code.includes('app.post') && !code.includes('csrf') && !code.includes('csurf')) {
        findings.push({
          id: 'missing-csrf-' + filename,
          file: filename,
          line: 0,
          function: 'global',
          severity: 'medium',
          title: 'Missing CSRF Protection',
          message: 'POST endpoints without CSRF protection',
          description: 'Consider implementing CSRF tokens',
          cwe: 'CWE-352',
          owasp: { category: 'A01:2021 - Broken Access Control' },
          cvss: { baseScore: 6.5 },
          remediation: remediationKnowledge.getRemediation('CWE-352', language)
        });
      }
      
      // Check for open redirects
      if (code.match(/res\.redirect\s*\([^)]*req\.(query|params|body)/gi)) {
        findings.push({
          id: 'open-redirect-' + filename,
          file: filename,
          line: 0,
          function: 'global',
          severity: 'medium',
          title: 'Open Redirect',
          message: 'Potential open redirect vulnerability',
          description: 'Validate redirect URLs against a whitelist',
          cwe: 'CWE-601',
          owasp: { category: 'A01:2021 - Broken Access Control' },
          cvss: { baseScore: 6.1 },
          remediation: remediationKnowledge.getRemediation('CWE-601', language)
        });
      }
    }
  }

  /**
   * Smart deduplication with grouping by function/route
   */
  smartDeduplicateFindings(findings) {
    const grouped = new Map();
    
    findings.forEach(finding => {
      const key = `${finding.file}-${finding.function}-${finding.cwe}`;
      
      if (!grouped.has(key)) {
        grouped.set(key, {
          ...finding,
          lines: [finding.line],
          occurrences: 1
        });
      } else {
        const existing = grouped.get(key);
        existing.lines.push(finding.line);
        existing.occurrences++;
        
        // Update message to show multiple occurrences
        if (existing.occurrences === 2) {
          existing.message = `${existing.title} vulnerability detected (multiple occurrences)`;
          existing.description = `${existing.title} found in ${existing.file} at lines: ${existing.lines.join(', ')}`;
        } else {
          existing.description = `${existing.title} found in ${existing.file} at lines: ${existing.lines.join(', ')}`;
        }
      }
    });
    
    return Array.from(grouped.values());
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
}

module.exports = { ASTVulnerabilityScanner };