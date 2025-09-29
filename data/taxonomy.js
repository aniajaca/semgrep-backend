// taxonomy.js - Fixed taxonomy system with proper CWE category mapping
const fs = require('fs');
const path = require('path');

class Taxonomy {
  constructor() {
    // Try to load taxonomy data
    try {
      const taxonomyPath = path.join(__dirname, '../data/security-taxonomy.json');
      this.data = JSON.parse(fs.readFileSync(taxonomyPath, 'utf8'));
    } catch (error) {
      console.warn('Using fallback taxonomy data:', error.message);
      // Comprehensive fallback taxonomy
      this.data = this.getDefaultTaxonomy();
    }
    
    // Build CWE to category mapping
    this.cweToCategory = this.buildCweCategoryMap();
  }
  
  /**
   * Get default taxonomy data
   */
  getDefaultTaxonomy() {
    return {
      cwe: {
        'CWE-89': { id: 'CWE-89', title: 'SQL Injection', category: 'injection', defaultSeverity: 'critical', cvssBase: 8.9, owasp: 'A03:2021' },
        'CWE-78': { id: 'CWE-78', title: 'OS Command Injection', category: 'injection', defaultSeverity: 'critical', cvssBase: 9.0, owasp: 'A03:2021' },
        'CWE-79': { id: 'CWE-79', title: 'Cross-Site Scripting', category: 'xss', defaultSeverity: 'high', cvssBase: 6.5, owasp: 'A03:2021' },
        'CWE-798': { id: 'CWE-798', title: 'Hardcoded Credentials', category: 'authentication', defaultSeverity: 'critical', cvssBase: 7.5, owasp: 'A07:2021' },
        'CWE-22': { id: 'CWE-22', title: 'Path Traversal', category: 'pathTraversal', defaultSeverity: 'high', cvssBase: 7.5, owasp: 'A01:2021' },
        'CWE-327': { id: 'CWE-327', title: 'Weak Cryptography', category: 'cryptography', defaultSeverity: 'medium', cvssBase: 5.3, owasp: 'A02:2021' },
        'CWE-502': { id: 'CWE-502', title: 'Deserialization', category: 'deserialization', defaultSeverity: 'critical', cvssBase: 8.6, owasp: 'A08:2021' },
        'CWE-918': { id: 'CWE-918', title: 'SSRF', category: 'ssrf', defaultSeverity: 'high', cvssBase: 7.5, owasp: 'A10:2021' },
        'CWE-94': { id: 'CWE-94', title: 'Code Injection', category: 'injection', defaultSeverity: 'critical', cvssBase: 8.5, owasp: 'A03:2021' },
        'CWE-287': { id: 'CWE-287', title: 'Authentication Bypass', category: 'authentication', defaultSeverity: 'high', cvssBase: 7.5, owasp: 'A07:2021' },
        'CWE-352': { id: 'CWE-352', title: 'CSRF', category: 'accessControl', defaultSeverity: 'medium', cvssBase: 6.5, owasp: 'A01:2021' },
        'CWE-601': { id: 'CWE-601', title: 'Open Redirect', category: 'accessControl', defaultSeverity: 'medium', cvssBase: 6.1, owasp: 'A01:2021' },
        'CWE-611': { id: 'CWE-611', title: 'XXE', category: 'xxe', defaultSeverity: 'high', cvssBase: 7.5, owasp: 'A05:2021' },
        'CWE-90': { id: 'CWE-90', title: 'LDAP Injection', category: 'injection', defaultSeverity: 'high', cvssBase: 8.0, owasp: 'A03:2021' },
        'CWE-400': { id: 'CWE-400', title: 'Resource Exhaustion', category: 'dos', defaultSeverity: 'medium', cvssBase: 5.3, owasp: 'A06:2021' },
        'CWE-693': { id: 'CWE-693', title: 'Protection Mechanism Failure', category: 'accessControl', defaultSeverity: 'medium', cvssBase: 5.3, owasp: 'A05:2021' },
        'CWE-20': { id: 'CWE-20', title: 'Input Validation', category: 'validation', defaultSeverity: 'medium', cvssBase: 5.3, owasp: 'A03:2021' },
        'CWE-1321': { id: 'CWE-1321', title: 'Prototype Pollution', category: 'injection', defaultSeverity: 'high', cvssBase: 7.0, owasp: 'A03:2021' },
        'CWE-1': { id: 'CWE-1', title: 'Generic', category: 'unknown', defaultSeverity: 'medium', cvssBase: 5.0, owasp: 'A06:2021' }
      },
      categories: {
        injection: { name: 'Injection', priority: 'critical' },
        xss: { name: 'Cross-Site Scripting', priority: 'high' },
        authentication: { name: 'Authentication', priority: 'high' },
        cryptography: { name: 'Cryptography', priority: 'medium' },
        pathTraversal: { name: 'Path Traversal', priority: 'high' },
        deserialization: { name: 'Deserialization', priority: 'critical' },
        accessControl: { name: 'Access Control', priority: 'high' },
        ssrf: { name: 'SSRF', priority: 'high' },
        dos: { name: 'Denial of Service', priority: 'medium' },
        validation: { name: 'Input Validation', priority: 'medium' },
        xxe: { name: 'XXE', priority: 'high' },
        unknown: { name: 'Unknown', priority: 'medium' }
      },
      severityLevels: {
        critical: { score: 9.0, priority: 'P0' },
        high: { score: 7.0, priority: 'P1' },
        medium: { score: 5.0, priority: 'P2' },
        low: { score: 2.5, priority: 'P3' },
        info: { score: 0.0, priority: 'P4' }
      },
      cvssMapping: {
        ranges: [
          { min: 9.0, max: 10.0, severity: 'critical' },
          { min: 7.0, max: 8.9, severity: 'high' },
          { min: 4.0, max: 6.9, severity: 'medium' },
          { min: 0.1, max: 3.9, severity: 'low' },
          { min: 0.0, max: 0.0, severity: 'info' }
        ]
      },
      owaspTop10_2021: {
        'A01:2021': { name: 'Broken Access Control' },
        'A02:2021': { name: 'Cryptographic Failures' },
        'A03:2021': { name: 'Injection' },
        'A04:2021': { name: 'Insecure Design' },
        'A05:2021': { name: 'Security Misconfiguration' },
        'A06:2021': { name: 'Vulnerable and Outdated Components' },
        'A07:2021': { name: 'Identification and Authentication Failures' },
        'A08:2021': { name: 'Software and Data Integrity Failures' },
        'A09:2021': { name: 'Security Logging and Monitoring Failures' },
        'A10:2021': { name: 'Server-Side Request Forgery' }
      }
    };
  }
  
  /**
   * Build CWE to category mapping
   */
  buildCweCategoryMap() {
    const map = {};
    
    // From data
    if (this.data && this.data.cwe) {
      Object.entries(this.data.cwe).forEach(([cweId, info]) => {
        if (info.category) {
          map[cweId] = info.category;
        }
      });
    }
    
    // Additional mappings for common CWEs
    const additionalMappings = {
      'CWE-77': 'injection',
      'CWE-91': 'injection',
      'CWE-564': 'injection',
      'CWE-80': 'xss',
      'CWE-81': 'xss',
      'CWE-82': 'xss',
      'CWE-83': 'xss',
      'CWE-306': 'authentication',
      'CWE-307': 'authentication',
      'CWE-521': 'authentication',
      'CWE-522': 'authentication',
      'CWE-620': 'authentication',
      'CWE-23': 'pathTraversal',
      'CWE-35': 'pathTraversal',
      'CWE-36': 'pathTraversal',
      'CWE-73': 'pathTraversal',
      'CWE-98': 'pathTraversal',
      'CWE-328': 'cryptography',
      'CWE-326': 'cryptography',
      'CWE-329': 'cryptography',
      'CWE-330': 'cryptography',
      'CWE-759': 'cryptography',
      'CWE-760': 'cryptography',
      'CWE-915': 'deserialization',
      'CWE-1279': 'deserialization',
      'CWE-134': 'deserialization',
      'CWE-284': 'accessControl',
      'CWE-285': 'accessControl',
      'CWE-862': 'accessControl',
      'CWE-863': 'accessControl',
      'CWE-639': 'accessControl',
      'CWE-732': 'accessControl',
      'CWE-770': 'dos',
      'CWE-920': 'dos',
      'CWE-1050': 'dos',
      'CWE-399': 'dos',
      'CWE-405': 'dos',
      'CWE-532': 'validation',
      'CWE-943': 'injection'
    };
    
    Object.assign(map, additionalMappings);
    
    return map;
  }
  
  /**
   * Get CWE data by ID
   */
  getByCwe(cweId) {
    if (!cweId) return null;
    
    // Normalize CWE ID
    const normalized = String(cweId).toUpperCase();
    const cweKey = normalized.startsWith('CWE-') ? normalized : `CWE-${normalized}`;
    
    return this.data.cwe[cweKey] || this.data.cwe['CWE-1'];
  }
  
  /**
   * Get CWE by category name
   */
  getCweByCategory(categoryName) {
    const categoryMappings = {
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
      'ldapInjection': 'CWE-90',
      'missing-validation': 'CWE-20',
      'missing-helmet': 'CWE-693',
      'missing-csrf': 'CWE-352',
      'open-redirect': 'CWE-601'
    };
    
    return categoryMappings[categoryName] || 'CWE-1';
  }
  
  /**
   * Get category for a CWE (NEW METHOD - FIXES THE BUG)
   */
  getCategoryForCwe(cweId) {
    if (!cweId) return 'unknown';
    
    // Normalize CWE ID
    const normalized = String(cweId).toUpperCase();
    const cweKey = normalized.startsWith('CWE-') ? normalized : `CWE-${normalized}`;
    
    // Check map first
    if (this.cweToCategory[cweKey]) {
      return this.cweToCategory[cweKey];
    }
    
    // Check data
    if (this.data.cwe && this.data.cwe[cweKey]) {
      return this.data.cwe[cweKey].category || 'unknown';
    }
    
    // Fallback category inference based on CWE number ranges
    const cweNum = parseInt(cweKey.replace('CWE-', ''));
    if (cweNum >= 77 && cweNum <= 94) return 'injection';
    if (cweNum >= 79 && cweNum <= 85) return 'xss';
    if (cweNum >= 284 && cweNum <= 287) return 'authentication';
    if (cweNum >= 326 && cweNum <= 330) return 'cryptography';
    
    return 'unknown';
  }
  
  /**
   * Get CVSS base score for a CWE
   */
  getCvssBase(cweId) {
    const cweData = this.getByCwe(cweId);
    return cweData?.cvssBase || 5.0;
  }
  
  /**
   * Get severity for a CWE
   */
  getSeverity(cweId) {
    const cweData = this.getByCwe(cweId);
    return cweData?.defaultSeverity || 'medium';
  }
  
  /**
   * Convert CVSS score to severity
   */
  cvssToSeverity(score) {
    if (!this.data.cvssMapping) {
      // Fallback
      if (score >= 9.0) return 'critical';
      if (score >= 7.0) return 'high';
      if (score >= 4.0) return 'medium';
      if (score >= 0.1) return 'low';
      return 'info';
    }
    
    for (const range of this.data.cvssMapping.ranges) {
      if (score >= range.min && score <= range.max) {
        return range.severity;
      }
    }
    return 'medium';
  }
  
  /**
   * Get severity level data
   */
  getSeverityLevel(severity) {
    const normalized = String(severity).toLowerCase();
    return this.data.severityLevels[normalized] || this.data.severityLevels.medium;
  }
  
  /**
   * Get category data
   */
  getCategory(categoryName) {
    return this.data.categories[categoryName] || { name: 'Unknown', priority: 'low' };
  }
  
  /**
   * Get OWASP mapping
   */
  getOwasp(owaspId) {
    return this.data.owaspTop10_2021?.[owaspId] || { name: 'Unknown' };
  }
}

module.exports = new Taxonomy();