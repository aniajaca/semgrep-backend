// taxonomy.js - Centralized vulnerability taxonomy mapping
const path = require('path');
const fs = require('fs');

// Load taxonomy from external file
const taxonomyPath = path.join(__dirname, 'data', 'security-taxonomy.json');
const taxonomyData = JSON.parse(fs.readFileSync(taxonomyPath, 'utf8'));

class Taxonomy {
  constructor() {
    // Load from external file
    this.cweMap = taxonomyData.cwe;
    this.categories = taxonomyData.categories;
    this.severityLevels = taxonomyData.severityLevels;
    
    // Category to CWE pattern mapping for scanner
    this.categoryPatterns = {
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
  }
  
  /**
   * Get taxonomy info by CWE ID
   */
  getByCwe(cweId) {
    if (!cweId) return null;
    
    // Ensure cweId is a string
    const cweString = String(cweId);
    
    // Normalize CWE ID format
    const normalized = cweString.toUpperCase().startsWith('CWE-') 
      ? cweString.toUpperCase() 
      : `CWE-${cweString}`;
    
    return this.cweMap[normalized] || this.cweMap['CWE-1'];
  }
  
  /**
   * Get CWE ID by pattern category
   */
  getCweByCategory(category) {
    return this.categoryPatterns[category] || 'CWE-1';
  }
  
  /**
   * Get all CWEs for a specific OWASP category
   */
  getByOwasp(owaspCategory) {
    const results = [];
    for (const [cwe, data] of Object.entries(this.cweMap)) {
      if (data.owasp === owaspCategory) {
        results.push({ cwe, ...data });
      }
    }
    return results;
  }
  
  /**
   * Get all CWEs for a specific category
   */
  getByCategory(category) {
    const results = [];
    for (const [cwe, data] of Object.entries(this.cweMap)) {
      if (data.category === category) {
        results.push({ cwe, ...data });
      }
    }
    return results;
  }
  
  /**
   * Get category for a specific CWE
   * @param {string} cwe - CWE identifier
   * @returns {string} Category name
   */
  getCategoryForCwe(cwe) {
    if (!cwe) return 'unknown';
    
    // Ensure cwe is a string
    const cweString = String(cwe);
    
    // Normalize CWE format
    const normalized = cweString.toUpperCase().startsWith('CWE-') 
      ? cweString.toUpperCase() 
      : `CWE-${cweString}`;
    
    // Look up in our CWE map
    const cweData = this.cweMap[normalized];
    if (cweData && cweData.category) {
      return cweData.category;
    }
    
    // Fallback: check category patterns
    for (const [category, cweId] of Object.entries(this.categoryPatterns)) {
      if (cweId === normalized) {
        return category;
      }
    }
    
    return 'unknown';
  }
  
  /**
   * Get severity ranking (for sorting)
   */
  getSeverityRank(severity) {
    const ranks = {
      'critical': 5,
      'high': 4,
      'medium': 3,
      'low': 2,
      'info': 1
    };
    return ranks[severity?.toLowerCase()] || 0;
  }
  
  /**
   * Get all categories
   */
  getAllCategories() {
    return this.categories || {};
  }
  
  /**
   * Get severity level info
   */
  getSeverityLevel(severity) {
    if (!severity) {
      return {
        score: 0,
        color: '#999999',
        sla: 'Not defined'
      };
    }
    
    return this.severityLevels?.[severity.toLowerCase()] || {
      score: 0,
      color: '#999999',
      sla: 'Not defined'
    };
  }
  
  /**
   * Check if CWE exists
   */
  hasCwe(cweId) {
    if (!cweId) return false;
    
    // Ensure cweId is a string
    const cweString = String(cweId);
    
    const normalized = cweString.toUpperCase().startsWith('CWE-') 
      ? cweString.toUpperCase() 
      : `CWE-${cweString}`;
    return this.cweMap.hasOwnProperty(normalized);
  }
  
  /**
   * Get all CWEs
   */
  getAllCwes() {
    return Object.entries(this.cweMap).map(([id, data]) => ({
      id,
      ...data
    }));
  }
  
  /**
   * Get CWE count by severity
   */
  getCweCountBySeverity() {
    const counts = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0
    };
    
    Object.values(this.cweMap).forEach(cwe => {
      const severity = (cwe.defaultSeverity || 'medium').toLowerCase();
      if (counts.hasOwnProperty(severity)) {
        counts[severity]++;
      }
    });
    
    return counts;
  }
  
  /**
   * Search CWEs by title or description
   */
  searchCwes(searchTerm) {
    if (!searchTerm) return [];
    
    const term = String(searchTerm).toLowerCase();
    const results = [];
    
    for (const [id, data] of Object.entries(this.cweMap)) {
      if ((data.title && data.title.toLowerCase().includes(term)) || 
          (data.category && data.category.toLowerCase().includes(term)) ||
          id.toLowerCase().includes(term)) {
        results.push({ id, ...data });
      }
    }
    
    return results;
  }
}

// Export singleton instance
module.exports = new Taxonomy();