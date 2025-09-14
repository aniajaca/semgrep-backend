// taxonomy.js - Centralized vulnerability taxonomy mapping
const path = require('path');
const fs = require('fs');

// Load taxonomy from external file
const taxonomyPath = path.join(__dirname, 'data', 'security-taxonomy.json');
const taxonomyData = JSON.parse(fs.readFileSync(taxonomyPath, 'utf8'));

class Taxonomy {
  constructor() {
    // Load from external file
    this.cweMap = taxonomyData.cwe || {};
    this.categories = taxonomyData.categories || {};
    this.severityLevels = taxonomyData.severityLevels || {};
    
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
  
  getByCwe(cweId) {
    if (!cweId) return null;
    
    let cweString;
    if (typeof cweId === 'object' && cweId !== null) {
      cweString = cweId.id || cweId.cweId || cweId.value || '';
    } else {
      cweString = String(cweId);
    }
    
    if (!cweString || cweString === 'undefined' || cweString === 'null' || cweString === '[object Object]') {
      return this.cweMap['CWE-1'] || null;
    }
    
    const normalized = cweString.toUpperCase().startsWith('CWE-') 
      ? cweString.toUpperCase() 
      : `CWE-${cweString}`;
    
    return this.cweMap[normalized] || this.cweMap['CWE-1'];
  }
  
  getCweByCategory(category) {
    return this.categoryPatterns[category] || 'CWE-1';
  }
  
  getByOwasp(owaspCategory) {
    const results = [];
    for (const [cwe, data] of Object.entries(this.cweMap)) {
      if (data && data.owasp === owaspCategory) {
        results.push({ cwe, ...data });
      }
    }
    return results;
  }
  
  getByCategory(category) {
    const results = [];
    for (const [cwe, data] of Object.entries(this.cweMap)) {
      if (data && data.category === category) {
        results.push({ cwe, ...data });
      }
    }
    return results;
  }
  
  getCategoryForCwe(cwe) {
    if (!cwe) return 'unknown';
    
    let cweString;
    if (typeof cwe === 'object' && cwe !== null) {
      cweString = cwe.id || cwe.cweId || cwe.value || '';
    } else {
      cweString = String(cwe);
    }
    
    if (!cweString || cweString === 'undefined' || cweString === 'null' || cweString === '[object Object]') {
      return 'unknown';
    }
    
    const normalized = cweString.toUpperCase().startsWith('CWE-') 
      ? cweString.toUpperCase() 
      : `CWE-${cweString}`;
    
    const cweData = this.cweMap[normalized];
    if (cweData && cweData.category) {
      return cweData.category;
    }
    
    for (const [category, cweId] of Object.entries(this.categoryPatterns)) {
      if (cweId === normalized) {
        return category;
      }
    }
    
    return 'unknown';
  }
  
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
  
  getAllCategories() {
    return this.categories || {};
  }
  
  getSeverityLevel(severity) {
    if (!severity) {
      return {
        score: 0,
        color: '#999999',
        sla: 'Not defined'
      };
    }
    
    const severityLevels = this.severityLevels || {};
    return severityLevels[severity.toLowerCase()] || {
      score: 0,
      color: '#999999',
      sla: 'Not defined'
    };
  }
  
  hasCwe(cweId) {
    if (!cweId) return false;
    
    let cweString;
    if (typeof cweId === 'object' && cweId !== null) {
      cweString = cweId.id || cweId.cweId || cweId.value || '';
    } else {
      cweString = String(cweId);
    }
    
    if (!cweString || cweString === 'undefined' || cweString === 'null' || cweString === '[object Object]') {
      return false;
    }
    
    const normalized = cweString.toUpperCase().startsWith('CWE-') 
      ? cweString.toUpperCase() 
      : `CWE-${cweString}`;
    return this.cweMap.hasOwnProperty(normalized);
  }
  
  getAllCwes() {
    return Object.entries(this.cweMap).map(([id, data]) => ({
      id,
      ...data
    }));
  }
  
  getCweCountBySeverity() {
    const counts = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0
    };
    
    Object.values(this.cweMap).forEach(cwe => {
      if (cwe) {
        const severity = (cwe.defaultSeverity || 'medium').toLowerCase();
        if (counts.hasOwnProperty(severity)) {
          counts[severity]++;
        }
      }
    });
    
    return counts;
  }
  
  searchCwes(searchTerm) {
    if (!searchTerm) return [];
    
    const term = String(searchTerm).toLowerCase();
    const results = [];
    
    for (const [id, data] of Object.entries(this.cweMap)) {
      if (data && 
          ((data.title && data.title.toLowerCase().includes(term)) || 
           (data.category && data.category.toLowerCase().includes(term)) ||
           id.toLowerCase().includes(term))) {
        results.push({ id, ...data });
      }
    }
    
    return results;
  }
}

module.exports = new Taxonomy();