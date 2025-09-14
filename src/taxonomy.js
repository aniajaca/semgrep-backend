// taxonomy.js - Fixed version that handles both string and object CWE formats

/**
 * Get taxonomy info by CWE ID
 */
getByCwe(cweId) {
  if (!cweId) return null;
  
  // Handle both string and object formats
  let cweString;
  if (typeof cweId === 'object' && cweId !== null) {
    // Extract ID from object format (e.g., {id: 'CWE-89', name: 'SQL Injection'})
    cweString = cweId.id || cweId.cweId || cweId.value || '';
  } else {
    cweString = String(cweId);
  }
  
  // Check for empty/invalid values
  if (!cweString || cweString === 'undefined' || cweString === 'null' || cweString === '[object Object]') {
    return this.cweMap['CWE-1'] || null;
  }
  
  // Normalize CWE ID format
  const normalized = cweString.toUpperCase().startsWith('CWE-') 
    ? cweString.toUpperCase() 
    : `CWE-${cweString}`;
  
  return this.cweMap[normalized] || this.cweMap['CWE-1'];
}

/**
 * Get category for a specific CWE
 * @param {string|Object} cwe - CWE identifier (string or object with id property)
 * @returns {string} Category name
 */
getCategoryForCwe(cwe) {
  if (!cwe) return 'unknown';
  
  // Handle both string and object formats
  let cweString;
  if (typeof cwe === 'object' && cwe !== null) {
    // Extract ID from object format
    cweString = cwe.id || cwe.cweId || cwe.value || '';
  } else {
    cweString = String(cwe);
  }
  
  // Check for empty/invalid values
  if (!cweString || cweString === 'undefined' || cweString === 'null' || cweString === '[object Object]') {
    return 'unknown';
  }
  
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
 * Check if CWE exists
 */
hasCwe(cweId) {
  if (!cweId) return false;
  
  // Handle both string and object formats
  let cweString;
  if (typeof cweId === 'object' && cweId !== null) {
    cweString = cweId.id || cweId.cweId || cweId.value || '';
  } else {
    cweString = String(cweId);
  }
  
  // Check for empty/invalid values
  if (!cweString || cweString === 'undefined' || cweString === 'null' || cweString === '[object Object]') {
    return false;
  }
  
  const normalized = cweString.toUpperCase().startsWith('CWE-') 
    ? cweString.toUpperCase() 
    : `CWE-${cweString}`;
  return this.cweMap.hasOwnProperty(normalized);
}