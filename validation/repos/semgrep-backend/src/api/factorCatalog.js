/**
 * Factor Catalog - Central registry of all risk factors
 * Defines how each factor affects scoring at vulnerability and file levels
 */

module.exports = {
  /**
   * Vulnerability-level factors
   * Applied to individual findings to adjust their risk scores
   */
  vulnerability: {
    // Exploit factors (with precedence)
    kevListed: {
      name: 'Known Exploited Vulnerability (KEV)',
      description: 'Listed in CISA KEV database as actively exploited',
      appliesTo: 'vulnerability',
      type: 'additive',
      defaultWeight: 0.25,
      maxValue: 0.25,
      autoApply: true,
      requiresConfirmation: false,
      precedence: 1,  // Highest precedence
      source: 'external_database'
    },
    publicExploit: {
      name: 'Public Exploit Available',
      description: 'Exploit code is publicly available',
      appliesTo: 'vulnerability',
      type: 'additive',
      defaultWeight: 0.15,
      maxValue: 0.15,
      autoApply: true,
      requiresConfirmation: false,
      precedence: 2,  // Medium precedence
      source: 'external_database'
    },
    epss: {
      name: 'EPSS Score',
      description: 'Exploit Prediction Scoring System probability',
      appliesTo: 'vulnerability',
      type: 'additive',
      defaultWeight: 0.25,  // Applied as weight * epss_score
      maxValue: 0.25,
      autoApply: true,
      requiresConfirmation: false,
      precedence: 3,  // Lowest precedence
      source: 'external_database',
      calculation: 'min(0.25, 0.25 * epss_score)'
    },
    
    // Environmental factors
    internetFacing: {
      name: 'Internet Facing',
      description: 'Component is exposed to the internet',
      appliesTo: 'vulnerability',
      type: 'additive',
      defaultWeight: 0.20,
      maxValue: 0.20,
      autoApply: false,
      requiresConfirmation: false,
      source: 'context_inference',
      indicators: ['external API endpoints', 'public routes', 'cloud services']
    },
    production: {
      name: 'Production Environment',
      description: 'Running in production environment',
      appliesTo: 'vulnerability',
      type: 'additive',
      defaultWeight: 0.15,
      maxValue: 0.15,
      autoApply: false,
      requiresConfirmation: false,
      source: 'context_inference',
      indicators: ['production configs', 'prod URLs', 'production flags']
    },
    handlesPI: {
      name: 'Handles Personal Information',
      description: 'Processes or stores personal/sensitive data',
      appliesTo: 'vulnerability',
      type: 'additive',
      defaultWeight: 0.15,
      maxValue: 0.15,
      autoApply: false,
      requiresConfirmation: false,
      source: 'context_inference',
      indicators: ['PII patterns', 'user data', 'payment info', 'health data']
    },
    userBaseLarge: {
      name: 'Large User Base',
      description: 'Affects many users (>10k)',
      appliesTo: 'vulnerability',
      type: 'additive',
      defaultWeight: 0.10,
      maxValue: 0.10,
      autoApply: false,
      requiresConfirmation: true,
      source: 'manual_input'
    },
    regulated: {
      name: 'Regulatory Compliance',
      description: 'Subject to regulatory requirements (GDPR, HIPAA, PCI)',
      appliesTo: 'vulnerability',
      type: 'additive',
      defaultWeight: 0.15,
      maxValue: 0.15,
      autoApply: false,
      requiresConfirmation: true,
      source: 'manual_input'
    },
    
    // System characteristics
    legacyCode: {
      name: 'Legacy System',
      description: 'Old codebase with technical debt',
      appliesTo: 'vulnerability',
      type: 'additive',
      defaultWeight: 0.10,
      maxValue: 0.10,
      autoApply: false,
      requiresConfirmation: false,
      source: 'context_inference',
      indicators: ['old dependencies', 'deprecated APIs', 'legacy patterns']
    },
    businessCritical: {
      name: 'Business Critical',
      description: 'Critical to business operations',
      appliesTo: 'vulnerability',
      type: 'additive',
      defaultWeight: 0.20,
      maxValue: 0.20,
      autoApply: false,
      requiresConfirmation: true,
      source: 'manual_input'
    },
    thirdPartyIntegration: {
      name: 'Third-Party Integration',
      description: 'Integrates with external services',
      appliesTo: 'vulnerability',
      type: 'additive',
      defaultWeight: 0.10,
      maxValue: 0.10,
      autoApply: false,
      requiresConfirmation: false,
      source: 'context_inference',
      indicators: ['API calls', 'webhooks', 'external services']
    },
    complexAuth: {
      name: 'Complex Authentication',
      description: 'Has complex auth/authz logic',
      appliesTo: 'vulnerability',
      type: 'additive',
      defaultWeight: 0.10,
      maxValue: 0.10,
      autoApply: false,
      requiresConfirmation: false,
      source: 'context_inference',
      indicators: ['OAuth', 'SAML', 'multi-factor', 'role-based']
    },
    
    // Special case: low confidence reduces score
    lowConfidence: {
      name: 'Low Confidence Finding',
      description: 'Finding has low confidence score',
      appliesTo: 'vulnerability',
      type: 'multiplier',
      defaultWeight: 0.5,  // Reduces score by 50%
      minValue: 0.5,
      maxValue: 1.0,
      autoApply: true,
      requiresConfirmation: false,
      source: 'scanner',
      calculation: 'if confidence < 0.5: score * (0.5 + confidence)'
    }
  },
  
  /**
   * File-level factors
   * Applied when aggregating multiple vulnerabilities in a file
   */
  file: {
    publicAPI: {
      name: 'Public API Endpoint',
      description: 'File contains public API endpoints',
      appliesTo: 'file',
      type: 'additive',
      defaultWeight: 15,  // Points added to exposure score
      maxValue: 15,
      autoApply: true,
      requiresConfirmation: false,
      source: 'context_inference'
    },
    userInput: {
      name: 'User Input Handling',
      description: 'File handles user input',
      appliesTo: 'file',
      type: 'additive',
      defaultWeight: 10,
      maxValue: 10,
      autoApply: true,
      requiresConfirmation: false,
      source: 'context_inference'
    },
    noAuth: {
      name: 'No Authentication',
      description: 'File has endpoints without authentication',
      appliesTo: 'file',
      type: 'additive',
      defaultWeight: 10,
      maxValue: 10,
      autoApply: true,
      requiresConfirmation: false,
      source: 'context_inference'
    },
    coreFile: {
      name: 'Core System File',
      description: 'Central to application functionality',
      appliesTo: 'file',
      type: 'multiplier',
      defaultWeight: 1.5,
      minValue: 1.0,
      maxValue: 2.0,
      autoApply: false,
      requiresConfirmation: true,
      source: 'manual_input'
    },
    highComplexity: {
      name: 'High Complexity',
      description: 'File has high cyclomatic complexity',
      appliesTo: 'file',
      type: 'multiplier',
      defaultWeight: 1.2,
      minValue: 1.0,
      maxValue: 1.5,
      autoApply: false,
      requiresConfirmation: false,
      source: 'static_analysis'
    }
  },
  
  /**
   * Constraints and rules
   */
  constraints: {
    // Maximum total lift for vulnerability factors
    totalLiftCap: 0.70,
    
    // Caps for specific factor categories
    exploitFactorsCap: 0.25,  // Only one exploit factor applies
    environmentalFactorsCap: 0.50,
    
    // File-level caps
    exposureCap: 25,  // Max exposure points
    densityCap: 30,   // Max density points
    diversityCap: 20, // Max diversity points
    
    // Ensure scores stay in valid ranges
    minScore: 0,
    maxScore: 100,
    
    // Priority thresholds (must be monotonic)
    priorityThresholds: {
      P0: 80,  // >= 80
      P1: 65,  // >= 65
      P2: 50,  // >= 50
      P3: 0    // >= 0
    }
  },
  
  /**
   * Helper functions for factor management
   */
  utils: {
    /**
     * Get all factors that apply to a specific level
     */
    getFactorsByLevel(level) {
      return this[level] || {};
    },
    
    /**
     * Get factors that can be auto-applied
     */
    getAutoApplicableFactors(level) {
      const factors = this[level] || {};
      return Object.entries(factors)
        .filter(([_, config]) => config.autoApply)
        .reduce((acc, [key, config]) => {
          acc[key] = config;
          return acc;
        }, {});
    },
    
    /**
     * Get factors by source type
     */
    getFactorsBySource(source) {
      const result = {};
      ['vulnerability', 'file'].forEach(level => {
        Object.entries(this[level] || {}).forEach(([key, config]) => {
          if (config.source === source) {
            result[key] = { ...config, level };
          }
        });
      });
      return result;
    },
    
    /**
     * Validate factor weight is in valid range
     */
    validateWeight(factorKey, weight, level = 'vulnerability') {
      const factor = this[level]?.[factorKey];
      if (!factor) return false;
      
      if (factor.minValue && weight < factor.minValue) return false;
      if (factor.maxValue && weight > factor.maxValue) return false;
      
      return true;
    },
    
    /**
     * Apply precedence rules for exploit factors
     */
    applyExploitPrecedence(factors) {
      // Only one exploit factor applies (highest precedence wins)
      const exploitFactors = ['kevListed', 'publicExploit', 'epss'];
      
      for (const factor of exploitFactors) {
        if (factors[factor]) {
          // Remove lower precedence factors
          exploitFactors.forEach(f => {
            if (f !== factor && this.vulnerability[f]?.precedence > this.vulnerability[factor]?.precedence) {
              delete factors[f];
            }
          });
          break;
        }
      }
      
      return factors;
    }
  }
};