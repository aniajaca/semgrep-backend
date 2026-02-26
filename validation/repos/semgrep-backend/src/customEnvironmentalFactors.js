// customEnvironmentalFactors.js - Environmental and contextual risk multipliers for security assessment

/**
 * CustomEnvironmentalFactorSystem
 * 
 * This module provides environmental and contextual factors that modify security risk scores
 * based on deployment environment, data sensitivity, exposure, and business criticality.
 * 
 * Factors can be applied at two levels:
 * - fileLevel: Multipliers for overall file/project risk scores
 * - vulnerabilityLevel: Additive adjustments for individual vulnerability scores
 */
class CustomEnvironmentalFactorSystem {
  constructor(config = {}) {
    // Profile-driven multiplier overrides (falls back to validated defaults)
    const fileLevelOverrides = config.contextMultipliers || {};
    
    // Define all available factors with their impacts
    this.factors = {
      fileLevel: {
        // Network exposure factors
        internetFacing: {
          id: 'internetFacing',
          name: 'Internet-Facing System',
          description: 'System is directly accessible from the internet',
          multiplier: fileLevelOverrides.internetFacing || 1.5,
          category: 'exposure',
          rationale: 'Internet-facing systems have higher attack surface'
        },
        
        // Data sensitivity factors
        handlesPI: {
          id: 'handlesPI',
          name: 'Handles Personal Information',
          description: 'System processes or stores personal/sensitive data',
          multiplier: fileLevelOverrides.handlesPI || 1.4,
          category: 'data',
          rationale: 'PII breaches have severe regulatory and reputational impact'
        },
        
        // Environment factors
        production: {
          id: 'production',
          name: 'Production Environment',
          description: 'Code is deployed to production environment',
          multiplier: fileLevelOverrides.production || 1.3,
          category: 'environment',
          rationale: 'Production issues affect real users and business operations'
        },
        
        // System characteristics
        legacyCode: {
          id: 'legacyCode',
          name: 'Legacy System',
          description: 'Codebase is legacy or lacks modern security controls',
          multiplier: 1.2,
          category: 'technical-debt',
          rationale: 'Legacy systems often have accumulated vulnerabilities'
        },
        
        // Business criticality
        businessCritical: {
          id: 'businessCritical',
          name: 'Business Critical',
          description: 'System is critical to business operations',
          multiplier: 1.6,
          category: 'business',
          rationale: 'Critical systems require immediate attention'
        },
        
        // Compliance requirements
        compliance: {
          id: 'compliance',
          name: 'Compliance Required',
          description: 'System must meet regulatory compliance (PCI-DSS, HIPAA, GDPR)',
          multiplier: 1.3,
          category: 'regulatory',
          rationale: 'Compliance violations result in fines and legal issues'
        },
        
        // Third-party integration
        thirdPartyIntegration: {
          id: 'thirdPartyIntegration',
          name: 'Third-Party Integrations',
          description: 'System integrates with external third-party services',
          multiplier: 1.2,
          category: 'integration',
          rationale: 'Third-party integrations expand attack surface'
        },
        
        // Authentication complexity
        complexAuth: {
          id: 'complexAuth',
          name: 'Complex Authentication',
          description: 'System has complex authentication/authorization requirements',
          multiplier: 1.1,
          category: 'authentication',
          rationale: 'Complex auth systems are prone to implementation errors'
        }
      },
      
      vulnerabilityLevel: {
        // These add to CVSS scores rather than multiply
        internetFacing: {
          id: 'internetFacing',
          name: 'Internet Exposure',
          description: 'Vulnerability in internet-facing component',
          additive: 1.5,
          category: 'exposure',
          appliesTo: ['xss', 'injection', 'deserialization', 'pathTraversal']        },
        
        handlesPI: {
          id: 'handlesPI',
          name: 'PII Exposure Risk',
          description: 'Vulnerability could expose personal information',
          additive: 1.0,
          category: 'data',
          appliesTo: ['injection', 'pathTraversal', 'accessControl']
        },
        
        production: {
          id: 'production',
          name: 'Production Impact',
          description: 'Vulnerability affects production systems',
          additive: 0.8,
          category: 'environment',
          appliesTo: 'all'
        },
        
        legacyCode: {
          id: 'legacyCode',
          name: 'Legacy Code Complexity',
          description: 'Vulnerability in legacy code is harder to fix',
          additive: 0.5,
          category: 'technical-debt',
          appliesTo: 'all'
        },
        
        noWAF: {
          id: 'noWAF',
          name: 'No WAF Protection',
          description: 'No Web Application Firewall to mitigate',
          additive: 0.7,
          category: 'mitigation',
          appliesTo: ['xss', 'injection', 'pathTraversal']
        },
        
        testOrDevCode: {
          id: 'testOrDevCode',
          name: 'Test/Dev Code',
          description: 'Code in test or development paths - lower operational risk',
          additive: -4.0,
          category: 'environment',
          appliesTo: 'all'
        },

        publicAPI: {
          id: 'publicAPI',
          name: 'Public API Endpoint',
          description: 'Vulnerability in publicly accessible API',
          additive: 1.2,
          category: 'exposure',
          appliesTo: ['injection', 'authentication', 'dos']
        }
      }
    };
    
    // Preset profiles for common scenarios
    this.profiles = {
      'public-web-app': {
        name: 'Public Web Application',
        factors: ['internetFacing', 'production', 'handlesPI'],
        description: 'Public-facing web application in production'
      },
      'internal-tool': {
        name: 'Internal Tool',
        factors: ['production'],
        description: 'Internal business tool'
      },
      'legacy-system': {
        name: 'Legacy System',
        factors: ['legacyCode', 'production', 'businessCritical'],
        description: 'Legacy system requiring maintenance'
      },
      'api-gateway': {
        name: 'API Gateway',
        factors: ['internetFacing', 'production', 'publicAPI'],
        description: 'Public API gateway or service'
      },
      'development': {
        name: 'Development Environment',
        factors: [],
        description: 'Development or testing environment'
      }
    };
  }

  /**
   * Get all available factors for a specific level
   */
  getAllFactors(level = 'fileLevel') {
    return this.factors[level] || {};
  }

  /**
   * Get a specific factor by ID
   */
  getFactor(factorId, level = 'fileLevel') {
    return this.factors[level]?.[factorId];
  }

  /**
   * Apply factors to calculate multipliers and impacts
   */
  calculateWithCustomFactors(data, level = 'fileLevel', enabledFactors = {}) {
    const result = {
      appliedFactors: [],
      totalMultiplier: 1.0,
      totalAdditive: 0,
      factorBreakdown: {}
    };
    
    // Process each enabled factor
    Object.entries(enabledFactors).forEach(([factorId, config]) => {
      if (!config?.enabled) return;
      
      const factorDef = this.getFactor(factorId, level);
      if (!factorDef) return;
      
      // Check if factor applies to this vulnerability type (for vulnerability level)
      if (level === 'vulnerabilityLevel' && factorDef.appliesTo && factorDef.appliesTo !== 'all') {
        const vulnerabilityCategory = this.getVulnerabilityCategory(data);
        if (!factorDef.appliesTo.includes(vulnerabilityCategory)) {
          return; // Skip this factor
        }
      }
      
      // Apply the factor
      if (factorDef.multiplier) {
        const weight = config.weight || factorDef.multiplier;
        result.totalMultiplier *= weight;
        result.factorBreakdown[factorId] = {
          type: 'multiplier',
          value: weight,
          impact: `×${weight.toFixed(2)}`
        };
      } else if (factorDef.additive) {
        const value = config.value || factorDef.additive;
        result.totalAdditive += value;
        result.factorBreakdown[factorId] = {
          type: 'additive',
          value: value,
          impact: `+${value.toFixed(1)}`
        };
      }
      
      result.appliedFactors.push({
        id: factorId,
        name: factorDef.name,
        impact: result.factorBreakdown[factorId].impact,
        category: factorDef.category,
        rationale: factorDef.rationale || factorDef.description
      });
    });
    
    return result;
  }

  /**
   * Determine vulnerability category for factor application
   */
  getVulnerabilityCategory(vulnerability) {
    if (!vulnerability?.cwe) return 'unknown';
    
    const cwe = vulnerability.cwe.toUpperCase();
    
    // Map CWEs to categories
    if (['CWE-89', 'CWE-78', 'CWE-90', 'CWE-94'].includes(cwe)) return 'injection';
    if (['CWE-79', 'CWE-80', 'CWE-81'].includes(cwe)) return 'xss';
    if (['CWE-22', 'CWE-23', 'CWE-35'].includes(cwe)) return 'pathTraversal';
    if (['CWE-502', 'CWE-915'].includes(cwe)) return 'deserialization';
    if (['CWE-287', 'CWE-798', 'CWE-306'].includes(cwe)) return 'authentication';
    if (['CWE-284', 'CWE-285', 'CWE-862'].includes(cwe)) return 'accessControl';
    if (['CWE-400', 'CWE-770'].includes(cwe)) return 'dos';
    
    return 'unknown';
  }

  /**
   * Get a preset profile
   */
  getProfile(profileName) {
    return this.profiles[profileName];
  }

  /**
   * Apply a preset profile to get enabled factors
   */
  applyProfile(profileName) {
    const profile = this.profiles[profileName];
    if (!profile) return {};
    
    const enabledFactors = {};
    profile.factors.forEach(factorId => {
      enabledFactors[factorId] = { enabled: true };
    });
    
    return enabledFactors;
  }

  /**
   * Calculate impact summary for reporting
   */
  generateImpactSummary(appliedFactors) {
    if (!appliedFactors || appliedFactors.length === 0) {
      return 'No environmental factors applied - using baseline risk assessment.';
    }
    
    const categories = {};
    appliedFactors.forEach(factor => {
      if (!categories[factor.category]) {
        categories[factor.category] = [];
      }
      categories[factor.category].push(factor.name);
    });
    
    const summaryParts = [];
    Object.entries(categories).forEach(([category, factors]) => {
      const categoryName = this.formatCategoryName(category);
      summaryParts.push(`${categoryName}: ${factors.join(', ')}`);
    });
    
    return `Environmental factors applied - ${summaryParts.join('; ')}`;
  }

  /**
   * Format category name for display
   */
  formatCategoryName(category) {
    const names = {
      'exposure': 'Network Exposure',
      'data': 'Data Sensitivity',
      'environment': 'Environment',
      'technical-debt': 'Technical Debt',
      'business': 'Business Impact',
      'regulatory': 'Compliance',
      'integration': 'Integration Risk',
      'authentication': 'Auth Complexity',
      'mitigation': 'Mitigation Status'
    };
    return names[category] || category;
  }

  /**
   * Validate factor configuration
   */
  validateFactorConfig(config, level = 'fileLevel') {
    const errors = [];
    const warnings = [];
    
    Object.entries(config).forEach(([factorId, settings]) => {
      const factorDef = this.getFactor(factorId, level);
      
      if (!factorDef) {
        warnings.push(`Unknown factor: ${factorId}`);
        return;
      }
      
      if (settings.weight && factorDef.multiplier) {
        // Hard error for extreme values
        if (settings.weight < 0 || settings.weight > 10) {
          errors.push(`Factor ${factorId} weight ${settings.weight} is invalid (must be 0-10)`);
        }
        // Warning for out of recommended range
        else if (settings.weight < 0.5 || settings.weight > 3.0) {
          warnings.push(`Factor ${factorId} weight ${settings.weight} outside recommended range [0.5, 3.0]`);
        }
      }
      
      if (settings.value && factorDef.additive) {
        // Hard error for extreme values
        if (settings.value < -5 || settings.value > 10) {
          errors.push(`Factor ${factorId} value ${settings.value} is invalid (must be -5 to 10)`);
        }
        // Warning for out of recommended range
        else if (settings.value < 0 || settings.value > 3.0) {
          warnings.push(`Factor ${factorId} value ${settings.value} outside recommended range [0, 3.0]`);
        }
      }
    });
    
    return { valid: errors.length === 0, errors, warnings };
  }

  /**
   * Export configuration for persistence
   */
  exportConfiguration(enabledFactors) {
    return {
      version: '1.0',
      timestamp: new Date().toISOString(),
      factors: enabledFactors,
      checksum: this.calculateChecksum(enabledFactors)
    };
  }

  /**
   * Import configuration
   */
  importConfiguration(config) {
    if (config.version !== '1.0') {
      throw new Error(`Unsupported configuration version: ${config.version}`);
    }
    
    const checksum = this.calculateChecksum(config.factors);
    if (checksum !== config.checksum) {
      console.warn('Configuration checksum mismatch - config may have been modified');
    }
    
    return config.factors;
  }

  /**
   * Calculate checksum for configuration
   */
  calculateChecksum(factors) {
    const crypto = require('crypto');
    const str = JSON.stringify(factors, Object.keys(factors).sort());
    return crypto.createHash('sha256').update(str).digest('hex').substring(0, 8);
  }
}

// Export the class and a singleton instance
module.exports = { CustomEnvironmentalFactorSystem };
module.exports.factorSystem = new CustomEnvironmentalFactorSystem();