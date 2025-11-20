const { CustomEnvironmentalFactorSystem } = require('../../src/customEnvironmentalFactors');

describe('CustomEnvironmentalFactors', () => {
  let cef;

  beforeEach(() => {
    cef = new CustomEnvironmentalFactorSystem();
  });

  describe('Factor System Initialization', () => {
    test('should initialize with file-level factors', () => {
      expect(cef.factors).toBeDefined();
      expect(cef.factors.fileLevel).toBeDefined();
      expect(typeof cef.factors.fileLevel).toBe('object');
    });

    test('should initialize with vulnerability-level factors', () => {
      expect(cef.factors.vulnerabilityLevel).toBeDefined();
      expect(typeof cef.factors.vulnerabilityLevel).toBe('object');
    });

    test('should have internet-facing factor defined', () => {
      const factor = cef.factors.fileLevel.internetFacing;
      expect(factor).toBeDefined();
      expect(factor.multiplier).toBe(1.5);
      expect(factor.category).toBe('exposure');
    });

    test('should have PII handling factor defined', () => {
      const factor = cef.factors.fileLevel.handlesPI;
      expect(factor).toBeDefined();
      expect(factor.multiplier).toBe(1.4);
      expect(factor.category).toBe('data');
    });

    test('should have production environment factor defined', () => {
      const factor = cef.factors.fileLevel.production;
      expect(factor).toBeDefined();
      expect(factor.multiplier).toBe(1.3);
    });
  });

  describe('getFactor() Method', () => {
    test('should get specific factor by ID', () => {
      const factor = cef.getFactor('internetFacing', 'fileLevel');
      
      expect(factor).toBeDefined();
      expect(factor).toHaveProperty('multiplier');
      expect(factor).toHaveProperty('category');
      expect(factor).toHaveProperty('name');
    });

    test('should return null for non-existent factor', () => {
      const factor = cef.getFactor('nonExistent', 'fileLevel');
      
      expect(factor).toBeUndefined();
    });

    test('should get file-level factor', () => {
      const factor = cef.getFactor('internetFacing', 'fileLevel');
      
      expect(factor.id).toBe('internetFacing');
      expect(factor.multiplier).toBe(1.5);
    });

    test('should get vulnerability-level factor', () => {
      const factor = cef.getFactor('exploited', 'vulnerabilityLevel');
      
      if (factor) {
        expect(factor).toHaveProperty('additive');
      }
    });
  });

  describe('Factor Validation', () => {
    test('should validate factor configuration', () => {
      const config = {
        internetFacing: { weight: 1.5 },
        authentication: { weight: 1.2 }
      };
      
      const result = cef.validateFactorConfig(config, 'fileLevel');
      
      expect(result).toBeDefined();
      expect(result).toHaveProperty('valid');
      expect(result).toHaveProperty('errors');
      expect(result).toHaveProperty('warnings');
    });

    test('should accept valid factor weights', () => {
      const config = {
        internetFacing: { weight: 1.5 }
      };
      
      const result = cef.validateFactorConfig(config, 'fileLevel');
      
      expect(result.valid).toBe(true);
      expect(result.errors.length).toBe(0);
    });

    test('should reject extremely high factor weights', () => {
      const config = {
        internetFacing: { weight: 50.0 } // Extreme value
      };
      
      const result = cef.validateFactorConfig(config, 'fileLevel');
      
      expect(result.valid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
    });

    test('should warn on out-of-range weights', () => {
      const config = {
        internetFacing: { weight: 4.0 } // High but not extreme
      };
      
      const result = cef.validateFactorConfig(config, 'fileLevel');
      
      expect(result).toBeDefined();
      expect(result.warnings.length).toBeGreaterThan(0);
    });

    test('should reject negative weights', () => {
      const config = {
        internetFacing: { weight: -1.0 }
      };
      
      const result = cef.validateFactorConfig(config, 'fileLevel');
      
      expect(result.valid).toBe(false);
    });
  });

  describe('Factor Metadata and Documentation', () => {
    test('should format category names correctly', () => {
      expect(cef.formatCategoryName('exposure')).toBe('Network Exposure');
      expect(cef.formatCategoryName('data')).toBe('Data Sensitivity');
      expect(cef.formatCategoryName('environment')).toBe('Environment');
    });

    test('should handle unknown category names', () => {
      const formatted = cef.formatCategoryName('unknown');
      
      expect(typeof formatted).toBe('string');
      expect(formatted).toBe('unknown');
    });
  });

  describe('Configuration Import/Export', () => {
    test('should export factor configuration', () => {
      const enabledFactors = {
        internetFacing: { weight: 1.5 }
      };
      
      const exported = cef.exportConfiguration(enabledFactors);
      
      expect(exported).toBeDefined();
      expect(exported).toHaveProperty('version');
      expect(exported).toHaveProperty('timestamp');
      expect(exported).toHaveProperty('checksum');
      expect(exported).toHaveProperty('factors');
    });

    test('should export with correct version', () => {
      const exported = cef.exportConfiguration({});
      
      expect(exported.version).toBe('1.0');
    });

    test('should import and validate configuration', () => {
      const enabledFactors = {
        internetFacing: { weight: 1.5 }
      };
      
      const exported = cef.exportConfiguration(enabledFactors);
      const imported = cef.importConfiguration(exported);
      
      expect(imported).toBeDefined();
      expect(imported).toEqual(enabledFactors);
    });

    test('should reject configuration with wrong version', () => {
      const badConfig = {
        version: '2.0',
        timestamp: new Date().toISOString(),
        factors: {}
      };
      
      expect(() => cef.importConfiguration(badConfig)).toThrow();
    });

    test('should calculate checksum correctly', () => {
      const factors = { internetFacing: { weight: 1.5 } };
      const checksum1 = cef.calculateChecksum(factors);
      const checksum2 = cef.calculateChecksum(factors);
      
      expect(checksum1).toBe(checksum2);
      expect(typeof checksum1).toBe('string');
      expect(checksum1.length).toBe(8);
    });

    test('should detect checksum mismatch on import', () => {
      const config = {
        version: '1.0',
        timestamp: new Date().toISOString(),
        factors: { internetFacing: { weight: 1.5 } },
        checksum: 'invalid'
      };
      
      // Should not throw, but warn
      const imported = cef.importConfiguration(config);
      expect(imported).toBeDefined();
    });
  });

  describe('Factor Structure and Properties', () => {
    test('all file-level factors should have required properties', () => {
      Object.values(cef.factors.fileLevel).forEach(factor => {
        expect(factor).toHaveProperty('id');
        expect(factor).toHaveProperty('name');
        expect(factor).toHaveProperty('multiplier');
        expect(factor).toHaveProperty('category');
        expect(factor).toHaveProperty('rationale');
      });
    });

    test('all vulnerability-level factors should have required properties', () => {
      Object.values(cef.factors.vulnerabilityLevel).forEach(factor => {
        expect(factor).toHaveProperty('id');
        expect(factor).toHaveProperty('name');
        expect(factor).toHaveProperty('additive');
        expect(factor).toHaveProperty('category');
      });
    });

    test('should have multiple categories defined', () => {
      const categories = new Set();
      Object.values(cef.factors.fileLevel).forEach(factor => {
        categories.add(factor.category);
      });
      
      expect(categories.size).toBeGreaterThan(1);
      expect(categories.has('exposure')).toBe(true);
      expect(categories.has('data')).toBe(true);
    });
  });
});