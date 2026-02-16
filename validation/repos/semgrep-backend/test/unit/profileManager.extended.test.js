const ProfileManager = require('../../src/contextInference/profiles/profileManager');

describe('ProfileManager - Extended Coverage', () => {
  let pm;

  beforeEach(() => {
    pm = new ProfileManager();
  });

  describe('Profile Validation - Deep', () => {
    test('should validate profile with all fields', () => {
      const profile = {
        name: 'test-profile',
        description: 'Test profile',
        version: '1.0.0',
        contextFactors: {
          weights: {
            internetFacing: 0.2,
            production: 0.15
          },
          enabled: {
            internetFacing: true,
            production: true
          },
          exploitCaps: {
            kev: 0.25,
            epss: 0.25
          },
          totalLiftCap: 0.7
        },
        scoring: {
          severityPoints: {
            critical: 25,
            high: 15,
            medium: 8,
            low: 3,
            info: 1
          },
          riskThresholds: {
            critical: 80,
            high: 60,
            medium: 40,
            low: 20,
            minimal: 0
          }
        },
        features: {
          contextInference: {
            js: { routes: true, auth: true, pii: true },
            py: { routes: true, auth: true, pii: true },
            java: { routes: true, auth: true, pii: true }
          }
        }
      };

      const result = pm.validateProfile(profile);
      expect(result.valid).toBe(true);
    });

    test('should reject profile with missing version', () => {
      const profile = {
        name: 'test',
        description: 'test'
      };
      const result = pm.validateProfile(profile);
      expect(result.valid).toBe(false);
    });

    test('should validate profile with minimal required fields', () => {
      const profile = {
        name: 'minimal',
        description: 'Minimal profile',
        version: '1.0.0'
      };
      const result = pm.validateProfile(profile);
      expect(result).toBeDefined();
    });

    test('should handle profile with invalid contextFactors', () => {
      const profile = {
        name: 'test',
        description: 'test',
        version: '1.0.0',
        contextFactors: 'invalid'
      };
      const result = pm.validateProfile(profile);
      expect(result).toBeDefined();
    });

    test('should handle profile with invalid scoring', () => {
      const profile = {
        name: 'test',
        description: 'test',
        version: '1.0.0',
        scoring: 'invalid'
      };
      const result = pm.validateProfile(profile);
      expect(result).toBeDefined();
    });
  });

  describe('Profile Translation', () => {
    test('should translate default profile correctly', () => {
      const profile = pm.getDefaultProfile();
      const config = pm.translateProfileToCalculatorConfig(profile);
      
      expect(config).toBeDefined();
      expect(config).toHaveProperty('fileLevel');
      expect(config).toHaveProperty('vulnerabilityLevel');
    });

    test('should include file-level configuration', () => {
      const profile = pm.getDefaultProfile();
      const config = pm.translateProfileToCalculatorConfig(profile);
      
      expect(config.fileLevel).toBeDefined();
      expect(config.fileLevel).toHaveProperty('severityPoints');
      expect(config.fileLevel).toHaveProperty('riskThresholds');
    });

    test('should include vulnerability-level configuration', () => {
      const profile = pm.getDefaultProfile();
      const config = pm.translateProfileToCalculatorConfig(profile);
      
      expect(config.vulnerabilityLevel).toBeDefined();
      expect(config.vulnerabilityLevel).toHaveProperty('severityThresholds');
    });

    test('should translate custom profile', () => {
      const profile = {
        name: 'custom',
        description: 'Custom',
        version: '1.0.0',
        contextFactors: {
          weights: { internetFacing: 0.3 },
          enabled: { internetFacing: true },
          exploitCaps: { kev: 0.2 },
          totalLiftCap: 0.5
        },
        scoring: {
          severityPoints: {
            critical: 30,
            high: 20,
            medium: 10,
            low: 5,
            info: 1
          },
          riskThresholds: {
            critical: 90,
            high: 70,
            medium: 50,
            low: 30,
            minimal: 0
          }
        }
      };

      const config = pm.translateProfileToCalculatorConfig(profile);
      expect(config).toBeDefined();
      expect(config.fileLevel.severityPoints.critical).toBe(30);
    });
  });

  describe('Profile Properties', () => {
    test('should have valid default profile name', () => {
      const profile = pm.getDefaultProfile();
      expect(typeof profile.name).toBe('string');
      expect(profile.name.length).toBeGreaterThan(0);
    });

    test('should have valid default profile description', () => {
      const profile = pm.getDefaultProfile();
      expect(typeof profile.description).toBe('string');
      expect(profile.description.length).toBeGreaterThan(0);
    });

    test('should have context factors in default profile', () => {
      const profile = pm.getDefaultProfile();
      expect(profile.contextFactors).toBeDefined();
      expect(profile.contextFactors.weights).toBeDefined();
      expect(profile.contextFactors.enabled).toBeDefined();
    });

    test('should have scoring config in default profile', () => {
      const profile = pm.getDefaultProfile();
      expect(profile.scoring).toBeDefined();
      expect(profile.scoring.severityPoints).toBeDefined();
      expect(profile.scoring.riskThresholds).toBeDefined();
    });

    test('should have features config in default profile', () => {
      const profile = pm.getDefaultProfile();
      expect(profile.features).toBeDefined();
      expect(profile.features.contextInference).toBeDefined();
    });

    test('should have version in default profile', () => {
      const profile = pm.getDefaultProfile();
      expect(profile.version).toBeDefined();
      expect(typeof profile.version).toBe('string');
    });
  });

  describe('Config Structure', () => {
    test('should produce consistent config structure', () => {
      const profile1 = pm.getDefaultProfile();
      const profile2 = pm.getDefaultProfile();
      
      const config1 = pm.translateProfileToCalculatorConfig(profile1);
      const config2 = pm.translateProfileToCalculatorConfig(profile2);
      
      expect(Object.keys(config1)).toEqual(Object.keys(config2));
    });

    test('should include all severity levels', () => {
      const profile = pm.getDefaultProfile();
      const config = pm.translateProfileToCalculatorConfig(profile);
      
      const severityPoints = config.fileLevel.severityPoints;
      expect(severityPoints).toHaveProperty('critical');
      expect(severityPoints).toHaveProperty('high');
      expect(severityPoints).toHaveProperty('medium');
      expect(severityPoints).toHaveProperty('low');
      expect(severityPoints).toHaveProperty('info');
    });

    test('should include all risk thresholds', () => {
      const profile = pm.getDefaultProfile();
      const config = pm.translateProfileToCalculatorConfig(profile);
      
      const thresholds = config.fileLevel.riskThresholds;
      expect(thresholds).toHaveProperty('critical');
      expect(thresholds).toHaveProperty('high');
      expect(thresholds).toHaveProperty('medium');
      expect(thresholds).toHaveProperty('low');
      expect(thresholds).toHaveProperty('minimal');
    });
  });

  describe('Edge Cases', () => {
    test('should handle profile without optional fields', () => {
      const profile = {
        name: 'minimal',
        description: 'test',
        version: '1.0.0'
      };
      const config = pm.translateProfileToCalculatorConfig(profile);
      expect(config).toBeDefined();
    });

    test('should handle empty contextFactors', () => {
      const profile = {
        name: 'test',
        description: 'test',
        version: '1.0.0',
        contextFactors: {}
      };
      const config = pm.translateProfileToCalculatorConfig(profile);
      expect(config).toBeDefined();
    });

    test('should handle empty scoring', () => {
      const profile = {
        name: 'test',
        description: 'test',
        version: '1.0.0',
        scoring: {}
      };
      const config = pm.translateProfileToCalculatorConfig(profile);
      expect(config).toBeDefined();
    });

    test('should validate profile structure consistency', () => {
      const profile = pm.getDefaultProfile();
      expect(profile).toHaveProperty('name');
      expect(profile).toHaveProperty('description');
      expect(profile).toHaveProperty('version');
    });
  });

  describe('Profile Modification', () => {
    test('should handle modified context weights', () => {
      const profile = pm.getDefaultProfile();
      profile.contextFactors.weights.internetFacing = 0.5;
      
      const result = pm.validateProfile(profile);
      expect(result.valid).toBe(true);
    });

    test('should handle modified severity points', () => {
      const profile = pm.getDefaultProfile();
      profile.scoring.severityPoints.critical = 50;
      
      const config = pm.translateProfileToCalculatorConfig(profile);
      expect(config.fileLevel.severityPoints.critical).toBe(50);
    });

    test('should handle modified risk thresholds', () => {
      const profile = pm.getDefaultProfile();
      profile.scoring.riskThresholds.critical = 95;
      
      const config = pm.translateProfileToCalculatorConfig(profile);
      expect(config.fileLevel.riskThresholds.critical).toBe(95);
    });
  });
});