const ProfileManager = require('../../src/contextInference/profiles/profileManager');

describe('ProfileManager', () => {
  let pm;

  beforeEach(() => {
    pm = new ProfileManager();
  });

  describe('Basic Operations', () => {
    test('should return default profile', () => {
      const profile = pm.getDefaultProfile();
      expect(profile).toBeDefined();
      expect(profile.name).toBeDefined();
    });

    test('should have profile structure', () => {
      const profile = pm.getDefaultProfile();
      expect(profile).toHaveProperty('name');
      expect(profile).toHaveProperty('description');
    });

    test('should validate valid profile', () => {
      const profile = pm.getDefaultProfile();
      const result = pm.validateProfile(profile);
      expect(result.valid).toBe(true);
    });

    test('should reject invalid profile', () => {
      const result = pm.validateProfile({ invalid: true });
      expect(result.valid).toBe(false);
    });

    test('should reject empty object', () => {
      const result = pm.validateProfile({});
      expect(result.valid).toBe(false);
    });

    test('should translate profile to config', () => {
      const profile = pm.getDefaultProfile();
      const config = pm.translateProfileToCalculatorConfig(profile);
      expect(config).toBeDefined();
      expect(typeof config).toBe('object');
    });

    test('should have consistent translation', () => {
      const profile1 = pm.getDefaultProfile();
      const profile2 = pm.getDefaultProfile();
      const config1 = pm.translateProfileToCalculatorConfig(profile1);
      const config2 = pm.translateProfileToCalculatorConfig(profile2);
      expect(config1).toEqual(config2);
    });

    test('should have version info', () => {
      const profile = pm.getDefaultProfile();
      expect(profile).toHaveProperty('version');
    });

    test('should have context factors', () => {
      const profile = pm.getDefaultProfile();
      expect(profile).toHaveProperty('contextFactors');
    });

    test('should have scoring config', () => {
      const profile = pm.getDefaultProfile();
      expect(profile).toHaveProperty('scoring');
    });
  });
});