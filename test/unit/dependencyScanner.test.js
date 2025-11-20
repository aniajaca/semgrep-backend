// test/unit/dependencyScanner.test.js
const { DependencyScanner } = require('../../src/dependencyScanner');

describe('DependencyScanner', () => {
  let scanner;

  beforeEach(() => {
    scanner = new DependencyScanner();
  });

  describe('scanDependencies', () => {
    test('should scan package.json dependencies', async () => {
      const packageJson = {
        name: 'test-app',
        dependencies: {
          'express': '4.17.1',
          'lodash': '4.17.20'
        }
      };

      const result = await scanner.scanDependencies(packageJson);

      expect(result).toHaveProperty('summary');
      expect(result).toHaveProperty('vulnerabilities');
      expect(Array.isArray(result.vulnerabilities)).toBe(true);
      expect(result.metrics.packagesScanned).toBeGreaterThan(0);
    });

    test('should handle empty dependencies', async () => {
      const packageJson = {
        name: 'test-app',
        dependencies: {}
      };

      const result = await scanner.scanDependencies(packageJson);

      expect(result.vulnerabilities).toEqual([]);
      expect(result.summary.totalVulnerabilities).toBe(0);
    });

    test('should handle null package.json', async () => {
      const result = await scanner.scanDependencies(null);

      expect(result).toHaveProperty('vulnerabilities');
      expect(result.vulnerabilities).toEqual([]);
      expect(result.summary.totalVulnerabilities).toBe(0);
    });

    test('should handle undefined package.json', async () => {
      const result = await scanner.scanDependencies(undefined);

      expect(result).toHaveProperty('vulnerabilities');
      expect(result.vulnerabilities).toEqual([]);
    });

    test('should handle missing dependencies property', async () => {
      const packageJson = {
        name: 'test-app'
        // No dependencies property
      };

      const result = await scanner.scanDependencies(packageJson);

      expect(result.vulnerabilities).toEqual([]);
      expect(result.summary.totalVulnerabilities).toBe(0);
    });
  });
});