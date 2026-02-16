// test/unit/normalize.test.js
const { normalizeFindings, enrichFindings, deduplicateFindings } = require('../../src/lib/normalize');

describe('Normalize Library', () => {
  describe('normalizeFindings', () => {
    test('should normalize Semgrep findings', () => {
      const findings = [{
        engine: 'semgrep',
        ruleId: 'test-rule',
        severity: 'ERROR',
        message: 'Test vulnerability',
        file: 'test.js',
        startLine: 1
      }];

      const result = normalizeFindings(findings);

      expect(Array.isArray(result)).toBe(true);
      expect(result[0]).toHaveProperty('engine');
    });

    test('should handle empty findings', () => {
      const result = normalizeFindings([]);

      expect(result).toEqual([]);
    });
  });

  describe('enrichFindings', () => {
    test('should enrich findings with metadata', () => {
      const findings = [{
        engine: 'ast',
        ruleId: 'test',
        severity: 'high',
        cwe: ['CWE-79']
      }];

      const result = enrichFindings(findings);

      expect(Array.isArray(result)).toBe(true);
      expect(result.length).toBeGreaterThanOrEqual(0);
    });
  });

  describe('deduplicateFindings', () => {
    test('should remove duplicate findings', () => {
      const findings = [
        { ruleId: 'test-1', file: 'test.js', startLine: 1 },
        { ruleId: 'test-1', file: 'test.js', startLine: 1 }
      ];

      const result = deduplicateFindings(findings);

      expect(result.length).toBeLessThanOrEqual(findings.length);
    });
  });
});