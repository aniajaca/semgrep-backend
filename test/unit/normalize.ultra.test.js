// test/unit/normalize.ultra.test.js - FIXED VERSION
const { 
  normalizeFindings, 
  enrichFindings, 
  deduplicateFindings,
  createRiskContext,
  normalizeSeverity,
  calculateRiskStatistics
} = require('../../src/lib/normalize');

describe('Normalize - Ultra Coverage', () => {
  describe('normalizeFindings - Edge Cases', () => {
    it('should handle findings with missing properties', () => {
      const findings = [
        { severity: 'high' },
        { file: 'test.js' },
        {}
      ];
      
      const result = normalizeFindings(findings, 'semgrep');
      expect(Array.isArray(result)).toBe(true);
    });

    it('should handle findings with null values', () => {
      const findings = [
        { 
          severity: null,
          file: null,
          message: null,
          cwe: null
        }
      ];
      
      const result = normalizeFindings(findings, 'semgrep');
      expect(Array.isArray(result)).toBe(true);
    });

    it('should handle AST findings', () => {
      const findings = [
        {
          type: 'vulnerability',
          severity: 'ERROR',
          location: { file: 'test.js', line: 10 }
        }
      ];
      
      const result = normalizeFindings(findings, 'ast');
      expect(Array.isArray(result)).toBe(true);
    });

    it('should handle dependency findings', () => {
      const findings = [
        {
          vulnerability: {
            id: 'CVE-2021-1234',
            severity: 'high'
          },
          package: { name: 'test-package' }
        }
      ];
      
      const result = normalizeFindings(findings, 'dependency');
      expect(Array.isArray(result)).toBe(true);
    });

    it('should handle very large finding arrays', () => {
      const findings = Array(1000).fill({
        severity: 'medium',
        file: 'test.js',
        message: 'test'
      });
      
      const result = normalizeFindings(findings, 'semgrep');
      expect(result.length).toBe(1000);
    });
  });

  describe('enrichFindings - Advanced', () => {
    it('should add timestamps to findings', () => {
      const findings = [
        { severity: 'high', file: 'test.js' }
      ];
      
      const result = enrichFindings(findings);
      expect(result[0].enrichedAt).toBeDefined();
    });

    it('should enrich null findings array', () => {
      const result = enrichFindings(null);
      expect(Array.isArray(result)).toBe(true);
      expect(result.length).toBe(0);
    });

    it('should enrich undefined findings array', () => {
      const result = enrichFindings(undefined);
      expect(Array.isArray(result)).toBe(true);
      expect(result.length).toBe(0);
    });
  });

  describe('deduplicateFindings - Advanced', () => {
    it('should deduplicate by file and line', () => {
      const findings = [
        { file: 'test.js', startLine: 10, severity: 'high' },
        { file: 'test.js', startLine: 10, severity: 'high' },
        { file: 'test.js', startLine: 20, severity: 'high' }
      ];
      
      const result = deduplicateFindings(findings);
      expect(result.length).toBe(2);
    });

    it('should handle empty array', () => {
      const result = deduplicateFindings([]);
      expect(result.length).toBe(0);
    });

    it('should handle null input', () => {
      const result = deduplicateFindings(null);
      expect(Array.isArray(result)).toBe(true);
    });

    it('should handle undefined input', () => {
      const result = deduplicateFindings(undefined);
      expect(Array.isArray(result)).toBe(true);
    });
  });

  describe('Integration - Full Pipeline', () => {
    it('should handle normalize enrich deduplicate pipeline', () => {
      const rawFindings = [
        { severity: 'HIGH', file: 'test.js', startLine: 10 },
        { severity: 'high', file: 'test.js', startLine: 10 },
        { severity: 'medium', file: 'test.js', startLine: 20 }
      ];
      
      const normalized = normalizeFindings(rawFindings, 'semgrep');
      const enriched = enrichFindings(normalized);
      const deduplicated = deduplicateFindings(enriched);
      
      expect(deduplicated.length).toBe(2);
      expect(deduplicated.every(f => f.enrichedAt)).toBe(true);
    });

    it('should handle empty pipeline', () => {
      const normalized = normalizeFindings([], 'semgrep');
      const enriched = enrichFindings(normalized);
      const deduplicated = deduplicateFindings(enriched);
      
      expect(deduplicated.length).toBe(0);
    });
  });

  describe('Performance Tests', () => {
    it('should handle large datasets efficiently', () => {
      const findings = Array(5000).fill({
        severity: 'medium',
        file: 'test.js',
        startLine: 100
      });
      
      const start = Date.now();
      const result = normalizeFindings(findings, 'semgrep');
      const duration = Date.now() - start;
      
      expect(result.length).toBe(5000);
      expect(duration).toBeLessThan(1000);
    });
  });

  describe('Error Recovery', () => {
    it('should recover from malformed findings', () => {
      const findings = [
        { severity: 'high' },
        'not an object',
        123,
        null,
        undefined,
        { severity: 'medium' }
      ];
      
      const result = normalizeFindings(findings, 'semgrep');
      expect(Array.isArray(result)).toBe(true);
    });
  });
});