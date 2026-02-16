const {
  normalizeSeverity,
  createRiskContext,
  normalizeBoolean,
  calculateRiskStatistics,
  enrichFindings,
  deduplicateFindings,
  normalizeFindings
} = require('../../src/lib/normalize');

describe('Normalize - Extended Coverage', () => {
  
  describe('normalizeSeverity - Comprehensive', () => {
    test('should normalize CRITICAL to critical', () => {
      expect(normalizeSeverity('CRITICAL')).toBe('critical');
    });

    test('should normalize crit to critical', () => {
      expect(normalizeSeverity('crit')).toBe('critical');
    });

    test('should normalize HIGH to high', () => {
      expect(normalizeSeverity('HIGH')).toBe('high');
    });

    test('should normalize error to high', () => {
      expect(normalizeSeverity('error')).toBe('high');
    });

    test('should normalize MEDIUM to medium', () => {
      expect(normalizeSeverity('MEDIUM')).toBe('medium');
    });

    test('should normalize warning to medium', () => {
      expect(normalizeSeverity('warning')).toBe('medium');
    });

    test('should normalize LOW to low', () => {
      expect(normalizeSeverity('LOW')).toBe('low');
    });

    test('should normalize note to low', () => {
      expect(normalizeSeverity('note')).toBe('low');
    });

    test('should handle info severity', () => {
      const result = normalizeSeverity('info');
      expect(['info', 'low']).toContain(result);
    });

    test('should handle mixed case', () => {
      expect(normalizeSeverity('CrItIcAl')).toBe('critical');
    });

    test('should default null to medium', () => {
      expect(normalizeSeverity(null)).toBe('medium');
    });

    test('should default undefined to medium', () => {
      expect(normalizeSeverity(undefined)).toBe('medium');
    });

    test('should handle empty string', () => {
      const result = normalizeSeverity('');
      expect(typeof result).toBe('string');
    });

    test('should handle whitespace', () => {
      const result = normalizeSeverity('  CRITICAL  ');
      expect(result).toBe('critical');
    });

    test('should handle unknown severity', () => {
      const result = normalizeSeverity('invalid-severity');
      expect(typeof result).toBe('string');
      expect(result).toBe('medium');
    });
  });

  describe('createRiskContext - Comprehensive', () => {
    test('should normalize internetFacing boolean', () => {
      const ctx = createRiskContext({ internetFacing: true });
      expect(ctx.internetFacing).toBe(true);
    });

    test('should normalize internetFacing string', () => {
      const ctx = createRiskContext({ internetFacing: 'true' });
      expect(ctx.internetFacing).toBe(true);
    });

    test('should normalize production boolean', () => {
      const ctx = createRiskContext({ production: true });
      expect(ctx.production).toBe(true);
    });

    test('should normalize production string', () => {
      const ctx = createRiskContext({ production: 'yes' });
      expect(ctx.production).toBe(true);
    });

    test('should normalize handlesPI number', () => {
      const ctx = createRiskContext({ handlesPI: 1 });
      expect(ctx.handlesPI).toBe(true);
    });

    test('should normalize EPSS over 100', () => {
      const ctx = createRiskContext({ epss: 95 });
      expect(ctx.epss).toBe(0.95);
    });

    test('should normalize EPSS under 1', () => {
      const ctx = createRiskContext({ epss: 0.5 });
      expect(ctx.epss).toBe(0.5);
    });

    test('should handle empty context', () => {
      const ctx = createRiskContext({});
      expect(typeof ctx).toBe('object');
    });

    test('should handle multiple boolean flags', () => {
      const ctx = createRiskContext({
        internetFacing: 'yes',
        production: 1,
        handlesPI: true
      });
      expect(ctx.internetFacing).toBe(true);
      expect(ctx.production).toBe(true);
      expect(ctx.handlesPI).toBe(true);
    });

    test('should normalize regulated flag', () => {
      const ctx = createRiskContext({ regulated: 'true' });
      expect(ctx.regulated).toBe(true);
    });

    test('should normalize userBaseLarge flag', () => {
      const ctx = createRiskContext({ userBaseLarge: 1 });
      expect(ctx.userBaseLarge).toBe(true);
    });
  });

  describe('normalizeBoolean - Comprehensive', () => {
    test('should handle true boolean', () => {
      expect(normalizeBoolean(true)).toBe(true);
    });

    test('should handle false boolean', () => {
      expect(normalizeBoolean(false)).toBe(false);
    });

    test('should handle "true" string', () => {
      expect(normalizeBoolean('true')).toBe(true);
    });

    test('should handle "false" string', () => {
      expect(normalizeBoolean('false')).toBe(false);
    });

    test('should handle "yes" string', () => {
      expect(normalizeBoolean('yes')).toBe(true);
    });

    test('should handle "no" string', () => {
      expect(normalizeBoolean('no')).toBe(false);
    });

    test('should handle 1 number', () => {
      expect(normalizeBoolean(1)).toBe(true);
    });

    test('should handle 0 number', () => {
      expect(normalizeBoolean(0)).toBe(false);
    });

    test('should handle "TRUE" uppercase', () => {
      expect(normalizeBoolean('TRUE')).toBe(true);
    });

    test('should handle "YES" uppercase', () => {
      expect(normalizeBoolean('YES')).toBe(true);
    });

    test('should handle "FALSE" uppercase', () => {
      expect(normalizeBoolean('FALSE')).toBe(false);
    });

    test('should default null to false', () => {
      expect(normalizeBoolean(null)).toBe(false);
    });

    test('should default undefined to false', () => {
      expect(normalizeBoolean(undefined)).toBe(false);
    });

    test('should default empty string to false', () => {
      expect(normalizeBoolean('')).toBe(false);
    });

    test('should handle "on" string', () => {
      const result = normalizeBoolean('on');
      expect(typeof result).toBe('boolean');
    });

    test('should handle "off" string', () => {
      const result = normalizeBoolean('off');
      expect(typeof result).toBe('boolean');
    });
  });

  describe('calculateRiskStatistics - Comprehensive', () => {
    test('should calculate with mixed severities', () => {
      const findings = [
        { severity: 'critical', score: 10 },
        { severity: 'high', score: 8 },
        { severity: 'medium', score: 5 }
      ];
      const stats = calculateRiskStatistics(findings);
      expect(stats.total).toBe(3);
      expect(stats.averageScore).toBeGreaterThan(0);
    });

    test('should handle empty array', () => {
      const stats = calculateRiskStatistics([]);
      expect(stats.total).toBe(0);
      expect(stats.averageScore).toBe(0);
    });

    test('should count distribution correctly', () => {
      const findings = [
        { severity: 'critical' },
        { severity: 'critical' },
        { severity: 'high' }
      ];
      const stats = calculateRiskStatistics(findings);
      expect(stats.distribution.critical).toBe(2);
      expect(stats.distribution.high).toBe(1);
    });

    test('should calculate average correctly', () => {
      const findings = [
        { severity: 'high', score: 8 },
        { severity: 'high', score: 6 }
      ];
      const stats = calculateRiskStatistics(findings);
      expect(stats.averageScore).toBe(7);
    });

    test('should handle findings without scores', () => {
      const findings = [
        { severity: 'high' },
        { severity: 'medium' }
      ];
      const stats = calculateRiskStatistics(findings);
      expect(stats.total).toBe(2);
    });

    test('should handle all severity levels', () => {
      const findings = [
        { severity: 'critical' },
        { severity: 'high' },
        { severity: 'medium' },
        { severity: 'low' },
        { severity: 'info' }
      ];
      const stats = calculateRiskStatistics(findings);
      expect(stats.total).toBe(5);
    });

    test('should handle duplicate severities', () => {
      const findings = [
        { severity: 'medium' },
        { severity: 'medium' },
        { severity: 'medium' }
      ];
      const stats = calculateRiskStatistics(findings);
      expect(stats.distribution.medium).toBe(3);
    });
  });

  describe('enrichFindings', () => {
    test('should add metadata to findings', () => {
      const findings = [{ check_id: 'test-rule', severity: 'high' }];
      const enriched = enrichFindings(findings);
      expect(Array.isArray(enriched)).toBe(true);
      expect(enriched.length).toBe(1);
    });

    test('should handle empty findings', () => {
      const enriched = enrichFindings([]);
      expect(Array.isArray(enriched)).toBe(true);
      expect(enriched.length).toBe(0);
    });

    test('should preserve original finding data', () => {
      const findings = [{ check_id: 'rule1', severity: 'high', message: 'test' }];
      const enriched = enrichFindings(findings);
      expect(enriched[0].check_id).toBe('rule1');
      expect(enriched[0].severity).toBe('high');
    });

    test('should handle multiple findings', () => {
      const findings = [
        { check_id: 'rule1' },
        { check_id: 'rule2' },
        { check_id: 'rule3' }
      ];
      const enriched = enrichFindings(findings);
      expect(enriched.length).toBe(3);
    });
  });

  describe('deduplicateFindings', () => {
    test('should process findings array', () => {
      const findings = [
        { check_id: 'rule1', path: 'file.js', line: 10 },
        { check_id: 'rule2', path: 'file.js', line: 20 }
      ];
      const deduped = deduplicateFindings(findings);
      expect(Array.isArray(deduped)).toBe(true);
      expect(deduped.length).toBeGreaterThan(0);
    });

    test('should handle empty findings', () => {
      const deduped = deduplicateFindings([]);
      expect(Array.isArray(deduped)).toBe(true);
      expect(deduped.length).toBe(0);
    });

    test('should preserve finding properties', () => {
      const findings = [
        { check_id: 'rule1', path: 'file1.js', line: 10 }
      ];
      const deduped = deduplicateFindings(findings);
      expect(deduped[0]).toHaveProperty('check_id');
    });
  });

 describe('normalizeFindings', () => {
    test('should process Semgrep findings', () => {
      const findings = [{
        check_id: 'test.rule',
        extra: {
          severity: 'ERROR',
          message: 'Test message',
          metadata: {}
        },
        path: 'test.js',
        start: { line: 1, col: 0 },
        end: { line: 1, col: 10 }
      }];
      
      const normalized = normalizeFindings(findings);
      expect(Array.isArray(normalized)).toBe(true);
      expect(normalized.length).toBe(1);
      expect(normalized[0]).toHaveProperty('ruleId');
      expect(normalized[0]).toHaveProperty('file');
    });

    test('should handle empty findings array', () => {
      const normalized = normalizeFindings([]);
      expect(Array.isArray(normalized)).toBe(true);
      expect(normalized.length).toBe(0);
    });

    test('should preserve finding structure', () => {
      const findings = [{
        check_id: 'rule',
        extra: { severity: 'WARNING', message: 'test', metadata: {} },
        path: 'test.js',
        start: { line: 1 },
        end: { line: 1 }
      }];
      
      const normalized = normalizeFindings(findings);
      expect(normalized[0]).toHaveProperty('ruleId');
      expect(normalized[0]).toHaveProperty('file');
      expect(normalized[0]).toHaveProperty('severity');
    });
  });
});