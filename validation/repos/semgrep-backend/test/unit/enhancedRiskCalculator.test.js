// test/unit/enhancedRiskCalculator.test.js
const EnhancedRiskCalculator = require('../../src/enhancedRiskCalculator');

describe('EnhancedRiskCalculator', () => {
  let calculator;

  beforeEach(() => {
    calculator = new EnhancedRiskCalculator();
  });

  describe('calculateVulnerabilityRisk', () => {
    test('should calculate risk for high severity vulnerability', () => {
      const vulnerability = {
        severity: 'high',
        cwe: 'CWE-89',
        cweId: 'CWE-89'
      };
      
      const context = {
        internetFacing: true,
        production: true
      };

      const result = calculator.calculateVulnerabilityRisk(vulnerability, context);

      expect(result).toHaveProperty('original');
      expect(result).toHaveProperty('adjusted');
      expect(result.adjusted.severity).toBe('critical');
      expect(result.adjusted.score).toBeGreaterThan(7);
    });

    test('should handle vulnerability without context', () => {
      const vulnerability = {
        severity: 'medium',
        cwe: 'CWE-79'
      };

      const result = calculator.calculateVulnerabilityRisk(vulnerability, {});

      expect(result.adjusted.severity).toBe('medium');
      expect(result.adjusted.score).toBeGreaterThanOrEqual(0);
    });

    test('should apply context factors correctly', () => {
      const vulnerability = {
        severity: 'medium',
        cwe: 'CWE-79'
      };

      const withContext = calculator.calculateVulnerabilityRisk(vulnerability, {
        internetFacing: true,
        production: true,
        handlesPI: true
      });

      const withoutContext = calculator.calculateVulnerabilityRisk(vulnerability, {});

      expect(withContext.adjusted.score).toBeGreaterThan(withoutContext.adjusted.score);
    });
  });

  describe('calculateFileRisk', () => {
    test('should calculate overall file risk from multiple findings', () => {
      const findings = [
        { severity: 'critical', cwe: 'CWE-89' },
        { severity: 'high', cwe: 'CWE-79' },
        { severity: 'medium', cwe: 'CWE-22' }
      ];

      const result = calculator.calculateFileRisk(findings, {});

      expect(result).toHaveProperty('score');
      expect(result).toHaveProperty('risk');
      expect(result.risk.level).toMatch(/critical|high|medium|low|minimal/);
    });

    test('should return minimal risk for empty findings', () => {
      const result = calculator.calculateFileRisk([], {});

      expect(result.risk.level).toBe('minimal');
      expect(result.score.final).toBe(0);
    });
  });
});