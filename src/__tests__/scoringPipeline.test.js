// __tests__/scoringPipeline.test.js
const { normalizeFindings, enrichFindings } = require('../lib/normalize');
const EnhancedRiskCalculator = require('../enhancedRiskCalculator');

describe('Scoring Pipeline', () => {
  let riskCalculator;
  
  beforeEach(() => {
    riskCalculator = new EnhancedRiskCalculator();
  });
  
  describe('End-to-end scoring', () => {
    it('should increase score when internetFacing is true', () => {
      const finding = {
        engine: 'semgrep',
        ruleId: 'sql-injection',
        severity: 'CRITICAL',
        cwe: ['CWE-89'],
        file: 'test.js',
        startLine: 10
      };
      
      const vuln = {
        severity: 'critical',
        cwe: 'CWE-89',
        cweId: 'CWE-89',
        file: finding.file,
        line: finding.startLine
      };
      
      // Score without context
      const baseResult = riskCalculator.calculateVulnerabilityRisk(vuln, {});
      
      // Score with internetFacing
      const exposedResult = riskCalculator.calculateVulnerabilityRisk(vuln, {
        internetFacing: true
      });
      
      expect(exposedResult.adjusted.score).toBeGreaterThan(baseResult.adjusted.score);
      expect(exposedResult.factors.applied).toContainEqual(
        expect.objectContaining({ id: 'internetFacing' })
      );
    });
    
    it('should apply multiple environmental factors', () => {
      const vuln = {
        severity: 'high',
        cwe: 'CWE-79',
        cweId: 'CWE-79',
        file: 'xss.js',
        line: 42
      };
      
      const result = riskCalculator.calculateVulnerabilityRisk(vuln, {
        internetFacing: true,
        production: true,
        handlesPI: true
      });
      
      expect(result.factors.applied.length).toBeGreaterThanOrEqual(3);
      expect(result.adjusted.score).toBeGreaterThan(result.original.cvss);
    });
    
    it('should cap adjusted score at 10.0', () => {
      const vuln = {
        severity: 'critical',
        cwe: 'CWE-89',
        cweId: 'CWE-89',
        cvss: { baseScore: 9.8 }
      };
      
      const result = riskCalculator.calculateVulnerabilityRisk(vuln, {
        internetFacing: true,
        production: true,
        handlesPI: true,
        exploitAvailable: true
      });
      
      expect(result.adjusted.score).toBeLessThanOrEqual(10.0);
    });
  });
  
  describe('Finding normalization', () => {
    it('should normalize different severity formats', () => {
      const findings = [
        { severity: 'critical' },
        { severity: 'CRIT' },
        { severity: 'error' },
        { severity: 'warn' },
        { severity: 'info' }
      ];
      
      const normalized = normalizeFindings(findings);
      
      expect(normalized[0].severity).toBe('CRITICAL');
      expect(normalized[1].severity).toBe('CRITICAL');
      expect(normalized[2].severity).toBe('HIGH');
      expect(normalized[3].severity).toBe('MEDIUM');
      expect(normalized[4].severity).toBe('LOW');
    });
    
    it('should ensure CWE and OWASP are arrays', () => {
      const findings = [
        { cwe: 'CWE-89', owasp: 'A03:2021' },
        { cwe: ['CWE-79'], owasp: ['A03:2021'] },
        { cwe: null, owasp: undefined }
      ];
      
      const normalized = normalizeFindings(findings);
      
      expect(Array.isArray(normalized[0].cwe)).toBe(true);
      expect(Array.isArray(normalized[0].owasp)).toBe(true);
      expect(normalized[0].cwe).toEqual(['CWE-89']);
      expect(normalized[0].owasp).toEqual(['A03:2021']);
      expect(normalized[2].cwe).toEqual([]);
      expect(normalized[2].owasp).toEqual([]);
    });
  });
  
  describe('Finding enrichment', () => {
    it('should enrich findings with taxonomy data', () => {
      const findings = [{
        engine: 'test',
        ruleId: 'test-rule',
        severity: 'HIGH',
        cwe: ['CWE-89'],
        owasp: [],
        file: 'test.js',
        startLine: 1
      }];
      
      const enriched = enrichFindings(findings);
      
      expect(enriched[0].cweTitle).toBe('SQL Injection');
      expect(enriched[0].category).toBe('injection');
      expect(enriched[0].owasp).toContain('A03:2021');
    });
  });
});