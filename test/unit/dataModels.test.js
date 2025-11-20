// test/unit/dataModels.test.js
const {
  Finding,
  SecurityContext,
  RiskAssessment,
  ScanResult
} = require('../../src/lib/dataModels');

describe('DataModels', () => {
  
  describe('Finding', () => {
    it('should create Finding instance', () => {
      const finding = new Finding({
        ruleId: 'test-rule',
        severity: 'HIGH',
        file: 'test.js',
        startLine: 1,
        endLine: 1
      });
      
      expect(finding).toBeDefined();
      expect(finding.ruleId).toBe('test-rule');
    });

    it('should handle minimal data', () => {
      const finding = new Finding({});
      expect(finding).toBeDefined();
    });

    it('should set ruleId', () => {
      const finding = new Finding({ ruleId: 'sql-injection' });
      expect(finding.ruleId).toBe('sql-injection');
    });

    it('should set severity', () => {
      const finding = new Finding({ severity: 'CRITICAL' });
      expect(finding.severity).toBe('CRITICAL');
    });

    it('should set file path', () => {
      const finding = new Finding({ file: '/app/test.js' });
      expect(finding.file).toBe('/app/test.js');
    });

    it('should set line numbers', () => {
      const finding = new Finding({ startLine: 10, endLine: 20 });
      expect(finding.startLine).toBe(10);
      expect(finding.endLine).toBe(20);
    });

    it('should set message', () => {
      const finding = new Finding({ message: 'Test vulnerability' });
      expect(finding.message).toBe('Test vulnerability');
    });

    it('should set CWE', () => {
      const finding = new Finding({ cwe: ['CWE-79'] });
      expect(finding.cwe).toEqual(['CWE-79']);
    });

    it('should set OWASP', () => {
      const finding = new Finding({ owasp: ['A03:2021'] });
      expect(finding.owasp).toEqual(['A03:2021']);
    });

    it('should set confidence', () => {
      const finding = new Finding({ confidence: 'HIGH' });
      expect(finding.confidence).toBe('HIGH');
    });

    it('should set category', () => {
      const finding = new Finding({ category: 'sast' });
      expect(finding.category).toBe('sast');
    });
  });

  describe('SecurityContext', () => {
    it('should create SecurityContext instance', () => {
      const context = new SecurityContext({
        internetFacing: true,
        production: false
      });
      
      expect(context).toBeDefined();
      expect(context.internetFacing).toBe(true);
    });

    it('should handle empty data', () => {
      const context = new SecurityContext({});
      expect(context).toBeDefined();
    });

    it('should set internetFacing', () => {
      const context = new SecurityContext({ internetFacing: true });
      expect(context.internetFacing).toBe(true);
    });

    it('should set production', () => {
      const context = new SecurityContext({ production: true });
      expect(context.production).toBe(true);
    });

    it('should set handlesPII', () => {
      const context = new SecurityContext({ handlesPII: true });
      expect(context.handlesPII).toBe(true);
    });

    it('should set authentication', () => {
      const context = new SecurityContext({ authentication: false });
      expect(context.authentication).toBe(false);
    });

    it('should set userInput', () => {
      const context = new SecurityContext({ userInput: true });
      expect(context.userInput).toBe(true);
    });
  });

  describe('RiskAssessment', () => {
    it('should create RiskAssessment instance', () => {
      const assessment = new RiskAssessment({
        score: 85,
        priority: 'HIGH'
      });
      
      expect(assessment).toBeDefined();
      expect(assessment.score).toBe(85);
    });

    it('should handle empty data', () => {
      const assessment = new RiskAssessment({});
      expect(assessment).toBeDefined();
    });

    it('should set score', () => {
      const assessment = new RiskAssessment({ score: 75 });
      expect(assessment.score).toBe(75);
    });

    it('should set priority', () => {
      const assessment = new RiskAssessment({ priority: 'CRITICAL' });
      expect(assessment.priority).toBe('CRITICAL');
    });

    it('should set factors', () => {
      const factors = { internet: 1.5, production: 1.2 };
      const assessment = new RiskAssessment({ factors });
      expect(assessment.factors).toEqual(factors);
    });

    it('should set confidence', () => {
      const assessment = new RiskAssessment({ confidence: 0.85 });
      expect(assessment.confidence).toBe(0.85);
    });
  });

  describe('ScanResult', () => {
    it('should create ScanResult instance', () => {
      const result = new ScanResult({
        findings: [],
        summary: { total: 0 }
      });
      
      expect(result).toBeDefined();
      expect(Array.isArray(result.findings)).toBe(true);
    });

    it('should handle empty data', () => {
      const result = new ScanResult({});
      expect(result).toBeDefined();
    });

    it('should set findings', () => {
      const findings = [{ ruleId: 'test' }];
      const result = new ScanResult({ findings });
      expect(result.findings).toEqual(findings);
    });

    it('should set summary', () => {
      const summary = { total: 5, critical: 1 };
      const result = new ScanResult({ summary });
      expect(result.summary).toEqual(summary);
    });

    it('should set scanTime', () => {
      const scanTime = '2025-01-01T00:00:00Z';
      const result = new ScanResult({ scanTime });
      expect(result.scanTime).toBe(scanTime);
    });

    it('should set targetPath', () => {
      const result = new ScanResult({ targetPath: '/app' });
      expect(result.targetPath).toBe('/app');
    });
  });

  describe('Integration', () => {
    it('should create complete scan result', () => {
      const finding = new Finding({
        ruleId: 'sql-injection',
        severity: 'HIGH',
        file: 'app.js',
        startLine: 42,
        endLine: 42
      });

      const context = new SecurityContext({
        internetFacing: true,
        production: true
      });

      const assessment = new RiskAssessment({
        score: 85,
        priority: 'HIGH'
      });

      const result = new ScanResult({
        findings: [finding],
        summary: { total: 1, high: 1 }
      });

      expect(finding).toBeDefined();
      expect(context).toBeDefined();
      expect(assessment).toBeDefined();
      expect(result).toBeDefined();
      expect(result.findings).toHaveLength(1);
    });
  });
});