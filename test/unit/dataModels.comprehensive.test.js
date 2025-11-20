// test/unit/dataModels.comprehensive.test.js
const {
  normalizeSeverity,
  createRiskContext,
  normalizeBoolean,
  calculateRiskStatistics,
  createEmptyRiskResult,
  scoreToRiskLevel,
  scoreToGrade,
  calculateConfidence
} = require('../../src/lib/dataModels');

describe('DataModels - Comprehensive Coverage', () => {
  describe('normalizeSeverity', () => {
    it('should normalize CRITICAL to critical', () => {
      expect(normalizeSeverity('CRITICAL')).toBe('critical');
    });

    it('should normalize crit to critical', () => {
      expect(normalizeSeverity('crit')).toBe('critical');
    });

    it('should normalize very_high to critical', () => {
      expect(normalizeSeverity('very_high')).toBe('critical');
    });

    it('should normalize HIGH to high', () => {
      expect(normalizeSeverity('HIGH')).toBe('high');
    });

    it('should normalize hi to high', () => {
      expect(normalizeSeverity('hi')).toBe('high');
    });

    it('should normalize error to high', () => {
      expect(normalizeSeverity('error')).toBe('high');
    });

    it('should normalize MEDIUM to medium', () => {
      expect(normalizeSeverity('MEDIUM')).toBe('medium');
    });

    it('should normalize med to medium', () => {
      expect(normalizeSeverity('med')).toBe('medium');
    });

    it('should normalize moderate to medium', () => {
      expect(normalizeSeverity('moderate')).toBe('medium');
    });

    it('should normalize warning to medium', () => {
      expect(normalizeSeverity('warning')).toBe('medium');
    });

    it('should normalize warn to medium', () => {
      expect(normalizeSeverity('warn')).toBe('medium');
    });

    it('should normalize LOW to low', () => {
      expect(normalizeSeverity('LOW')).toBe('low');
    });

    it('should normalize lo to low', () => {
      expect(normalizeSeverity('lo')).toBe('low');
    });

    it('should normalize note to low', () => {
      expect(normalizeSeverity('note')).toBe('low');
    });

    it('should normalize info to info', () => {
      expect(normalizeSeverity('info')).toBe('info');
    });

    it('should normalize informational to info', () => {
      expect(normalizeSeverity('informational')).toBe('info');
    });

    it('should normalize information to info', () => {
      expect(normalizeSeverity('information')).toBe('info');
    });

    it('should handle unknown severity', () => {
      expect(normalizeSeverity('unknown')).toBe('medium');
    });

    it('should handle null severity', () => {
      expect(normalizeSeverity(null)).toBe('medium');
    });

    it('should handle undefined severity', () => {
      expect(normalizeSeverity(undefined)).toBe('medium');
    });

    it('should handle empty string', () => {
      expect(normalizeSeverity('')).toBe('medium');
    });

    it('should handle whitespace', () => {
      expect(normalizeSeverity('  CRITICAL  ')).toBe('critical');
    });

    it('should handle mixed case', () => {
      expect(normalizeSeverity('CrItIcAl')).toBe('critical');
    });

    it('should handle numeric input', () => {
      expect(normalizeSeverity(123)).toBe('medium');
    });
  });

  describe('normalizeBoolean', () => {
    it('should handle true boolean', () => {
      expect(normalizeBoolean(true)).toBe(true);
    });

    it('should handle false boolean', () => {
      expect(normalizeBoolean(false)).toBe(false);
    });

    it('should handle 1 as true', () => {
      expect(normalizeBoolean(1)).toBe(true);
    });

    it('should handle 0 as false', () => {
      expect(normalizeBoolean(0)).toBe(false);
    });

    it('should handle "true" string', () => {
      expect(normalizeBoolean('true')).toBe(true);
    });

    it('should handle "false" string', () => {
      expect(normalizeBoolean('false')).toBe(false);
    });

    it('should handle "TRUE" uppercase', () => {
      expect(normalizeBoolean('TRUE')).toBe(true);
    });

    it('should handle "FALSE" uppercase', () => {
      expect(normalizeBoolean('FALSE')).toBe(false);
    });

    it('should handle "yes" string', () => {
      expect(normalizeBoolean('yes')).toBe(true);
    });

    it('should handle "no" string', () => {
      expect(normalizeBoolean('no')).toBe(false);
    });

    it('should handle "1" string', () => {
      expect(normalizeBoolean('1')).toBe(true);
    });

    it('should handle "0" string', () => {
      expect(normalizeBoolean('0')).toBe(false);
    });

    it('should handle "on" string', () => {
      expect(normalizeBoolean('on')).toBe(true);
    });

    it('should handle "off" string', () => {
      expect(normalizeBoolean('off')).toBe(false);
    });

    it('should handle whitespace in strings', () => {
      expect(normalizeBoolean('  true  ')).toBe(true);
    });

    it('should handle null as false', () => {
      expect(normalizeBoolean(null)).toBe(false);
    });

    it('should handle undefined as false', () => {
      expect(normalizeBoolean(undefined)).toBe(false);
    });

    it('should handle empty string as false', () => {
      expect(normalizeBoolean('')).toBe(false);
    });

    it('should handle other truthy values', () => {
      expect(normalizeBoolean('anything')).toBe(true);
    });

    it('should handle objects as truthy', () => {
      expect(normalizeBoolean({})).toBe(true);
    });

    it('should handle arrays as truthy', () => {
      expect(normalizeBoolean([])).toBe(true);
    });
  });

  describe('createRiskContext', () => {
    it('should normalize internetFacing boolean', () => {
      const context = createRiskContext({ internetFacing: true });
      expect(context.internetFacing).toBe(true);
    });

    it('should normalize internetFacing string', () => {
      const context = createRiskContext({ internetFacing: 'true' });
      expect(context.internetFacing).toBe(true);
    });

    it('should normalize production boolean', () => {
      const context = createRiskContext({ production: false });
      expect(context.production).toBe(false);
    });

    it('should normalize production string', () => {
      const context = createRiskContext({ production: 'yes' });
      expect(context.production).toBe(true);
    });

    it('should normalize handlesPI flag', () => {
      const context = createRiskContext({ handlesPI: true });
      expect(context.handlesPI).toBe(true);
    });

    it('should normalize handlesFinancialData', () => {
      const context = createRiskContext({ handlesFinancialData: '1' });
      expect(context.handlesFinancialData).toBe(true);
    });

    it('should normalize handlesHealthData', () => {
      const context = createRiskContext({ handlesHealthData: 'on' });
      expect(context.handlesHealthData).toBe(true);
    });

    it('should normalize legacyCode', () => {
      const context = createRiskContext({ legacyCode: true });
      expect(context.legacyCode).toBe(true);
    });

    it('should normalize businessCritical', () => {
      const context = createRiskContext({ businessCritical: 1 });
      expect(context.businessCritical).toBe(true);
    });

    it('should normalize regulated flag', () => {
      const context = createRiskContext({ regulated: true });
      expect(context.regulated).toBe(true);
    });

    it('should normalize compliance flag', () => {
      const context = createRiskContext({ compliance: true });
      expect(context.compliance).toBe(true);
    });

    it('should normalize thirdPartyIntegration', () => {
      const context = createRiskContext({ thirdPartyIntegration: 'yes' });
      expect(context.thirdPartyIntegration).toBe(true);
    });

    it('should normalize complexAuth', () => {
      const context = createRiskContext({ complexAuth: false });
      expect(context.complexAuth).toBe(false);
    });

    it('should normalize userBaseLarge', () => {
      const context = createRiskContext({ userBaseLarge: true });
      expect(context.userBaseLarge).toBe(true);
    });

    it('should normalize kevListed', () => {
      const context = createRiskContext({ kevListed: '1' });
      expect(context.kevListed).toBe(true);
    });

    it('should normalize publicExploit', () => {
      const context = createRiskContext({ publicExploit: true });
      expect(context.publicExploit).toBe(true);
    });

    it('should normalize exploitAvailable', () => {
      const context = createRiskContext({ exploitAvailable: 'true' });
      expect(context.exploitAvailable).toBe(true);
    });

    it('should normalize hasControls', () => {
      const context = createRiskContext({ hasControls: false });
      expect(context.hasControls).toBe(false);
    });

    it('should normalize EPSS percentage over 100', () => {
      const context = createRiskContext({ epss: 150 });
      expect(context.epss).toBe(1);
    });

    it('should normalize EPSS percentage under 1', () => {
      const context = createRiskContext({ epss: 0.85 });
      expect(context.epss).toBe(0.85);
    });

    it('should convert EPSS percentage to decimal', () => {
      const context = createRiskContext({ epss: 45 });
      expect(context.epss).toBe(0.45);
    });

    it('should normalize assetCriticality string', () => {
      const context = createRiskContext({ assetCriticality: 'HIGH' });
      expect(context.assetCriticality).toBe('high');
    });

    it('should normalize fixEffort string', () => {
      const context = createRiskContext({ fixEffort: 'MEDIUM' });
      expect(context.fixEffort).toBe('medium');
    });

    it('should normalize dataClassification string', () => {
      const context = createRiskContext({ dataClassification: 'CONFIDENTIAL' });
      expect(context.dataClassification).toBe('confidential');
    });

    it('should preserve compliance array', () => {
      const compliance = ['PCI-DSS', 'HIPAA'];
      const context = createRiskContext({ compliance });
      expect(context.compliance).toEqual(compliance);
    });

    it('should preserve customFactors', () => {
      const customFactors = { customRisk: 1.5 };
      const context = createRiskContext({ customFactors });
      expect(context.customFactors).toEqual(customFactors);
    });

    it('should handle empty context', () => {
      const context = createRiskContext();
      expect(context).toBeDefined();
      expect(typeof context).toBe('object');
    });

    it('should handle null context', () => {
      const context = createRiskContext(null);
      expect(context).toBeDefined();
    });

    it('should handle multiple flags together', () => {
      const context = createRiskContext({
        internetFacing: true,
        production: true,
        handlesPI: true
      });
      expect(context.internetFacing).toBe(true);
      expect(context.production).toBe(true);
      expect(context.handlesPI).toBe(true);
    });

    it('should ignore undefined values', () => {
      const context = createRiskContext({
        internetFacing: undefined,
        production: true
      });
      expect(context.internetFacing).toBeUndefined();
      expect(context.production).toBe(true);
    });
  });

  describe('calculateRiskStatistics', () => {
    it('should calculate stats for mixed severities', () => {
      const findings = [
        { severity: 'critical', score: 90 },
        { severity: 'high', score: 75 },
        { severity: 'medium', score: 50 }
      ];
      const stats = calculateRiskStatistics(findings);
      
      expect(stats.total).toBe(3);
      expect(stats.distribution.critical).toBe(1);
      expect(stats.distribution.high).toBe(1);
      expect(stats.distribution.medium).toBe(1);
    });

    it('should handle empty findings array', () => {
      const stats = calculateRiskStatistics([]);
      
      expect(stats.total).toBe(0);
      expect(stats.averageScore).toBe(0);
    });

    it('should count distribution correctly', () => {
      const findings = [
        { severity: 'critical' },
        { severity: 'critical' },
        { severity: 'high' },
        { severity: 'low' }
      ];
      const stats = calculateRiskStatistics(findings);
      
      expect(stats.distribution.critical).toBe(2);
      expect(stats.distribution.high).toBe(1);
      expect(stats.distribution.low).toBe(1);
    });

    it('should calculate average score correctly', () => {
      const findings = [
        { score: 80 },
        { score: 60 },
        { score: 40 }
      ];
      const stats = calculateRiskStatistics(findings);
      
      expect(stats.averageScore).toBe(60);
    });

    it('should handle findings without scores', () => {
      const findings = [
        { severity: 'high' },
        { severity: 'medium' }
      ];
      const stats = calculateRiskStatistics(findings);
      
      expect(stats.total).toBe(2);
      expect(stats.averageScore).toBe(0);
    });

    it('should calculate maxScore correctly', () => {
      const findings = [
        { score: 90 },
        { score: 50 },
        { score: 70 }
      ];
      const stats = calculateRiskStatistics(findings);
      
      expect(stats.maxScore).toBe(90);
    });

    it('should calculate minScore correctly', () => {
      const findings = [
        { score: 90 },
        { score: 30 },
        { score: 70 }
      ];
      const stats = calculateRiskStatistics(findings);
      
      expect(stats.minScore).toBe(30);
    });

    it('should count categories', () => {
      const findings = [
        { category: 'sast', severity: 'high' },
        { category: 'sast', severity: 'medium' },
        { category: 'sca', severity: 'low' }
      ];
      const stats = calculateRiskStatistics(findings);
      
      expect(stats.categories.sast).toBe(2);
      expect(stats.categories.sca).toBe(1);
    });

    it('should handle findings without category', () => {
      const findings = [
        { severity: 'high' }
      ];
      const stats = calculateRiskStatistics(findings);
      
      expect(stats.categories.unknown).toBe(1);
    });

    it('should use cvss as fallback for score', () => {
      const findings = [
        { cvss: 8.5 },
        { cvss: 6.0 }
      ];
      const stats = calculateRiskStatistics(findings);
      
      expect(stats.averageScore).toBe(7.25);
    });

    it('should handle null findings', () => {
      const stats = calculateRiskStatistics(null || []);
      expect(stats.total).toBe(0);
    });

    it('should handle undefined findings', () => {
      const stats = calculateRiskStatistics(undefined);
      expect(stats.total).toBe(0);
    });
  });

  describe('createEmptyRiskResult', () => {
    it('should create valid empty result', () => {
      const result = createEmptyRiskResult();
      
      expect(result).toBeDefined();
      expect(result.summary).toBeDefined();
      expect(result.distribution).toBeDefined();
    });

    it('should have zero totalFindings', () => {
      const result = createEmptyRiskResult();
      expect(result.summary.totalFindings).toBe(0);
    });

    it('should have zero riskScore', () => {
      const result = createEmptyRiskResult();
      expect(result.summary.riskScore).toBe(0);
    });

    it('should have none risk level', () => {
      const result = createEmptyRiskResult();
      expect(result.summary.riskLevel).toBe('none');
    });

    it('should have A grade', () => {
      const result = createEmptyRiskResult();
      expect(result.summary.grade).toBe('A');
    });

    it('should have full confidence', () => {
      const result = createEmptyRiskResult();
      expect(result.summary.confidence).toBe(1.0);
    });

    it('should have zero distribution', () => {
      const result = createEmptyRiskResult();
      expect(result.distribution.critical).toBe(0);
      expect(result.distribution.high).toBe(0);
      expect(result.distribution.medium).toBe(0);
      expect(result.distribution.low).toBe(0);
    });

    it('should have metadata with timestamp', () => {
      const result = createEmptyRiskResult();
      expect(result.metadata.calculatedAt).toBeDefined();
    });

    it('should have empty topRisks array', () => {
      const result = createEmptyRiskResult();
      expect(Array.isArray(result.topRisks)).toBe(true);
      expect(result.topRisks.length).toBe(0);
    });

    it('should have empty recommendations array', () => {
      const result = createEmptyRiskResult();
      expect(Array.isArray(result.recommendations)).toBe(true);
      expect(result.recommendations.length).toBe(0);
    });
  });

  describe('scoreToRiskLevel', () => {
    it('should return critical for score >= 80', () => {
      expect(scoreToRiskLevel(80)).toBe('critical');
      expect(scoreToRiskLevel(90)).toBe('critical');
      expect(scoreToRiskLevel(100)).toBe('critical');
    });

    it('should return high for score >= 60', () => {
      expect(scoreToRiskLevel(60)).toBe('high');
      expect(scoreToRiskLevel(70)).toBe('high');
      expect(scoreToRiskLevel(79)).toBe('high');
    });

    it('should return medium for score >= 40', () => {
      expect(scoreToRiskLevel(40)).toBe('medium');
      expect(scoreToRiskLevel(50)).toBe('medium');
      expect(scoreToRiskLevel(59)).toBe('medium');
    });

    it('should return low for score >= 20', () => {
      expect(scoreToRiskLevel(20)).toBe('low');
      expect(scoreToRiskLevel(30)).toBe('low');
      expect(scoreToRiskLevel(39)).toBe('low');
    });

    it('should return minimal for score < 20', () => {
      expect(scoreToRiskLevel(0)).toBe('minimal');
      expect(scoreToRiskLevel(10)).toBe('minimal');
      expect(scoreToRiskLevel(19)).toBe('minimal');
    });
  });

  describe('scoreToGrade', () => {
    it('should return A for high inverted scores', () => {
      expect(scoreToGrade(0)).toBe('A');
      expect(scoreToGrade(10)).toBe('A');
      expect(scoreToGrade(15)).toBe('A');
    });

    it('should return B for medium-high inverted scores', () => {
      expect(scoreToGrade(20)).toBe('B');
      expect(scoreToGrade(25)).toBe('B');
      expect(scoreToGrade(30)).toBe('B');
    });

    it('should return C for medium inverted scores', () => {
      expect(scoreToGrade(40)).toBe('C');
      expect(scoreToGrade(45)).toBe('C');
    });

    it('should return D for low inverted scores', () => {
      expect(scoreToGrade(55)).toBe('D');
      expect(scoreToGrade(60)).toBe('D');
    });

    it('should return F for very low inverted scores', () => {
      expect(scoreToGrade(70)).toBe('F');
      expect(scoreToGrade(80)).toBe('F');
      expect(scoreToGrade(100)).toBe('F');
    });
  });

  describe('calculateConfidence', () => {
    it('should return 0.5 for empty sources', () => {
      expect(calculateConfidence([])).toBe(0.5);
    });

    it('should calculate confidence for semgrep', () => {
      const sources = [
        { engine: 'semgrep', confidence: 0.9 }
      ];
      const confidence = calculateConfidence(sources);
      expect(confidence).toBeGreaterThan(0.7);
    });

    it('should calculate confidence for ast', () => {
      const sources = [
        { engine: 'ast', confidence: 0.8 }
      ];
      const confidence = calculateConfidence(sources);
      expect(confidence).toBeGreaterThan(0.5);
    });

    it('should calculate confidence for custom engine', () => {
      const sources = [
        { engine: 'custom', confidence: 0.7 }
      ];
      const confidence = calculateConfidence(sources);
      expect(confidence).toBeGreaterThan(0);
    });

    it('should calculate weighted confidence for multiple sources', () => {
      const sources = [
        { engine: 'semgrep', confidence: 0.9 },
        { engine: 'ast', confidence: 0.8 }
      ];
      const confidence = calculateConfidence(sources);
      expect(confidence).toBeGreaterThan(0.7);
      expect(confidence).toBeLessThan(1.0);
    });

    it('should handle sources without confidence', () => {
      const sources = [
        { engine: 'semgrep' }
      ];
      const confidence = calculateConfidence(sources);
      expect(confidence).toBeGreaterThan(0);
    });

    it('should handle unknown engine types', () => {
      const sources = [
        { engine: 'unknown', confidence: 0.6 }
      ];
      const confidence = calculateConfidence(sources);
      expect(confidence).toBeGreaterThan(0);
    });

    it('should use default weight for manual engine', () => {
      const sources = [
        { engine: 'manual', confidence: 0.8 }
      ];
      const confidence = calculateConfidence(sources);
      expect(confidence).toBeGreaterThan(0);
    });
  });
});