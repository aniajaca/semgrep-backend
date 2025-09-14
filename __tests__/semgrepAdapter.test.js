// __tests__/semgrepAdapter.test.js
const { normalizeResults } = require('../semgrepAdapter');

describe('Semgrep Adapter', () => {
  describe('normalizeResults', () => {
    it('should normalize Semgrep output to our format', () => {
      const mockSemgrepOutput = {
        results: [
          {
            check_id: 'sql-injection-sequelize',
            path: '/app/controllers/user.js',
            start: { line: 42, col: 10 },
            end: { line: 42, col: 50 },
            extra: {
              message: 'Potential SQL injection vulnerability',
              severity: 'ERROR',
              metadata: {
                cwe: ['CWE-89'],
                owasp: ['A03:2021'],
                confidence: 'HIGH'
              },
              lines: 'db.query(`SELECT * FROM users WHERE id = ${userId}`)'
            }
          }
        ]
      };
      
      const normalized = normalizeResults(mockSemgrepOutput);
      
      expect(normalized).toHaveLength(1);
      expect(normalized[0]).toMatchObject({
        engine: 'semgrep',
        ruleId: 'sql-injection-sequelize',
        category: 'sast',
        severity: 'CRITICAL',
        message: 'Potential SQL injection vulnerability',
        cwe: ['CWE-89'],
        owasp: ['A03:2021'],
        file: '/app/controllers/user.js',
        startLine: 42,
        endLine: 42,
        confidence: 'HIGH'
      });
    });
    
    it('should handle missing metadata gracefully', () => {
      const mockSemgrepOutput = {
        results: [
          {
            check_id: 'generic-rule',
            path: 'test.js',
            start: { line: 1 },
            end: { line: 1 },
            extra: {
              message: 'Test finding',
              severity: 'WARNING'
            }
          }
        ]
      };
      
      const normalized = normalizeResults(mockSemgrepOutput);
      
      expect(normalized[0]).toMatchObject({
        engine: 'semgrep',
        severity: 'HIGH',
        cwe: [],
        owasp: [],
        confidence: 'MEDIUM'
      });
    });
    
    it('should map severity levels correctly', () => {
      const severityTests = [
        { input: 'ERROR', expected: 'CRITICAL' },
        { input: 'WARNING', expected: 'HIGH' },
        { input: 'INFO', expected: 'MEDIUM' },
        { input: 'INVENTORY', expected: 'LOW' }
      ];
      
      severityTests.forEach(test => {
        const output = normalizeResults({
          results: [{
            check_id: 'test',
            path: 'test.js',
            start: { line: 1 },
            end: { line: 1 },
            extra: { severity: test.input }
          }]
        });
        
        expect(output[0].severity).toBe(test.expected);
      });
    });
  });
});