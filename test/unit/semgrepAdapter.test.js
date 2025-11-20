// test/unit/semgrepAdapter.test.js
const { normalizeResults, checkSemgrepAvailable, getSemgrepVersion } = require('../../src/semgrepAdapter');

describe('semgrepAdapter - Extended Coverage', () => {
  
  describe('normalizeResults - Additional Cases', () => {
    it('should handle empty results array', async () => {
      const output = await normalizeResults({ results: [] });
      expect(output).toEqual([]);
    });

    it('should handle null semgrepOutput', async () => {
      const output = await normalizeResults(null);
      expect(output).toEqual([]);
    });

    it('should handle undefined semgrepOutput', async () => {
      const output = await normalizeResults(undefined);
      expect(output).toEqual([]);
    });

    it('should handle missing results property', async () => {
      const output = await normalizeResults({});
      expect(output).toEqual([]);
    });

    it('should handle results that is not an array', async () => {
      const output = await normalizeResults({ results: 'not-an-array' });
      expect(output).toEqual([]);
    });

    it('should handle EXPERIMENTAL severity', async () => {
      const result = await normalizeResults({
        results: [{
          check_id: 'test-rule',
          path: 'test.js',
          start: { line: 1, col: 1 },
          end: { line: 1, col: 10 },
          extra: {
            severity: 'EXPERIMENTAL',
            message: 'Test message'
          }
        }]
      });

      expect(result[0].severity).toBe('LOW');
    });

    it('should handle unknown severity and default to MEDIUM', async () => {
      const result = await normalizeResults({
        results: [{
          check_id: 'test-rule',
          path: 'test.js',
          start: { line: 1, col: 1 },
          end: { line: 1, col: 10 },
          extra: {
            severity: 'UNKNOWN_SEVERITY',
            message: 'Test message'
          }
        }]
      });

      expect(result[0].severity).toBe('MEDIUM');
    });

    it('should default to MEDIUM when severity is missing', async () => {
      const result = await normalizeResults({
        results: [{
          check_id: 'test-rule',
          path: 'test.js',
          start: { line: 1, col: 1 },
          end: { line: 1, col: 10 },
          extra: {
            message: 'Test message'
          }
        }]
      });

      expect(result[0].severity).toBe('MEDIUM');
    });

    it('should handle result without extra property', async () => {
      const result = await normalizeResults({
        results: [{
          check_id: 'test-rule',
          path: 'test.js',
          start: { line: 1, col: 1 },
          end: { line: 1, col: 10 }
        }]
      });

      expect(result[0].severity).toBe('MEDIUM');
      expect(result[0].message).toBe('');
    });

    it('should extract CWE from metadata array', async () => {
      const result = await normalizeResults({
        results: [{
          check_id: 'test-rule',
          path: 'test.js',
          start: { line: 1 },
          end: { line: 1 },
          extra: {
            metadata: {
              cwe: ['CWE-79', 'CWE-80']
            }
          }
        }]
      });

      expect(result[0].cwe).toEqual(['CWE-79', 'CWE-80']);
    });

    it('should extract CWE from metadata string', async () => {
      const result = await normalizeResults({
        results: [{
          check_id: 'test-rule',
          path: 'test.js',
          start: { line: 1 },
          end: { line: 1 },
          extra: {
            metadata: {
              cwe: 'CWE-89'
            }
          }
        }]
      });

      expect(result[0].cwe).toContain('CWE-89');
    });

    it('should extract CWE from check_id', async () => {
      const result = await normalizeResults({
        results: [{
          check_id: 'sql-injection-cwe-89',
          path: 'test.js',
          start: { line: 1 },
          end: { line: 1 },
          extra: {}
        }]
      });

      expect(result[0].cwe).toContain('CWE-89');
    });

    it('should extract multiple CWE IDs from check_id', async () => {
      const result = await normalizeResults({
        results: [{
          check_id: 'security-cwe-79-cwe-80-xss',
          path: 'test.js',
          start: { line: 1 },
          end: { line: 1 },
          extra: {}
        }]
      });

      expect(result[0].cwe.length).toBeGreaterThan(0);
    });

    it('should extract OWASP from metadata array', async () => {
      const result = await normalizeResults({
        results: [{
          check_id: 'test-rule',
          path: 'test.js',
          start: { line: 1 },
          end: { line: 1 },
          extra: {
            metadata: {
              owasp: ['A03:2021', 'A01:2021']
            }
          }
        }]
      });

      expect(result[0].owasp).toEqual(['A03:2021', 'A01:2021']);
    });

    it('should extract OWASP from metadata string', async () => {
      const result = await normalizeResults({
        results: [{
          check_id: 'test-rule',
          path: 'test.js',
          start: { line: 1 },
          end: { line: 1 },
          extra: {
            metadata: {
              owasp: 'A03:2021'
            }
          }
        }]
      });

      expect(result[0].owasp).toContain('A03:2021');
    });

    it('should map SQL injection to OWASP A03', async () => {
      const result = await normalizeResults({
        results: [{
          check_id: 'sql-injection-test',
          path: 'test.js',
          start: { line: 1 },
          end: { line: 1 },
          extra: {}
        }]
      });

      expect(result[0].owasp).toContain('A03:2021');
    });

    it('should map XSS to OWASP A03', async () => {
      const result = await normalizeResults({
        results: [{
          check_id: 'xss-vulnerability',
          path: 'test.js',
          start: { line: 1 },
          end: { line: 1 },
          extra: {}
        }]
      });

      expect(result[0].owasp).toContain('A03:2021');
    });

    it('should map auth issues to OWASP A07', async () => {
      const result = await normalizeResults({
        results: [{
          check_id: 'broken-authentication',
          path: 'test.js',
          start: { line: 1 },
          end: { line: 1 },
          extra: {}
        }]
      });

      expect(result[0].owasp).toContain('A07:2021');
    });

    it('should handle missing start line', async () => {
      const result = await normalizeResults({
        results: [{
          check_id: 'test-rule',
          path: 'test.js',
          end: { line: 5 },
          extra: {}
        }]
      });

      expect(result[0].startLine).toBe(0);
    });

    it('should handle missing end line', async () => {
      const result = await normalizeResults({
        results: [{
          check_id: 'test-rule',
          path: 'test.js',
          start: { line: 1 },
          extra: {}
        }]
      });

      expect(result[0].endLine).toBe(result[0].startLine);
    });

    it('should handle missing start and end lines', async () => {
      const result = await normalizeResults({
        results: [{
          check_id: 'test-rule',
          path: 'test.js',
          extra: {}
        }]
      });

      expect(result[0].startLine).toBe(0);
      expect(result[0].endLine).toBe(0);
    });

    it('should set engine to semgrep', async () => {
      const result = await normalizeResults({
        results: [{
          check_id: 'test-rule',
          path: 'test.js',
          start: { line: 1 },
          end: { line: 1 },
          extra: {}
        }]
      });

      expect(result[0].engine).toBe('semgrep');
    });

    it('should set category to sast by default', async () => {
      const result = await normalizeResults({
        results: [{
          check_id: 'test-rule',
          path: 'test.js',
          start: { line: 1 },
          end: { line: 1 },
          extra: {}
        }]
      });

      expect(result[0].category).toBe('sast');
    });

    it('should extract category from metadata', async () => {
      const result = await normalizeResults({
        results: [{
          check_id: 'test-rule',
          path: 'test.js',
          start: { line: 1 },
          end: { line: 1 },
          extra: {
            metadata: {
              category: 'security'
            }
          }
        }]
      });

      expect(result[0].category).toBe('security');
    });

    it('should handle confidence from metadata', async () => {
      const result = await normalizeResults({
        results: [{
          check_id: 'test-rule',
          path: 'test.js',
          start: { line: 1 },
          end: { line: 1 },
          extra: {
            metadata: {
              confidence: 'HIGH'
            }
          }
        }]
      });

      expect(result[0].confidence).toBe('HIGH');
    });

    it('should default confidence to MEDIUM', async () => {
      const result = await normalizeResults({
        results: [{
          check_id: 'test-rule',
          path: 'test.js',
          start: { line: 1 },
          end: { line: 1 },
          extra: {}
        }]
      });

      expect(result[0].confidence).toBe('MEDIUM');
    });

    it('should include ruleId', async () => {
      const result = await normalizeResults({
        results: [{
          check_id: 'my-custom-rule',
          path: 'test.js',
          start: { line: 1 },
          end: { line: 1 },
          extra: {}
        }]
      });

      expect(result[0].ruleId).toBe('my-custom-rule');
    });

    it('should include file path', async () => {
      const result = await normalizeResults({
        results: [{
          check_id: 'test-rule',
          path: '/app/src/test.js',
          start: { line: 1 },
          end: { line: 1 },
          extra: {}
        }]
      });

      expect(result[0].file).toBe('/app/src/test.js');
    });

    it('should process multiple results', async () => {
      const results = await normalizeResults({
        results: [
          {
            check_id: 'rule1',
            path: 'file1.js',
            start: { line: 1 },
            end: { line: 1 },
            extra: { severity: 'ERROR' }
          },
          {
            check_id: 'rule2',
            path: 'file2.js',
            start: { line: 10 },
            end: { line: 15 },
            extra: { severity: 'WARNING' }
          }
        ]
      });

      expect(results).toHaveLength(2);
      expect(results[0].severity).toBe('CRITICAL');
      expect(results[1].severity).toBe('HIGH');
    });
  });

  describe('checkSemgrepAvailable', () => {
    it('should be a function', () => {
      expect(typeof checkSemgrepAvailable).toBe('function');
    });
  });

  describe('getSemgrepVersion', () => {
    it('should be a function', () => {
      expect(typeof getSemgrepVersion).toBe('function');
    });
  });
});