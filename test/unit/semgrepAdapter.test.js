// test/unit/semgrepAdapter.test.js
const { checkSemgrepAvailable, getSemgrepVersion, normalizeResults } = require('../../src/semgrepAdapter');

describe('semgrepAdapter', () => {
  describe('checkSemgrepAvailable', () => {
    test('should return a boolean', async () => {
      const result = await checkSemgrepAvailable();
      expect(typeof result).toBe('boolean');
    });
  });

  describe('getSemgrepVersion', () => {
    test('should return string or null', async () => {
      const result = await getSemgrepVersion();
      expect(result === null || typeof result === 'string').toBe(true);
    });
  });

  describe('normalizeResults', () => {
    test('should return empty array for null input', async () => {
      const result = await normalizeResults(null);
      expect(result).toEqual([]);
    });

    test('should return empty array for undefined input', async () => {
      const result = await normalizeResults(undefined);
      expect(result).toEqual([]);
    });

    test('should return empty array for empty results', async () => {
      const result = await normalizeResults({ results: [] });
      expect(result).toEqual([]);
    });

    test('should normalize semgrep result format', async () => {
      const semgrepOutput = {
        results: [{
          check_id: 'javascript.express.security.audit.express-path-traversal',
          path: 'test.js',
          start: { line: 10, col: 1 },
          end: { line: 10, col: 50 },
          extra: {
            message: 'Path traversal vulnerability detected',
            severity: 'WARNING',
            metadata: {
              cwe: ['CWE-22'],
              owasp: ['A01:2021']
            },
            lines: 'const file = fs.readFileSync(userInput);'
          }
        }]
      };

      const normalized = await normalizeResults(semgrepOutput);

      expect(normalized.length).toBe(1);
      expect(normalized[0]).toHaveProperty('ruleId');
      expect(normalized[0]).toHaveProperty('file');
      expect(normalized[0]).toHaveProperty('startLine');
      expect(normalized[0]).toHaveProperty('message');
    });

    test('should handle missing metadata gracefully', async () => {
      const semgrepOutput = {
        results: [{
          check_id: 'test-rule',
          path: 'test.js',
          start: { line: 1 },
          end: { line: 1 },
          extra: {
            message: 'Test finding',
            severity: 'INFO'
          }
        }]
      };

      const normalized = await normalizeResults(semgrepOutput);
      expect(normalized.length).toBe(1);
      expect(normalized[0].ruleId).toBe('test-rule');
    });
  });
});
