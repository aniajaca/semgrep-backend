const {
  normalizeResults
} = require('../../src/semgrepAdapter');

// Mock SnippetExtractor before requiring semgrepAdapter
jest.mock('../../src/lib/snippetExtractor', () => {
  return jest.fn().mockImplementation(() => ({
    extractSnippet: jest.fn().mockResolvedValue('mocked snippet')
  }));
});

jest.mock('fs', () => ({
  promises: {
    access: jest.fn()
  }
}));

jest.mock('child_process');

describe('semgrepAdapter', () => {
  
  describe('normalizeResults', () => {
    test('should return empty array for no results', async () => {
      const output = { results: [] };
      const normalized = await normalizeResults(output);
      
      expect(Array.isArray(normalized)).toBe(true);
      expect(normalized.length).toBe(0);
    });

    test('should return empty array for missing results', async () => {
      const output = {};
      const normalized = await normalizeResults(output);
      
      expect(Array.isArray(normalized)).toBe(true);
      expect(normalized.length).toBe(0);
    });

    test('should normalize ERROR severity to CRITICAL', async () => {
      const output = {
        results: [{
          check_id: 'test-rule',
          path: 'test.js',
          start: { line: 1, col: 0 },
          end: { line: 1, col: 10 },
          extra: {
            severity: 'ERROR',
            message: 'Test error',
            lines: 'const x = 1;',
            metadata: {}
          }
        }]
      };
      
      const normalized = await normalizeResults(output);
      
      expect(normalized[0].severity).toBe('CRITICAL');
      expect(normalized[0].engine).toBe('semgrep');
    });

    test('should normalize WARNING severity to HIGH', async () => {
      const output = {
        results: [{
          check_id: 'test-rule',
          path: 'test.js',
          start: { line: 1, col: 0 },
          end: { line: 1, col: 10 },
          extra: {
            severity: 'WARNING',
            message: 'Test warning',
            lines: 'const x = 1;',
            metadata: {}
          }
        }]
      };
      
      const normalized = await normalizeResults(output);
      expect(normalized[0].severity).toBe('HIGH');
    });

    test('should normalize INFO severity to MEDIUM', async () => {
      const output = {
        results: [{
          check_id: 'test-rule',
          path: 'test.js',
          start: { line: 1, col: 0 },
          end: { line: 1, col: 10 },
          extra: {
            severity: 'INFO',
            message: 'Test info',
            lines: 'const x = 1;',
            metadata: {}
          }
        }]
      };
      
      const normalized = await normalizeResults(output);
      expect(normalized[0].severity).toBe('MEDIUM');
    });

    test('should normalize INVENTORY severity to LOW', async () => {
      const output = {
        results: [{
          check_id: 'test-rule',
          path: 'test.js',
          start: { line: 1 },
          end: { line: 1 },
          extra: {
            severity: 'INVENTORY',
            message: 'Test',
            lines: 'code',
            metadata: {}
          }
        }]
      };
      
      const normalized = await normalizeResults(output);
      expect(normalized[0].severity).toBe('LOW');
    });

    test('should extract CWE from metadata array', async () => {
      const output = {
        results: [{
          check_id: 'test-rule',
          path: 'test.js',
          start: { line: 1 },
          end: { line: 1 },
          extra: {
            severity: 'ERROR',
            message: 'Test',
            lines: 'code',
            metadata: {
              cwe: ['CWE-79', 'CWE-89']
            }
          }
        }]
      };
      
      const normalized = await normalizeResults(output);
      expect(normalized[0].cwe).toContain('CWE-79');
      expect(normalized[0].cwe).toContain('CWE-89');
    });

    test('should extract CWE from metadata string', async () => {
      const output = {
        results: [{
          check_id: 'test-rule',
          path: 'test.js',
          start: { line: 1 },
          end: { line: 1 },
          extra: {
            severity: 'ERROR',
            message: 'Test',
            lines: 'code',
            metadata: {
              cwe: 'CWE-79, CWE-89'
            }
          }
        }]
      };
      
      const normalized = await normalizeResults(output);
      expect(normalized[0].cwe.length).toBeGreaterThan(0);
    });

    test('should extract CWE from cwe-id field', async () => {
      const output = {
        results: [{
          check_id: 'test-rule',
          path: 'test.js',
          start: { line: 1 },
          end: { line: 1 },
          extra: {
            severity: 'ERROR',
            message: 'Test',
            lines: 'code',
            metadata: {
              'cwe-id': '79'
            }
          }
        }]
      };
      
      const normalized = await normalizeResults(output);
      expect(normalized[0].cwe).toContain('CWE-79');
    });

    test('should extract CWE from rule ID', async () => {
      const output = {
        results: [{
          check_id: 'test-cwe-79-xss',
          path: 'test.js',
          start: { line: 1 },
          end: { line: 1 },
          extra: {
            severity: 'ERROR',
            message: 'XSS vulnerability',
            lines: 'code',
            metadata: {}
          }
        }]
      };
      
      const normalized = await normalizeResults(output);
      expect(normalized[0].cwe).toContain('CWE-79');
    });

    test('should extract OWASP from metadata array', async () => {
      const output = {
        results: [{
          check_id: 'test-rule',
          path: 'test.js',
          start: { line: 1 },
          end: { line: 1 },
          extra: {
            severity: 'ERROR',
            message: 'Test',
            lines: 'code',
            metadata: {
              owasp: ['A03:2021']
            }
          }
        }]
      };
      
      const normalized = await normalizeResults(output);
      expect(normalized[0].owasp).toContain('A03:2021');
    });

    test('should extract OWASP from metadata string', async () => {
      const output = {
        results: [{
          check_id: 'test-rule',
          path: 'test.js',
          start: { line: 1 },
          end: { line: 1 },
          extra: {
            severity: 'ERROR',
            message: 'Test',
            lines: 'code',
            metadata: {
              owasp: 'A03:2021, A01:2021'
            }
          }
        }]
      };
      
      const normalized = await normalizeResults(output);
      expect(normalized[0].owasp.length).toBeGreaterThan(0);
    });

    test('should map SQL injection to OWASP category', async () => {
      const output = {
        results: [{
          check_id: 'sql-injection-test',
          path: 'test.js',
          start: { line: 1 },
          end: { line: 1 },
          extra: {
            severity: 'ERROR',
            message: 'SQL Injection',
            lines: 'code',
            metadata: {}
          }
        }]
      };
      
      const normalized = await normalizeResults(output);
      expect(normalized[0].owasp).toContain('A03:2021');
    });

    test('should map XSS to OWASP category', async () => {
      const output = {
        results: [{
          check_id: 'xss-vulnerability',
          path: 'test.js',
          start: { line: 1 },
          end: { line: 1 },
          extra: {
            severity: 'ERROR',
            message: 'XSS',
            lines: 'code',
            metadata: {}
          }
        }]
      };
      
      const normalized = await normalizeResults(output);
      expect(normalized[0].owasp).toContain('A03:2021');
    });

    test('should map auth to OWASP category', async () => {
      const output = {
        results: [{
          check_id: 'auth-bypass',
          path: 'test.js',
          start: { line: 1 },
          end: { line: 1 },
          extra: {
            severity: 'ERROR',
            message: 'Auth bypass',
            lines: 'code',
            metadata: {}
          }
        }]
      };
      
      const normalized = await normalizeResults(output);
      expect(normalized[0].owasp).toContain('A07:2021');
    });

    test('should include file path', async () => {
      const output = {
        results: [{
          check_id: 'test-rule',
          path: 'src/test.js',
          start: { line: 1 },
          end: { line: 1 },
          extra: {
            severity: 'ERROR',
            message: 'Test',
            lines: 'code',
            metadata: {}
          }
        }]
      };
      
      const normalized = await normalizeResults(output);
      expect(normalized[0].file).toBe('src/test.js');
    });

    test('should include line numbers', async () => {
      const output = {
        results: [{
          check_id: 'test-rule',
          path: 'test.js',
          start: { line: 10, col: 5 },
          end: { line: 15, col: 20 },
          extra: {
            severity: 'ERROR',
            message: 'Test',
            lines: 'code',
            metadata: {}
          }
        }]
      };
      
      const normalized = await normalizeResults(output);
      expect(normalized[0].startLine).toBe(10);
      expect(normalized[0].endLine).toBe(15);
      expect(normalized[0].startColumn).toBe(5);
      expect(normalized[0].endColumn).toBe(20);
    });

    test('should handle missing metadata gracefully', async () => {
      const output = {
        results: [{
          check_id: 'test-rule',
          path: 'test.js',
          start: { line: 1 },
          end: { line: 1 },
          extra: {
            severity: 'ERROR',
            message: 'Test',
            lines: 'code'
          }
        }]
      };
      
      const normalized = await normalizeResults(output);
      expect(normalized[0]).toBeDefined();
      expect(normalized[0].cwe).toEqual([]);
    });

    test('should default missing severity to MEDIUM', async () => {
      const output = {
        results: [{
          check_id: 'test-rule',
          path: 'test.js',
          start: { line: 1 },
          end: { line: 1 },
          extra: {
            message: 'Test',
            lines: 'code',
            metadata: {}
          }
        }]
      };
      
      const normalized = await normalizeResults(output);
      expect(normalized[0].severity).toBe('MEDIUM');
    });

    test('should include category from metadata', async () => {
      const output = {
        results: [{
          check_id: 'test-rule',
          path: 'test.js',
          start: { line: 1 },
          end: { line: 1 },
          extra: {
            severity: 'ERROR',
            message: 'Test',
            lines: 'code',
            metadata: {
              category: 'injection'
            }
          }
        }]
      };
      
      const normalized = await normalizeResults(output);
      expect(normalized[0].category).toBe('injection');
    });

    test('should default category to sast', async () => {
      const output = {
        results: [{
          check_id: 'test-rule',
          path: 'test.js',
          start: { line: 1 },
          end: { line: 1 },
          extra: {
            severity: 'ERROR',
            message: 'Test',
            lines: 'code',
            metadata: {}
          }
        }]
      };
      
      const normalized = await normalizeResults(output);
      expect(normalized[0].category).toBe('sast');
    });

    test('should include confidence level', async () => {
      const output = {
        results: [{
          check_id: 'test-rule',
          path: 'test.js',
          start: { line: 1 },
          end: { line: 1 },
          extra: {
            severity: 'ERROR',
            message: 'Test',
            lines: 'code',
            metadata: {
              confidence: 'HIGH'
            }
          }
        }]
      };
      
      const normalized = await normalizeResults(output);
      expect(normalized[0].confidence).toBe('HIGH');
    });

    test('should process multiple results', async () => {
      const output = {
        results: [
          {
            check_id: 'rule1',
            path: 'file1.js',
            start: { line: 1 },
            end: { line: 1 },
            extra: { severity: 'ERROR', message: 'Test1', lines: 'code', metadata: {} }
          },
          {
            check_id: 'rule2',
            path: 'file2.js',
            start: { line: 5 },
            end: { line: 5 },
            extra: { severity: 'WARNING', message: 'Test2', lines: 'code', metadata: {} }
          }
        ]
      };
      
      const normalized = await normalizeResults(output);
      expect(normalized.length).toBe(2);
      expect(normalized[0].ruleId).toBe('rule1');
      expect(normalized[1].ruleId).toBe('rule2');
    });

    test('should handle missing start/end gracefully', async () => {
      const output = {
        results: [{
          check_id: 'test-rule',
          path: 'test.js',
          extra: {
            severity: 'ERROR',
            message: 'Test',
            lines: 'code',
            metadata: {}
          }
        }]
      };
      
      const normalized = await normalizeResults(output);
      expect(normalized[0].startLine).toBe(0);
      expect(normalized[0].endLine).toBe(0);
    });
  });
});