// test/unit/semgrepAdapter.working.test.js
// Mock SnippetExtractor BEFORE requiring semgrepAdapter
jest.mock('../../src/lib/snippetExtractor', () => {
  return class SnippetExtractor {
    constructor() {
      this.fileCache = new Map();
      this.snippetCache = new Map();
    }
    
    async extractSnippet(filePath, startLine, endLine, options = {}) {
      // Mock implementation
      return `→ ${startLine}: const vulnerable = eval(userInput);`;
    }
    
    clearCache() {
      this.fileCache.clear();
      this.snippetCache.clear();
    }
  };
});

const {
  runSemgrep,
  checkSemgrepAvailable,
  getSemgrepVersion,
  normalizeResults
} = require('../../src/semgrepAdapter');

describe('SemgrepAdapter', () => {
  describe('normalizeResults', () => {
    it('should normalize empty results', async () => {
      const semgrepOutput = { results: [] };
      const findings = await normalizeResults(semgrepOutput);
      
      expect(Array.isArray(findings)).toBe(true);
      expect(findings.length).toBe(0);
    });

    it('should normalize results with missing results array', async () => {
      const semgrepOutput = {};
      const findings = await normalizeResults(semgrepOutput);
      
      expect(Array.isArray(findings)).toBe(true);
      expect(findings.length).toBe(0);
    });

    it('should normalize basic Semgrep finding', async () => {
      const semgrepOutput = {
        results: [
          {
            check_id: 'javascript.lang.security.audit.eval',
            path: 'test.js',
            start: { line: 10, col: 5 },
            end: { line: 10, col: 20 },
            extra: {
              severity: 'ERROR',
              message: 'Use of eval detected',
              lines: 'eval(userInput)',
              metadata: {
                cwe: ['CWE-95'],
                owasp: ['A03:2021'],
                confidence: 'HIGH'
              }
            }
          }
        ]
      };

      const findings = await normalizeResults(semgrepOutput);
      
      expect(findings.length).toBe(1);
      expect(findings[0].engine).toBe('semgrep');
      expect(findings[0].severity).toBe('CRITICAL');
      expect(findings[0].file).toBe('test.js');
      expect(findings[0].startLine).toBe(10);
    });

    it('should map Semgrep severities correctly', async () => {
      const semgrepOutput = {
        results: [
          {
            check_id: 'test-error',
            path: 'test.js',
            start: { line: 1 },
            end: { line: 1 },
            extra: { severity: 'ERROR', message: 'Error test' }
          },
          {
            check_id: 'test-warning',
            path: 'test.js',
            start: { line: 2 },
            end: { line: 2 },
            extra: { severity: 'WARNING', message: 'Warning test' }
          },
          {
            check_id: 'test-info',
            path: 'test.js',
            start: { line: 3 },
            end: { line: 3 },
            extra: { severity: 'INFO', message: 'Info test' }
          }
        ]
      };

      const findings = await normalizeResults(semgrepOutput);
      
      expect(findings.length).toBe(3);
      expect(findings[0].severity).toBe('CRITICAL');
      expect(findings[1].severity).toBe('HIGH');
      expect(findings[2].severity).toBe('MEDIUM');
    });

    it('should extract CWE from metadata', async () => {
      const semgrepOutput = {
        results: [
          {
            check_id: 'test-cwe',
            path: 'test.js',
            start: { line: 1 },
            end: { line: 1 },
            extra: {
              severity: 'ERROR',
              message: 'Test',
              metadata: {
                cwe: ['CWE-79', 'CWE-89']
              }
            }
          }
        ]
      };

      const findings = await normalizeResults(semgrepOutput);
      
      expect(findings[0].cwe).toContain('CWE-79');
      expect(findings[0].cwe).toContain('CWE-89');
    });

    it('should extract CWE from rule ID', async () => {
      const semgrepOutput = {
        results: [
          {
            check_id: 'javascript.cwe-79.xss-detection',
            path: 'test.js',
            start: { line: 1 },
            end: { line: 1 },
            extra: {
              severity: 'ERROR',
              message: 'XSS detected'
            }
          }
        ]
      };

      const findings = await normalizeResults(semgrepOutput);
      
      expect(findings[0].cwe).toContain('CWE-79');
    });

    it('should extract OWASP from metadata', async () => {
      const semgrepOutput = {
        results: [
          {
            check_id: 'test-owasp',
            path: 'test.js',
            start: { line: 1 },
            end: { line: 1 },
            extra: {
              severity: 'ERROR',
              message: 'Test',
              metadata: {
                owasp: ['A03:2021']
              }
            }
          }
        ]
      };

      const findings = await normalizeResults(semgrepOutput);
      
      expect(findings[0].owasp).toContain('A03:2021');
    });

    it('should infer OWASP from rule ID', async () => {
      const semgrepOutput = {
        results: [
          {
            check_id: 'javascript.sql-injection.detect',
            path: 'test.js',
            start: { line: 1 },
            end: { line: 1 },
            extra: {
              severity: 'ERROR',
              message: 'SQL injection'
            }
          }
        ]
      };

      const findings = await normalizeResults(semgrepOutput);
      
      expect(findings[0].owasp.length).toBeGreaterThan(0);
    });

    it('should handle findings with fix suggestions', async () => {
      const semgrepOutput = {
        results: [
          {
            check_id: 'test-fix',
            path: 'test.js',
            start: { line: 1 },
            end: { line: 1 },
            extra: {
              severity: 'ERROR',
              message: 'Use secure function',
              fix: 'Use secureFunction() instead',
              fix_regex: {
                regex: 'insecureFunc',
                replacement: 'secureFunction'
              }
            }
          }
        ]
      };

      const findings = await normalizeResults(semgrepOutput);
      
      expect(findings[0].fix).toBe('Use secureFunction() instead');
      expect(findings[0].fixRegex).toBeDefined();
    });

    it('should handle findings without start/end line', async () => {
      const semgrepOutput = {
        results: [
          {
            check_id: 'test',
            path: 'test.js',
            extra: {
              severity: 'ERROR',
              message: 'Test'
            }
          }
        ]
      };

      const findings = await normalizeResults(semgrepOutput);
      
      expect(findings[0].startLine).toBe(0);
      expect(findings[0].endLine).toBe(0);
    });

    it('should use enhanced snippet extraction', async () => {
      const semgrepOutput = {
        results: [
          {
            check_id: 'test',
            path: 'test.js',
            start: { line: 5 },
            end: { line: 5 },
            extra: {
              severity: 'ERROR',
              message: 'Test',
              lines: 'requires login'  // Triggers enhancement
            }
          }
        ]
      };

      const findings = await normalizeResults(semgrepOutput, '/test/path');
      
      // Should have used SnippetExtractor (mocked)
      expect(findings[0].snippet).toBeDefined();
    });

    it('should handle multiple findings', async () => {
      const semgrepOutput = {
        results: Array(10).fill({
          check_id: 'test',
          path: 'test.js',
          start: { line: 1 },
          end: { line: 1 },
          extra: {
            severity: 'ERROR',
            message: 'Test'
          }
        })
      };

      const findings = await normalizeResults(semgrepOutput);
      
      expect(findings.length).toBe(10);
    });
  });

  describe('checkSemgrepAvailable', () => {
    it('should return boolean', async () => {
      const result = await checkSemgrepAvailable();
      expect(typeof result).toBe('boolean');
    });
  });

  describe('getSemgrepVersion', () => {
    it('should return version string or null', async () => {
      const version = await getSemgrepVersion();
      expect(version === null || typeof version === 'string').toBe(true);
    });
  });

  describe('Helper Functions', () => {
    it('should handle CWE string formats', async () => {
      const testCases = [
        { input: 'CWE-79', expected: 'CWE-79' },
        { input: '79', expected: 'CWE-79' },
        { input: 'cwe-79', expected: 'CWE-79' }
      ];

      for (const testCase of testCases) {
        const semgrepOutput = {
          results: [{
            check_id: 'test',
            path: 'test.js',
            start: { line: 1 },
            end: { line: 1 },
            extra: {
              severity: 'ERROR',
              message: 'Test',
              metadata: { cwe: [testCase.input] }
            }
          }]
        };

        const findings = await normalizeResults(semgrepOutput);
        expect(findings[0].cwe[0]).toBe(testCase.expected);
      }
    });

    it('should deduplicate CWE entries', async () => {
      const semgrepOutput = {
        results: [{
          check_id: 'test-cwe-79',  // Contains CWE in ID
          path: 'test.js',
          start: { line: 1 },
          end: { line: 1 },
          extra: {
            severity: 'ERROR',
            message: 'Test',
            metadata: {
              cwe: ['CWE-79']  // Same CWE in metadata
            }
          }
        }]
      };

      const findings = await normalizeResults(semgrepOutput);
      
      // Should only have one CWE-79, not duplicates
      const cweCount = findings[0].cwe.filter(c => c === 'CWE-79').length;
      expect(cweCount).toBe(1);
    });

    it('should handle OWASP array formats', async () => {
      const semgrepOutput = {
        results: [{
          check_id: 'test',
          path: 'test.js',
          start: { line: 1 },
          end: { line: 1 },
          extra: {
            severity: 'ERROR',
            message: 'Test',
            metadata: {
              owasp: ['A01:2021', 'A03:2021']
            }
          }
        }]
      };

      const findings = await normalizeResults(semgrepOutput);
      
      expect(findings[0].owasp.length).toBe(2);
      expect(findings[0].owasp).toContain('A01:2021');
      expect(findings[0].owasp).toContain('A03:2021');
    });

    it('should handle OWASP string formats', async () => {
      const semgrepOutput = {
        results: [{
          check_id: 'test',
          path: 'test.js',
          start: { line: 1 },
          end: { line: 1 },
          extra: {
            severity: 'ERROR',
            message: 'Test',
            metadata: {
              owasp: 'A01:2021, A03:2021'
            }
          }
        }]
      };

      const findings = await normalizeResults(semgrepOutput);
      
      expect(findings[0].owasp.length).toBeGreaterThanOrEqual(2);
    });
  });

  describe('Edge Cases', () => {
    it('should handle null semgrepOutput', async () => {
      const findings = await normalizeResults(null);
      expect(findings).toEqual([]);
    });

    it('should handle undefined semgrepOutput', async () => {
      const findings = await normalizeResults(undefined);
      expect(findings).toEqual([]);
    });

    it('should handle results as non-array', async () => {
      const semgrepOutput = { results: 'not an array' };
      const findings = await normalizeResults(semgrepOutput);
      expect(findings).toEqual([]);
    });

    it('should handle missing extra field', async () => {
      const semgrepOutput = {
        results: [{
          check_id: 'test',
          path: 'test.js',
          start: { line: 1 },
          end: { line: 1 }
        }]
      };

      const findings = await normalizeResults(semgrepOutput);
      
      expect(findings.length).toBe(1);
      expect(findings[0].severity).toBe('MEDIUM');
    });

    it('should handle missing metadata', async () => {
      const semgrepOutput = {
        results: [{
          check_id: 'test',
          path: 'test.js',
          start: { line: 1 },
          end: { line: 1 },
          extra: {
            severity: 'ERROR',
            message: 'Test'
          }
        }]
      };

      const findings = await normalizeResults(semgrepOutput);
      
      expect(findings[0].cwe).toEqual([]);
      expect(findings[0].owasp.length).toBeGreaterThanOrEqual(0);
    });

    it('should use default values for missing fields', async () => {
      const semgrepOutput = {
        results: [{
          extra: {}
        }]
      };

      const findings = await normalizeResults(semgrepOutput);
      
      expect(findings[0].ruleId).toBe('unknown');
      expect(findings[0].file).toBe('unknown');
      expect(findings[0].message).toBe('Security issue detected');
    });
  });
});