// test/unit/semgrepAdapter.test.js
// Comprehensive foundational tests for semgrepAdapter

const { 
  normalizeResults, 
  checkSemgrepAvailable, 
  getSemgrepVersion 
} = require('../../src/semgrepAdapter');
const fs = require('fs').promises;
const path = require('path');

describe('semgrepAdapter - Comprehensive Foundational Tests', () => {
  
  // ============================================================================
  // SECTION 1: normalizeResults - Core Functionality
  // ============================================================================
  
  describe('normalizeResults - Core Functionality', () => {
    
    it('should handle null/undefined input gracefully', async () => {
      expect(await normalizeResults(null)).toEqual([]);
      expect(await normalizeResults(undefined)).toEqual([]);
      expect(await normalizeResults({})).toEqual([]);
      expect(await normalizeResults({ results: null })).toEqual([]);
    });

    it('should handle empty results array', async () => {
      const result = await normalizeResults({ results: [] });
      expect(result).toEqual([]);
    });

    it('should normalize a basic Semgrep finding correctly', async () => {
      const semgrepOutput = {
        results: [{
          check_id: 'javascript.lang.security.audit.sql-injection',
          path: 'controllers/user.js',
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
        }]
      };

      const results = await normalizeResults(semgrepOutput);

      expect(results).toHaveLength(1);
      expect(results[0]).toMatchObject({
        engine: 'semgrep',
        ruleId: 'javascript.lang.security.audit.sql-injection',
        category: 'sast',
        severity: 'CRITICAL',
        message: 'Potential SQL injection vulnerability',
        cwe: ['CWE-89'],
        owasp: ['A03:2021'],
        file: 'controllers/user.js',
        startLine: 42,
        endLine: 42,
        startColumn: 10,
        endColumn: 50,
        confidence: 'HIGH'
      });
    });

    it('should normalize multiple findings', async () => {
      const semgrepOutput = {
        results: [
          {
            check_id: 'rule1',
            path: 'file1.js',
            start: { line: 10 },
            end: { line: 10 },
            extra: { severity: 'ERROR', message: 'Finding 1' }
          },
          {
            check_id: 'rule2',
            path: 'file2.js',
            start: { line: 20 },
            end: { line: 20 },
            extra: { severity: 'WARNING', message: 'Finding 2' }
          },
          {
            check_id: 'rule3',
            path: 'file3.js',
            start: { line: 30 },
            end: { line: 30 },
            extra: { severity: 'INFO', message: 'Finding 3' }
          }
        ]
      };

      const results = await normalizeResults(semgrepOutput);

      expect(results).toHaveLength(3);
      expect(results[0].severity).toBe('CRITICAL');
      expect(results[1].severity).toBe('HIGH');
      expect(results[2].severity).toBe('MEDIUM');
    });
  });

  // ============================================================================
  // SECTION 2: Severity Mapping
  // ============================================================================
  
  describe('normalizeResults - Severity Mapping', () => {
    
    const severityTestCases = [
      { input: 'ERROR', expected: 'CRITICAL' },
      { input: 'WARNING', expected: 'HIGH' },
      { input: 'INFO', expected: 'MEDIUM' },
      { input: 'INVENTORY', expected: 'LOW' },
      { input: 'EXPERIMENTAL', expected: 'LOW' },
      { input: 'UNKNOWN', expected: 'MEDIUM' }, // Unknown maps to MEDIUM
      { input: undefined, expected: 'MEDIUM' }, // Missing maps to MEDIUM
    ];

    severityTestCases.forEach(({ input, expected }) => {
      it(`should map severity "${input}" to "${expected}"`, async () => {
        const semgrepOutput = {
          results: [{
            check_id: 'test-rule',
            path: 'test.js',
            start: { line: 1 },
            end: { line: 1 },
            extra: input ? { severity: input } : {}
          }]
        };

        const results = await normalizeResults(semgrepOutput);
        expect(results[0].severity).toBe(expected);
      });
    });

    it('should handle case-insensitive severity values', async () => {
      const severities = ['error', 'Error', 'ERROR', 'ErRoR'];
      
      for (const severity of severities) {
        const result = await normalizeResults({
          results: [{
            check_id: 'test',
            path: 'test.js',
            start: { line: 1 },
            end: { line: 1 },
            extra: { severity }
          }]
        });
        
        expect(result[0].severity).toBe('CRITICAL');
      }
    });
  });

  // ============================================================================
  // SECTION 3: CWE Extraction
  // ============================================================================
  
  describe('normalizeResults - CWE Extraction', () => {
    
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

    it('should extract CWE from comma-separated string', async () => {
      const result = await normalizeResults({
        results: [{
          check_id: 'test-rule',
          path: 'test.js',
          start: { line: 1 },
          end: { line: 1 },
          extra: {
            metadata: {
              cwe: 'CWE-79, CWE-80, CWE-81'
            }
          }
        }]
      });

      expect(result[0].cwe).toEqual(['CWE-79', 'CWE-80', 'CWE-81']);
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

    it('should extract CWE from check_id with different formats', async () => {
      const testCases = [
        { ruleId: 'security-cwe-79', expected: 'CWE-79' },
        { ruleId: 'xss-CWE79-test', expected: 'CWE-79' },
        { ruleId: 'cwe_89_sqli', expected: 'CWE-89' },
      ];

      for (const { ruleId, expected } of testCases) {
        const result = await normalizeResults({
          results: [{
            check_id: ruleId,
            path: 'test.js',
            start: { line: 1 },
            end: { line: 1 },
            extra: {}
          }]
        });

        expect(result[0].cwe).toContain(expected);
      }
    });

    it('should format CWE identifiers consistently', async () => {
      const testCases = [
        { input: 'cwe-79', expected: 'CWE-79' },
        { input: 'CWE79', expected: 'CWE-79' },
        { input: '79', expected: 'CWE-79' },
        { input: 'CWE-79', expected: 'CWE-79' },
      ];

      for (const { input, expected } of testCases) {
        const result = await normalizeResults({
          results: [{
            check_id: 'test',
            path: 'test.js',
            start: { line: 1 },
            end: { line: 1 },
            extra: {
              metadata: { cwe: input }
            }
          }]
        });

        expect(result[0].cwe[0]).toBe(expected);
      }
    });

    it('should deduplicate CWE identifiers', async () => {
      const result = await normalizeResults({
        results: [{
          check_id: 'cwe-79-xss-cwe-79',
          path: 'test.js',
          start: { line: 1 },
          end: { line: 1 },
          extra: {
            metadata: {
              cwe: ['CWE-79', 'CWE-79']
            }
          }
        }]
      });

      // Should have CWE-79 only once
      const cweCount = result[0].cwe.filter(c => c === 'CWE-79').length;
      expect(cweCount).toBe(1);
    });

    it('should handle metadata cwe-id field', async () => {
      const result = await normalizeResults({
        results: [{
          check_id: 'test',
          path: 'test.js',
          start: { line: 1 },
          end: { line: 1 },
          extra: {
            metadata: {
              'cwe-id': 'CWE-89'
            }
          }
        }]
      });

      expect(result[0].cwe).toContain('CWE-89');
    });
  });

  // ============================================================================
  // SECTION 4: OWASP Mapping
  // ============================================================================
  
  describe('normalizeResults - OWASP Extraction', () => {
    
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

    it('should map crypto issues to OWASP A02', async () => {
      const result = await normalizeResults({
        results: [{
          check_id: 'weak-crypto-algorithm',
          path: 'test.js',
          start: { line: 1 },
          end: { line: 1 },
          extra: {}
        }]
      });

      expect(result[0].owasp).toContain('A02:2021');
    });

    it('should map XXE to OWASP A05', async () => {
      const result = await normalizeResults({
        results: [{
          check_id: 'xxe-vulnerability',
          path: 'test.js',
          start: { line: 1 },
          end: { line: 1 },
          extra: {}
        }]
      });

      expect(result[0].owasp).toContain('A05:2021');
    });

    it('should map deserialization to OWASP A08', async () => {
      const result = await normalizeResults({
        results: [{
          check_id: 'insecure-deserialization',
          path: 'test.js',
          start: { line: 1 },
          end: { line: 1 },
          extra: {}
        }]
      });

      expect(result[0].owasp).toContain('A08:2021');
    });

    it('should deduplicate OWASP categories', async () => {
      const result = await normalizeResults({
        results: [{
          check_id: 'test',
          path: 'test.js',
          start: { line: 1 },
          end: { line: 1 },
          extra: {
            metadata: {
              owasp: ['A03:2021', 'A03:2021']
            }
          }
        }]
      });

      const owaspCount = result[0].owasp.filter(o => o === 'A03:2021').length;
      expect(owaspCount).toBe(1);
    });
  });

  // ============================================================================
  // SECTION 5: Line Number Handling
  // ============================================================================
  
  describe('normalizeResults - Line Number Handling', () => {
    
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
          start: { line: 10 },
          extra: {}
        }]
      });

      expect(result[0].endLine).toBe(0);
    });

    it('should handle missing both start and end lines', async () => {
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

    it('should handle column information', async () => {
      const result = await normalizeResults({
        results: [{
          check_id: 'test',
          path: 'test.js',
          start: { line: 10, col: 5 },
          end: { line: 10, col: 25 },
          extra: {}
        }]
      });

      expect(result[0].startColumn).toBe(5);
      expect(result[0].endColumn).toBe(25);
    });

    it('should default columns to 0 when missing', async () => {
      const result = await normalizeResults({
        results: [{
          check_id: 'test',
          path: 'test.js',
          start: { line: 10 },
          end: { line: 10 },
          extra: {}
        }]
      });

      expect(result[0].startColumn).toBe(0);
      expect(result[0].endColumn).toBe(0);
    });
  });

  // ============================================================================
  // SECTION 6: Metadata and Additional Fields
  // ============================================================================
  
  describe('normalizeResults - Metadata and Fields', () => {
    
    it('should include engine field as "semgrep"', async () => {
      const result = await normalizeResults({
        results: [{
          check_id: 'test',
          path: 'test.js',
          start: { line: 1 },
          end: { line: 1 },
          extra: {}
        }]
      });

      expect(result[0].engine).toBe('semgrep');
    });

    it('should set default category to "sast"', async () => {
      const result = await normalizeResults({
        results: [{
          check_id: 'test',
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
          check_id: 'test',
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

    it('should include confidence from metadata', async () => {
      const result = await normalizeResults({
        results: [{
          check_id: 'test',
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
          check_id: 'test',
          path: 'test.js',
          start: { line: 1 },
          end: { line: 1 },
          extra: {}
        }]
      });

      expect(result[0].confidence).toBe('MEDIUM');
    });

    it('should include impact from metadata', async () => {
      const result = await normalizeResults({
        results: [{
          check_id: 'test',
          path: 'test.js',
          start: { line: 1 },
          end: { line: 1 },
          extra: {
            metadata: {
              impact: 'HIGH'
            }
          }
        }]
      });

      expect(result[0].impact).toBe('HIGH');
    });

    it('should include likelihood from metadata', async () => {
      const result = await normalizeResults({
        results: [{
          check_id: 'test',
          path: 'test.js',
          start: { line: 1 },
          end: { line: 1 },
          extra: {
            metadata: {
              likelihood: 'MEDIUM'
            }
          }
        }]
      });

      expect(result[0].likelihood).toBe('MEDIUM');
    });

    it('should include references from metadata', async () => {
      const refs = [
        'https://owasp.org/www-community/attacks/SQL_Injection',
        'https://cwe.mitre.org/data/definitions/89.html'
      ];

      const result = await normalizeResults({
        results: [{
          check_id: 'test',
          path: 'test.js',
          start: { line: 1 },
          end: { line: 1 },
          extra: {
            metadata: {
              references: refs
            }
          }
        }]
      });

      expect(result[0].references).toEqual(refs);
    });

    it('should include fix suggestion from extra', async () => {
      const result = await normalizeResults({
        results: [{
          check_id: 'test',
          path: 'test.js',
          start: { line: 1 },
          end: { line: 1 },
          extra: {
            fix: 'Use parameterized queries'
          }
        }]
      });

      expect(result[0].fix).toBe('Use parameterized queries');
    });

    it('should include fixRegex from extra', async () => {
      const result = await normalizeResults({
        results: [{
          check_id: 'test',
          path: 'test.js',
          start: { line: 1 },
          end: { line: 1 },
          extra: {
            fix_regex: {
              regex: 'vulnerable_pattern',
              replacement: 'safe_pattern'
            }
          }
        }]
      });

      expect(result[0].fixRegex).toBeDefined();
    });

    it('should handle message from extra.message', async () => {
      const result = await normalizeResults({
        results: [{
          check_id: 'test',
          path: 'test.js',
          start: { line: 1 },
          end: { line: 1 },
          extra: {
            message: 'Custom security message'
          }
        }]
      });

      expect(result[0].message).toBe('Custom security message');
    });

    it('should fallback to result.message if extra.message missing', async () => {
      const result = await normalizeResults({
        results: [{
          check_id: 'test',
          path: 'test.js',
          message: 'Fallback message',
          start: { line: 1 },
          end: { line: 1 },
          extra: {}
        }]
      });

      expect(result[0].message).toBe('Fallback message');
    });

    it('should use default message if both missing', async () => {
      const result = await normalizeResults({
        results: [{
          check_id: 'test',
          path: 'test.js',
          start: { line: 1 },
          end: { line: 1 },
          extra: {}
        }]
      });

      expect(result[0].message).toBe('Security issue detected');
    });

    it('should include ruleId from check_id', async () => {
      const result = await normalizeResults({
        results: [{
          check_id: 'my-custom-rule-123',
          path: 'test.js',
          start: { line: 1 },
          end: { line: 1 },
          extra: {}
        }]
      });

      expect(result[0].ruleId).toBe('my-custom-rule-123');
    });

    it('should default ruleId to "unknown" if missing', async () => {
      const result = await normalizeResults({
        results: [{
          path: 'test.js',
          start: { line: 1 },
          end: { line: 1 },
          extra: {}
        }]
      });

      expect(result[0].ruleId).toBe('unknown');
    });

    it('should include file path', async () => {
      const result = await normalizeResults({
        results: [{
          check_id: 'test',
          path: '/app/src/controllers/user.js',
          start: { line: 1 },
          end: { line: 1 },
          extra: {}
        }]
      });

      expect(result[0].file).toBe('/app/src/controllers/user.js');
    });

    it('should default file to "unknown" if missing', async () => {
      const result = await normalizeResults({
        results: [{
          check_id: 'test',
          start: { line: 1 },
          end: { line: 1 },
          extra: {}
        }]
      });

      expect(result[0].file).toBe('unknown');
    });
  });

  // ============================================================================
  // SECTION 7: Edge Cases and Error Handling
  // ============================================================================
  
  describe('normalizeResults - Edge Cases', () => {
    
    it('should handle result without extra property', async () => {
      const result = await normalizeResults({
        results: [{
          check_id: 'test',
          path: 'test.js',
          start: { line: 1 },
          end: { line: 1 }
        }]
      });

      expect(result[0].severity).toBe('MEDIUM');
      expect(result[0].message).toBe('Security issue detected');
      expect(result[0].cwe).toEqual([]);
      expect(result[0].owasp).toEqual([]);
    });

    it('should handle malformed severity value', async () => {
      const result = await normalizeResults({
        results: [{
          check_id: 'test',
          path: 'test.js',
          start: { line: 1 },
          end: { line: 1 },
          extra: {
            severity: 'INVALID_SEVERITY'
          }
        }]
      });

      expect(result[0].severity).toBe('MEDIUM');
    });

    it('should handle non-array results', async () => {
      const result = await normalizeResults({
        results: 'not-an-array'
      });

      expect(result).toEqual([]);
    });

    it('should handle very large result sets', async () => {
      const results = Array.from({ length: 1000 }, (_, i) => ({
        check_id: `rule-${i}`,
        path: `file-${i}.js`,
        start: { line: i },
        end: { line: i },
        extra: { severity: 'ERROR' }
      }));

      const normalized = await normalizeResults({ results });

      expect(normalized).toHaveLength(1000);
      expect(normalized[0].ruleId).toBe('rule-0');
      expect(normalized[999].ruleId).toBe('rule-999');
    });

    it('should handle special characters in paths', async () => {
      const result = await normalizeResults({
        results: [{
          check_id: 'test',
          path: '../../../etc/passwd',
          start: { line: 1 },
          end: { line: 1 },
          extra: {}
        }]
      });

      expect(result[0].file).toBe('../../../etc/passwd');
    });

    it('should handle unicode in messages', async () => {
      const result = await normalizeResults({
        results: [{
          check_id: 'test',
          path: 'test.js',
          start: { line: 1 },
          end: { line: 1 },
          extra: {
            message: 'Security issue detected: 安全问题 🔒'
          }
        }]
      });

      expect(result[0].message).toContain('安全问题');
      expect(result[0].message).toContain('🔒');
    });
  });

  // ============================================================================
  // SECTION 8: Helper Functions
  // ============================================================================
  
  describe('checkSemgrepAvailable', () => {
    
    it('should be a function', () => {
      expect(typeof checkSemgrepAvailable).toBe('function');
    });

    it('should return a Promise', () => {
      const result = checkSemgrepAvailable();
      expect(result).toBeInstanceOf(Promise);
    });

    // Note: Actual execution depends on environment
    it('should eventually resolve to boolean', async () => {
      const result = await checkSemgrepAvailable();
      expect(typeof result).toBe('boolean');
    }, 10000); // 10 second timeout
  });

  describe('getSemgrepVersion', () => {
    
    it('should be a function', () => {
      expect(typeof getSemgrepVersion).toBe('function');
    });

    it('should return a Promise', () => {
      const result = getSemgrepVersion();
      expect(result).toBeInstanceOf(Promise);
    });

    // Note: Actual execution depends on environment
    it('should resolve to string or null', async () => {
      const version = await getSemgrepVersion();
      expect(version === null || typeof version === 'string').toBe(true);
      
      if (version) {
        // If version exists, it should match semantic versioning pattern
        expect(version).toMatch(/^\d+\.\d+\.\d+/);
      }
    }, 10000); // 10 second timeout
  });

  // ============================================================================
  // SECTION 9: Integration Scenarios
  // ============================================================================
  
  describe('normalizeResults - Integration Scenarios', () => {
    
    it('should handle real-world SQL injection finding', async () => {
      const semgrepOutput = {
        results: [{
          check_id: 'javascript.sequelize.security.audit.sequelize-injection-express',
          path: 'src/controllers/userController.js',
          start: { line: 45, col: 12 },
          end: { line: 45, col: 65 },
          extra: {
            message: 'Detected possible SQL injection. Use parameterized queries.',
            severity: 'ERROR',
            metadata: {
              cwe: ['CWE-89'],
              owasp: ['A03:2021 - Injection'],
              confidence: 'HIGH',
              impact: 'HIGH',
              likelihood: 'HIGH',
              category: 'security'
            },
            lines: 'User.findAll({ where: { id: req.params.id } })'
          }
        }]
      };

      const results = await normalizeResults(semgrepOutput);

      expect(results[0]).toMatchObject({
        engine: 'semgrep',
        category: 'security',
        severity: 'CRITICAL',
        confidence: 'HIGH',
        impact: 'HIGH',
        likelihood: 'HIGH'
      });
      expect(results[0].cwe).toContain('CWE-89');
      expect(results[0].owasp).toContain('A03:2021 - Injection');
    });

    it('should handle real-world XSS finding', async () => {
      const semgrepOutput = {
        results: [{
          check_id: 'javascript.react.security.audit.react-dangerouslysetinnerhtml',
          path: 'src/components/UserProfile.jsx',
          start: { line: 23, col: 8 },
          end: { line: 23, col: 52 },
          extra: {
            message: 'Dangerous use of dangerouslySetInnerHTML detected',
            severity: 'WARNING',
            metadata: {
              cwe: ['CWE-79', 'CWE-80'],
              owasp: ['A03:2021'],
              confidence: 'MEDIUM'
            }
          }
        }]
      };

      const results = await normalizeResults(semgrepOutput);

      expect(results[0].severity).toBe('HIGH');
      expect(results[0].cwe).toContain('CWE-79');
      expect(results[0].cwe).toContain('CWE-80');
    });

    it('should handle mixed severity findings', async () => {
      const semgrepOutput = {
        results: [
          {
            check_id: 'critical-finding',
            path: 'auth.js',
            start: { line: 10 },
            end: { line: 10 },
            extra: { severity: 'ERROR', message: 'Critical security issue' }
          },
          {
            check_id: 'low-finding',
            path: 'utils.js',
            start: { line: 20 },
            end: { line: 20 },
            extra: { severity: 'INFO', message: 'Minor code smell' }
          },
          {
            check_id: 'medium-finding',
            path: 'api.js',
            start: { line: 30 },
            end: { line: 30 },
            extra: { severity: 'WARNING', message: 'Potential issue' }
          }
        ]
      };

      const results = await normalizeResults(semgrepOutput);

      expect(results).toHaveLength(3);
      expect(results.map(r => r.severity)).toEqual(['CRITICAL', 'MEDIUM', 'HIGH']);
    });
  });
});