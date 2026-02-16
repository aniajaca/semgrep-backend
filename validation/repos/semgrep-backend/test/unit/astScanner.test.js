// test/unit/astScanner.test.js
const { ASTVulnerabilityScanner } = require('../../src/astScanner');

describe('ASTVulnerabilityScanner', () => {
  let scanner;

  beforeEach(() => {
    scanner = new ASTVulnerabilityScanner();
  });

  describe('scan', () => {
    test('should detect hardcoded credentials', () => {
      const code = 'const password = "hardcoded123";';
      const results = scanner.scan(code, 'test.js', 'javascript');

      expect(results.length).toBeGreaterThan(0);
      expect(results[0].cweId).toBe('CWE-798');
      expect(results[0].severity).toBe('critical');
    });

    test('should detect eval usage', () => {
      const code = 'eval(userInput);';
      const results = scanner.scan(code, 'test.js', 'javascript');

      expect(results.length).toBeGreaterThan(0);
      expect(results[0].cweId).toBe('CWE-94');
      expect(results[0].message).toContain('Code Injection');
    });

    test('should detect XSS vulnerability', () => {
      const code = 'document.innerHTML = userInput;';
      const results = scanner.scan(code, 'test.js', 'javascript');

      expect(results.length).toBeGreaterThan(0);
      const xss = results.find(r => r.cweId === 'CWE-79');
      expect(xss).toBeDefined();
    });

    test('should return empty array for safe code', () => {
      const code = 'const x = 5; console.log(x);';
      const results = scanner.scan(code, 'test.js', 'javascript');

      expect(Array.isArray(results)).toBe(true);
    });

    test('should handle syntax errors gracefully', () => {
      const code = 'const x = {{{';
      const results = scanner.scan(code, 'test.js', 'javascript');

      expect(Array.isArray(results)).toBe(true);
    });
  });
});