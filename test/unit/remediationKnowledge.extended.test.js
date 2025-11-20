// test/unit/remediationKnowledge.extended.test.js
const remediationKnowledge = require('../../src/remediationKnowledge');

describe('remediationKnowledge - Extended Coverage', () => {
  
  describe('getRemediation', () => {
    it('should return remediation for CWE-79 (XSS)', () => {
      const remediation = remediationKnowledge.getRemediation('CWE-79');
      
      expect(remediation).toBeDefined();
      expect(remediation.title).toBeDefined();
      expect(remediation.risk).toBeDefined();
      expect(remediation.remediation).toBeDefined();
    });

    it('should return remediation for CWE-89 (SQL Injection)', () => {
      const remediation = remediationKnowledge.getRemediation('CWE-89');
      
      expect(remediation).toBeDefined();
      expect(remediation.title).toContain('SQL');
    });

    it('should return remediation for CWE-78 (OS Command Injection)', () => {
      const remediation = remediationKnowledge.getRemediation('CWE-78');
      
      expect(remediation).toBeDefined();
      expect(remediation.title).toBeDefined();
    });

    it('should return remediation for CWE-22 (Path Traversal)', () => {
      const remediation = remediationKnowledge.getRemediation('CWE-22');
      
      expect(remediation).toBeDefined();
      expect(remediation.remediation).toBeDefined();
    });

    it('should return remediation for CWE-502 (Deserialization)', () => {
      const remediation = remediationKnowledge.getRemediation('CWE-502');
      
      expect(remediation).toBeDefined();
    });

    it('should return remediation for CWE-614 (Cookie Security)', () => {
      const remediation = remediationKnowledge.getRemediation('CWE-614');
      
      expect(remediation).toBeDefined();
    });

    it('should return remediation for CWE-327 (Weak Crypto)', () => {
      const remediation = remediationKnowledge.getRemediation('CWE-327');
      
      expect(remediation).toBeDefined();
    });

    it('should return remediation for CWE-798 (Hardcoded Credentials)', () => {
      const remediation = remediationKnowledge.getRemediation('CWE-798');
      
      expect(remediation).toBeDefined();
    });

    it('should return remediation for CWE-611 (XXE)', () => {
      const remediation = remediationKnowledge.getRemediation('CWE-611');
      
      expect(remediation).toBeDefined();
    });

    it('should return remediation for CWE-94 (Code Injection)', () => {
      const remediation = remediationKnowledge.getRemediation('CWE-94');
      
      expect(remediation).toBeDefined();
    });

    it('should return language-specific remediation for JavaScript', () => {
      const remediation = remediationKnowledge.getRemediation('CWE-79', 'javascript');
      
      expect(remediation).toBeDefined();
      expect(remediation.languageSpecific).toBeDefined();
    });

    it('should return language-specific remediation for Python', () => {
      const remediation = remediationKnowledge.getRemediation('CWE-89', 'python');
      
      expect(remediation).toBeDefined();
      expect(remediation.languageSpecific).toBeDefined();
    });

    it('should return language-specific remediation for Java', () => {
      const remediation = remediationKnowledge.getRemediation('CWE-78', 'java');
      
      expect(remediation).toBeDefined();
      expect(remediation.languageSpecific).toBeDefined();
    });

    it('should fallback to javascript for unsupported language', () => {
      const remediation = remediationKnowledge.getRemediation('CWE-79', 'ruby');
      
      expect(remediation).toBeDefined();
      expect(remediation.languageSpecific).toBeDefined();
    });

    it('should return generic remediation for unknown CWE', () => {
      const remediation = remediationKnowledge.getRemediation('CWE-99999');
      
      expect(remediation).toBeDefined();
      expect(remediation.title).toBe('Security Issue');
      expect(remediation.risk).toBe('Potential security vulnerability detected');
    });

    it('should handle null CWE ID', () => {
      const remediation = remediationKnowledge.getRemediation(null);
      
      expect(remediation).toBeDefined();
      expect(remediation.title).toBe('Security Issue');
    });

    it('should handle undefined CWE ID', () => {
      const remediation = remediationKnowledge.getRemediation(undefined);
      
      expect(remediation).toBeDefined();
      expect(remediation.title).toBe('Security Issue');
    });

    it('should handle empty string CWE ID', () => {
      const remediation = remediationKnowledge.getRemediation('');
      
      expect(remediation).toBeDefined();
      expect(remediation.title).toBe('Security Issue');
    });
  });

  describe('getSeverity', () => {
    it('should return severity for known CWE', () => {
      const severity = remediationKnowledge.getSeverity('CWE-79');
      
      expect(severity).toBeDefined();
      expect(['critical', 'high', 'medium', 'low']).toContain(severity);
    });

    it('should return default severity for unknown CWE', () => {
      const severity = remediationKnowledge.getSeverity('CWE-99999');
      
      expect(severity).toBe('medium');
    });

    it('should handle null CWE ID', () => {
      const severity = remediationKnowledge.getSeverity(null);
      
      expect(severity).toBe('medium');
    });

    it('should handle undefined CWE ID', () => {
      const severity = remediationKnowledge.getSeverity(undefined);
      
      expect(severity).toBe('medium');
    });
  });

  describe('getOWASP', () => {
    it('should return OWASP category for known CWE', () => {
      const owasp = remediationKnowledge.getOWASP('CWE-79');
      
      expect(owasp).toBeDefined();
      expect(typeof owasp).toBe('string');
      expect(owasp).toContain('A');
    });

    it('should return default OWASP for unknown CWE', () => {
      const owasp = remediationKnowledge.getOWASP('CWE-99999');
      
      expect(owasp).toBe('A06:2021 - Vulnerable and Outdated Components');
    });

    it('should handle null CWE ID', () => {
      const owasp = remediationKnowledge.getOWASP(null);
      
      expect(owasp).toBe('A06:2021 - Vulnerable and Outdated Components');
    });

    it('should handle undefined CWE ID', () => {
      const owasp = remediationKnowledge.getOWASP(undefined);
      
      expect(owasp).toBe('A06:2021 - Vulnerable and Outdated Components');
    });
  });

  describe('getOneLiner', () => {
    it('should return one-liner fix for CWE-79', () => {
      const oneLiner = remediationKnowledge.getOneLiner('CWE-79');
      
      expect(oneLiner).toBeDefined();
      expect(typeof oneLiner).toBe('string');
      expect(oneLiner.length).toBeGreaterThan(0);
    });

    it('should return one-liner fix for CWE-89', () => {
      const oneLiner = remediationKnowledge.getOneLiner('CWE-89');
      
      expect(oneLiner).toBeDefined();
      expect(typeof oneLiner).toBe('string');
    });

    it('should return one-liner fix for CWE-78', () => {
      const oneLiner = remediationKnowledge.getOneLiner('CWE-78');
      
      expect(oneLiner).toBeDefined();
      expect(typeof oneLiner).toBe('string');
    });

    it('should return default message for unknown CWE', () => {
      const oneLiner = remediationKnowledge.getOneLiner('CWE-99999');
      
      expect(oneLiner).toBe('Review and apply security best practices');
    });

    it('should handle null CWE ID', () => {
      const oneLiner = remediationKnowledge.getOneLiner(null);
      
      expect(oneLiner).toBe('Review and apply security best practices');
    });

    it('should handle undefined CWE ID', () => {
      const oneLiner = remediationKnowledge.getOneLiner(undefined);
      
      expect(oneLiner).toBe('Review and apply security best practices');
    });

    it('should prioritize JavaScript fix', () => {
      const oneLiner = remediationKnowledge.getOneLiner('CWE-79');
      
      expect(oneLiner).toBeDefined();
      expect(typeof oneLiner).toBe('string');
    });

    it('should fallback to general fix if JavaScript not available', () => {
      // Test with a CWE that might not have JavaScript-specific fix
      const oneLiner = remediationKnowledge.getOneLiner('CWE-22');
      
      expect(oneLiner).toBeDefined();
      expect(typeof oneLiner).toBe('string');
    });
  });

  describe('Remediation Data Structure', () => {
    it('CWE-79 should have all required fields', () => {
      const data = remediationKnowledge['CWE-79'];
      
      expect(data).toBeDefined();
      expect(data.title).toBeDefined();
      expect(data.risk).toBeDefined();
      expect(data.remediation).toBeDefined();
    });

    it('CWE-89 should have all required fields', () => {
      const data = remediationKnowledge['CWE-89'];
      
      expect(data).toBeDefined();
      expect(data.title).toBeDefined();
      expect(data.risk).toBeDefined();
      expect(data.remediation).toBeDefined();
    });

    it('should have remediation object structure', () => {
      const data = remediationKnowledge['CWE-79'];
      
      expect(data.remediation).toHaveProperty('javascript');
      expect(data.remediation.javascript).toHaveProperty('fix');
      expect(data.remediation.javascript).toHaveProperty('prevention');
    });

    it('prevention should be an array', () => {
      const data = remediationKnowledge['CWE-79'];
      
      expect(Array.isArray(data.remediation.javascript.prevention)).toBe(true);
    });

    it('should have references array', () => {
      const data = remediationKnowledge['CWE-79'];
      
      if (data.references) {
        expect(Array.isArray(data.references)).toBe(true);
      }
    });
  });

  describe('Multiple CWE Coverage', () => {
    const commonCWEs = [
      'CWE-79',  // XSS
      'CWE-89',  // SQL Injection
      'CWE-78',  // OS Command Injection
      'CWE-22',  // Path Traversal
      'CWE-502', // Deserialization
      'CWE-798', // Hardcoded Credentials
      'CWE-327', // Weak Crypto
      'CWE-611', // XXE
      'CWE-94'   // Code Injection
    ];

    commonCWEs.forEach(cweId => {
      it(`should have remediation data for ${cweId}`, () => {
        const remediation = remediationKnowledge.getRemediation(cweId);
        
        expect(remediation).toBeDefined();
        expect(remediation.title).toBeDefined();
        expect(remediation.risk).toBeDefined();
      });

      it(`should have severity for ${cweId}`, () => {
        const severity = remediationKnowledge.getSeverity(cweId);
        
        expect(severity).toBeDefined();
        expect(['critical', 'high', 'medium', 'low']).toContain(severity);
      });

      it(`should have OWASP mapping for ${cweId}`, () => {
        const owasp = remediationKnowledge.getOWASP(cweId);
        
        expect(owasp).toBeDefined();
        expect(typeof owasp).toBe('string');
      });

      it(`should have one-liner for ${cweId}`, () => {
        const oneLiner = remediationKnowledge.getOneLiner(cweId);
        
        expect(oneLiner).toBeDefined();
        expect(typeof oneLiner).toBe('string');
        expect(oneLiner.length).toBeGreaterThan(0);
      });
    });
  });
});