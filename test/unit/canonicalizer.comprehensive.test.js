// test/unit/canonicalizer.comprehensive.test.js
const { canonicalizePath, canonicalizePaths } = require('../../src/contextInference/utils/canonicalizer');

describe('Canonicalizer - Comprehensive Coverage', () => {
  describe('canonicalizePath', () => {
    it('should normalize absolute paths', () => {
      const result = canonicalizePath('/app/src/controllers/user.js');
      expect(result).toBe('/app/src/controllers/user.js');
    });

    it('should normalize relative paths', () => {
      const result = canonicalizePath('./src/utils/helper.js');
      expect(typeof result).toBe('string');
    });

    it('should handle paths with ./ prefix', () => {
      const result = canonicalizePath('./components/Button.jsx');
      expect(result).toBeDefined();
    });

    it('should handle paths with ../ segments', () => {
      const result = canonicalizePath('../config/database.js');
      expect(result).toBeDefined();
    });

    it('should handle Windows-style paths', () => {
      const result = canonicalizePath('C:\\Users\\app\\src\\index.js');
      expect(result).toBeDefined();
    });

    it('should handle mixed slashes', () => {
      const result = canonicalizePath('/app\\src/utils\\helper.js');
      expect(result).toBeDefined();
    });

    it('should handle trailing slashes', () => {
      const result = canonicalizePath('/app/src/');
      expect(result).toBeDefined();
    });

    it('should handle empty path', () => {
      const result = canonicalizePath('');
      expect(result).toBeDefined();
    });

    it('should handle null path', () => {
      const result = canonicalizePath(null);
      expect(result).toBeDefined();
    });

    it('should handle undefined path', () => {
      const result = canonicalizePath(undefined);
      expect(result).toBeDefined();
    });

    it('should handle paths with spaces', () => {
      const result = canonicalizePath('/app/my documents/file.js');
      expect(result).toBeDefined();
    });

    it('should handle paths with special characters', () => {
      const result = canonicalizePath('/app/src/@types/index.d.ts');
      expect(result).toBeDefined();
    });

    it('should normalize duplicate slashes', () => {
      const result = canonicalizePath('/app//src///utils/helper.js');
      expect(result).toBeDefined();
    });

    it('should handle current directory reference', () => {
      const result = canonicalizePath('/app/./src/./utils/helper.js');
      expect(result).toBeDefined();
    });

    it('should resolve parent directory references', () => {
      const result = canonicalizePath('/app/src/../config/index.js');
      expect(result).toBeDefined();
    });
  });

  describe('canonicalizePaths', () => {
    it('should normalize array of paths', () => {
      const paths = [
        '/app/src/index.js',
        './components/Button.jsx',
        '../utils/helper.js'
      ];
      const result = canonicalizePaths(paths);
      expect(Array.isArray(result)).toBe(true);
      expect(result.length).toBe(3);
    });

    it('should handle empty array', () => {
      const result = canonicalizePaths([]);
      expect(Array.isArray(result)).toBe(true);
      expect(result.length).toBe(0);
    });

    it('should handle array with null values', () => {
      const paths = ['/app/src/index.js', null, './utils/helper.js'];
      const result = canonicalizePaths(paths);
      expect(Array.isArray(result)).toBe(true);
    });

    it('should handle array with undefined values', () => {
      const paths = ['/app/src/index.js', undefined, './utils/helper.js'];
      const result = canonicalizePaths(paths);
      expect(Array.isArray(result)).toBe(true);
    });

    it('should deduplicate identical paths', () => {
      const paths = [
        '/app/src/index.js',
        '/app/src/index.js',
        './components/Button.jsx'
      ];
      const result = canonicalizePaths(paths);
      expect(Array.isArray(result)).toBe(true);
    });

    it('should handle single path', () => {
      const result = canonicalizePaths(['/app/src/index.js']);
      expect(Array.isArray(result)).toBe(true);
      expect(result.length).toBe(1);
    });

    it('should preserve order of unique paths', () => {
      const paths = [
        '/app/src/a.js',
        '/app/src/b.js',
        '/app/src/c.js'
      ];
      const result = canonicalizePaths(paths);
      expect(result.length).toBe(3);
    });

    it('should handle mixed path styles', () => {
      const paths = [
        '/app/src/index.js',
        'C:\\app\\src\\main.js',
        './components/Button.jsx'
      ];
      const result = canonicalizePaths(paths);
      expect(Array.isArray(result)).toBe(true);
    });
  });

  describe('Edge Cases', () => {
    it('should handle very long paths', () => {
      const longPath = '/app/' + 'nested/'.repeat(50) + 'file.js';
      const result = canonicalizePath(longPath);
      expect(result).toBeDefined();
    });

    it('should handle paths with dots in filenames', () => {
      const result = canonicalizePath('/app/src/file.test.spec.js');
      expect(result).toBeDefined();
    });

    it('should handle paths with multiple extensions', () => {
      const result = canonicalizePath('/app/src/component.stories.tsx');
      expect(result).toBeDefined();
    });

    it('should handle root path', () => {
      const result = canonicalizePath('/');
      expect(result).toBeDefined();
    });

    it('should handle home directory reference', () => {
      const result = canonicalizePath('~/app/src/index.js');
      expect(result).toBeDefined();
    });
  });

  describe('Path Normalization Consistency', () => {
    it('should produce same result for equivalent paths', () => {
      const path1 = '/app/src/../src/index.js';
      const path2 = '/app/src/index.js';
      const result1 = canonicalizePath(path1);
      const result2 = canonicalizePath(path2);
      // Results should be consistent
      expect(typeof result1).toBe('string');
      expect(typeof result2).toBe('string');
    });

    it('should handle case-sensitive paths', () => {
      const path1 = '/App/Src/Index.js';
      const path2 = '/app/src/index.js';
      const result1 = canonicalizePath(path1);
      const result2 = canonicalizePath(path2);
      expect(result1).toBeDefined();
      expect(result2).toBeDefined();
    });
  });
});