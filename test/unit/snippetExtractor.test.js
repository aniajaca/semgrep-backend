// test/unit/snippetExtractor.test.js
const SnippetExtractor = require('../../src/lib/snippetExtractor');
const fs = require('fs').promises;
const path = require('path');

describe('SnippetExtractor', () => {
  let extractor;
  let tempDir;
  let testFile;

  beforeEach(async () => {
    extractor = new SnippetExtractor();
    tempDir = path.join('/tmp', `test-snippets-${Date.now()}`);
    await fs.mkdir(tempDir, { recursive: true });
    
    // Create test file
    testFile = path.join(tempDir, 'test.js');
    const content = [
      'function example() {',
      '  const x = 1;',
      '  const y = 2;',
      '  // Vulnerable line',
      '  eval(userInput);',
      '  const z = 3;',
      '  return x + y + z;',
      '}'
    ].join('\n');
    
    await fs.writeFile(testFile, content);
  });

  afterEach(async () => {
    try {
      await fs.rm(tempDir, { recursive: true, force: true });
    } catch (e) {
      // Ignore cleanup errors
    }
  });

  describe('extractSnippet', () => {
    it('should extract snippet with context', async () => {
      const snippet = await extractor.extractSnippet(testFile, 5, 5);
      
      expect(snippet).toBeDefined();
      expect(typeof snippet).toBe('string');
      expect(snippet).toContain('eval');
    });

    it('should include line numbers by default', async () => {
      const snippet = await extractor.extractSnippet(testFile, 5, 5);
      
      expect(snippet).toMatch(/\d+:/); // Should have line numbers
    });

    it('should highlight target lines', async () => {
      const snippet = await extractor.extractSnippet(testFile, 5, 5);
      
      expect(snippet).toContain('→'); // Highlight marker
    });

    it('should include context lines', async () => {
      const snippet = await extractor.extractSnippet(testFile, 5, 5, { contextLines: 2 });
      
      expect(snippet).toContain('const y');
      expect(snippet).toContain('eval');
      expect(snippet).toContain('const z');
    });

    it('should handle custom context lines', async () => {
      const snippet = await extractor.extractSnippet(testFile, 5, 5, { contextLines: 1 });
      
      expect(snippet).toBeDefined();
      expect(snippet.split('\n').length).toBeLessThan(10);
    });

    it('should handle line ranges', async () => {
      const snippet = await extractor.extractSnippet(testFile, 3, 5);
      
      expect(snippet).toContain('const y');
      expect(snippet).toContain('eval');
    });

    it('should truncate long snippets', async () => {
      const snippet = await extractor.extractSnippet(testFile, 5, 5, { maxLength: 50 });
      
      expect(snippet.length).toBeLessThanOrEqual(100); // Some buffer for truncation message
    });

    it('should handle missing files gracefully', async () => {
      const snippet = await extractor.extractSnippet('/non/existent/file.js', 5, 5);
      
      expect(snippet).toBeNull();
    });

    it('should cache file content', async () => {
      await extractor.extractSnippet(testFile, 5, 5);
      const cached = extractor.fileCache.has(testFile);
      
      expect(cached).toBe(true);
    });

    it('should use snippet cache', async () => {
      const snippet1 = await extractor.extractSnippet(testFile, 5, 5);
      const snippet2 = await extractor.extractSnippet(testFile, 5, 5);
      
      expect(snippet1).toBe(snippet2);
    });

    it('should handle files without line numbers', async () => {
      const snippet = await extractor.extractSnippet(testFile, 5, 5, { includeLineNumbers: false });
      
      expect(snippet).toBeDefined();
      expect(snippet).not.toMatch(/\d+:/);
    });

    it('should handle files without highlighting', async () => {
      const snippet = await extractor.extractSnippet(testFile, 5, 5, { highlightLines: false });
      
      expect(snippet).toBeDefined();
      expect(snippet).not.toContain('→');
    });

    it('should handle start of file', async () => {
      const snippet = await extractor.extractSnippet(testFile, 1, 1);
      
      expect(snippet).toBeDefined();
      expect(snippet).toContain('function example');
    });

    it('should handle end of file', async () => {
      const snippet = await extractor.extractSnippet(testFile, 8, 8);
      
      expect(snippet).toBeDefined();
      expect(snippet).toContain('}');
    });

    it('should handle single line', async () => {
      const snippet = await extractor.extractSnippet(testFile, 5, null);
      
      expect(snippet).toBeDefined();
    });
  });

  describe('getFileContent', () => {
    it('should read file content', async () => {
      const content = await extractor.getFileContent(testFile);
      
      expect(content).toBeDefined();
      expect(content).toContain('eval');
    });

    it('should cache file content', async () => {
      await extractor.getFileContent(testFile);
      
      expect(extractor.fileCache.has(testFile)).toBe(true);
    });

    it('should return cached content', async () => {
      const content1 = await extractor.getFileContent(testFile);
      const content2 = await extractor.getFileContent(testFile);
      
      expect(content1).toBe(content2);
    });

    it('should handle missing files', async () => {
      const content = await extractor.getFileContent('/non/existent/file.js');
      
      expect(content).toBeNull();
    });

    it('should respect cache size limit', async () => {
      // Create many files to exceed cache
      for (let i = 0; i < 150; i++) {
        const file = path.join(tempDir, `file${i}.js`);
        await fs.writeFile(file, `// File ${i}`);
        await extractor.getFileContent(file);
      }
      
      expect(extractor.fileCache.size).toBeLessThanOrEqual(100);
    });
  });

  describe('cacheSnippet', () => {
    it('should cache snippet', () => {
      extractor.cacheSnippet('test:1:1:3', 'snippet content');
      
      expect(extractor.snippetCache.has('test:1:1:3')).toBe(true);
    });

    it('should manage cache size', () => {
      // Fill cache beyond limit
      for (let i = 0; i < 250; i++) {
        extractor.cacheSnippet(`key${i}`, `snippet ${i}`);
      }
      
      expect(extractor.snippetCache.size).toBeLessThan(250);
    });
  });

  describe('clearCache', () => {
    it('should clear file cache', async () => {
      await extractor.getFileContent(testFile);
      extractor.clearCache();
      
      expect(extractor.fileCache.size).toBe(0);
    });

    it('should clear snippet cache', async () => {
      await extractor.extractSnippet(testFile, 5, 5);
      extractor.clearCache();
      
      expect(extractor.snippetCache.size).toBe(0);
    });

    it('should clear both caches', async () => {
      await extractor.extractSnippet(testFile, 5, 5);
      extractor.clearCache();
      
      expect(extractor.fileCache.size).toBe(0);
      expect(extractor.snippetCache.size).toBe(0);
    });
  });

  describe('Edge Cases', () => {
    it('should handle very large files', async () => {
      const largeFile = path.join(tempDir, 'large.js');
      const lines = Array(10000).fill('const x = 1;').join('\n');
      await fs.writeFile(largeFile, lines);
      
      const snippet = await extractor.extractSnippet(largeFile, 5000, 5000);
      expect(snippet).toBeDefined();
    });

    it('should handle files with special characters', async () => {
      const specialFile = path.join(tempDir, 'special.js');
      await fs.writeFile(specialFile, 'const x = "hello 世界 🎉";');
      
      const snippet = await extractor.extractSnippet(specialFile, 1, 1);
      expect(snippet).toBeDefined();
    });

    it('should handle empty files', async () => {
      const emptyFile = path.join(tempDir, 'empty.js');
      await fs.writeFile(emptyFile, '');
      
      const snippet = await extractor.extractSnippet(emptyFile, 1, 1);
      expect(snippet).toBeDefined();
    });

    it('should handle line numbers beyond file length', async () => {
      const snippet = await extractor.extractSnippet(testFile, 1000, 1000);
      
      expect(snippet).toBeDefined();
    });

    it('should handle negative line numbers', async () => {
      const snippet = await extractor.extractSnippet(testFile, -1, -1);
      
      expect(snippet).toBeDefined();
    });

    it('should handle zero context lines', async () => {
      const snippet = await extractor.extractSnippet(testFile, 5, 5, { contextLines: 0 });
      
      expect(snippet).toBeDefined();
    });
  });
});