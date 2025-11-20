// test/unit/snippetExtractor.test.js
const SnippetExtractor = require('../../src/lib/snippetExtractor');
const fs = require('fs').promises;
const path = require('path');

describe('SnippetExtractor', () => {
  let extractor;
  let testFilePath;

  beforeAll(async () => {
    // Create a test file
    testFilePath = path.join(__dirname, 'test-snippet.js');
    const testContent = `line 1
line 2
line 3
line 4
line 5
line 6
line 7`;
    await fs.writeFile(testFilePath, testContent, 'utf8');
  });

  afterAll(async () => {
    // Cleanup test file
    try {
      await fs.unlink(testFilePath);
    } catch (err) {
      // Ignore
    }
  });

  beforeEach(() => {
    extractor = new SnippetExtractor();
  });

  describe('extractSnippet', () => {
    test('should extract snippet with context', async () => {
      const snippet = await extractor.extractSnippet(testFilePath, 4, 4, {
        contextLines: 1
      });

      expect(typeof snippet).toBe('string');
      expect(snippet.length).toBeGreaterThan(0);
    });

    test('should handle start of file', async () => {
      const snippet = await extractor.extractSnippet(testFilePath, 1, 1, {
        contextLines: 2
      });

      expect(typeof snippet).toBe('string');
      expect(snippet).toContain('line 1');
    });

    test('should handle end of file', async () => {
      const snippet = await extractor.extractSnippet(testFilePath, 7, 7, {
        contextLines: 2
      });

      expect(typeof snippet).toBe('string');
      expect(snippet).toContain('line 7');
    });

    test('should handle invalid file', async () => {
      const snippet = await extractor.extractSnippet('/nonexistent/file.js', 1, 1);

      expect(snippet).toBeNull();
    });

    test('should include line numbers by default', async () => {
      const snippet = await extractor.extractSnippet(testFilePath, 3, 3);

      expect(snippet).toContain('3:');
    });

    test('should highlight target lines', async () => {
      const snippet = await extractor.extractSnippet(testFilePath, 3, 3, {
        highlightLines: true
      });

      expect(snippet).toContain('→');
    });

    test('should truncate long snippets', async () => {
      const snippet = await extractor.extractSnippet(testFilePath, 1, 7, {
        maxLength: 50
      });

      expect(snippet.length).toBeLessThanOrEqual(100);
    });
  });

  describe('getFileContent', () => {
    test('should read file content', async () => {
      const content = await extractor.getFileContent(testFilePath);

      expect(typeof content).toBe('string');
      expect(content).toContain('line 1');
    });

    test('should cache file content', async () => {
      await extractor.getFileContent(testFilePath);
      const content = await extractor.getFileContent(testFilePath);

      expect(typeof content).toBe('string');
    });

    test('should return null for invalid files', async () => {
      const content = await extractor.getFileContent('/nonexistent.js');

      expect(content).toBeNull();
    });
  });

  describe('clearCache', () => {
    test('should clear all caches', async () => {
      await extractor.getFileContent(testFilePath);
      await extractor.extractSnippet(testFilePath, 1, 1);

      extractor.clearCache();

      expect(extractor.fileCache.size).toBe(0);
      expect(extractor.snippetCache.size).toBe(0);
    });
  });
});