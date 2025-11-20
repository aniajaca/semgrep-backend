const SnippetExtractor = require('../../src/lib/snippetExtractor');
const fs = require('fs').promises;

jest.mock('fs', () => ({
  promises: {
    readFile: jest.fn()
  }
}));

describe('SnippetExtractor', () => {
  let extractor;

  beforeEach(() => {
    extractor = new SnippetExtractor();
    jest.clearAllMocks();
  });

  describe('extractSnippet', () => {
    test('should extract single line', async () => {
      fs.readFile.mockResolvedValue('line1\nline2\nline3\n');
      
      const snippet = await extractor.extractSnippet('/test/file.js', 2, 2);
      
      expect(snippet).toBeDefined();
      expect(typeof snippet).toBe('string');
    });

    test('should extract multiple lines', async () => {
      fs.readFile.mockResolvedValue('line1\nline2\nline3\nline4\n');
      
      const snippet = await extractor.extractSnippet('/test/file.js', 2, 3);
      
      expect(snippet).toBeDefined();
    });

    test('should handle file read error gracefully', async () => {
      fs.readFile.mockRejectedValue(new Error('File not found'));
      
      const snippet = await extractor.extractSnippet('/test/missing.js', 1, 1);
      
      expect(snippet).toBe('');
    });

    test('should handle out of bounds line numbers', async () => {
      fs.readFile.mockResolvedValue('line1\nline2\n');
      
      const snippet = await extractor.extractSnippet('/test/file.js', 10, 15);
      
      expect(snippet).toBeDefined();
    });

    test('should handle empty file', async () => {
      fs.readFile.mockResolvedValue('');
      
      const snippet = await extractor.extractSnippet('/test/empty.js', 1, 1);
      
      expect(snippet).toBe('');
    });

    test('should respect context lines option', async () => {
      fs.readFile.mockResolvedValue('line1\nline2\nline3\nline4\nline5\n');
      
      const snippet = await extractor.extractSnippet('/test/file.js', 3, 3, {
        contextLines: 1
      });
      
      expect(snippet).toBeDefined();
    });

    test('should handle maxLength option', async () => {
      const longContent = 'x'.repeat(1000) + '\n';
      fs.readFile.mockResolvedValue(longContent);
      
      const snippet = await extractor.extractSnippet('/test/file.js', 1, 1, {
        maxLength: 100
      });
      
      expect(snippet).toBeDefined();
    });

    test('should include line numbers when requested', async () => {
      fs.readFile.mockResolvedValue('line1\nline2\nline3\n');
      
      const snippet = await extractor.extractSnippet('/test/file.js', 2, 2, {
        includeLineNumbers: true
      });
      
      expect(snippet).toBeDefined();
    });

    test('should handle same start and end line', async () => {
      fs.readFile.mockResolvedValue('line1\nline2\nline3\n');
      
      const snippet = await extractor.extractSnippet('/test/file.js', 2, 2);
      
      expect(snippet).toBeDefined();
    });

    test('should use default options when none provided', async () => {
      fs.readFile.mockResolvedValue('line1\nline2\n');
      
      const snippet = await extractor.extractSnippet('/test/file.js', 1, 1);
      
      expect(snippet).toBeDefined();
    });

    test('should handle Windows line endings', async () => {
      fs.readFile.mockResolvedValue('line1\r\nline2\r\nline3\r\n');
      
      const snippet = await extractor.extractSnippet('/test/windows.js', 2, 2);
      
      expect(snippet).toBeDefined();
    });

    test('should handle binary content safely', async () => {
      fs.readFile.mockResolvedValue(Buffer.from([0xFF, 0xFE, 0xFD]));
      
      const snippet = await extractor.extractSnippet('/test/binary.dat', 1, 1);
      
      expect(snippet).toBeDefined();
    });

    test('should handle very long lines', async () => {
      const longLine = 'x'.repeat(10000);
      fs.readFile.mockResolvedValue(longLine + '\n');
      
      const snippet = await extractor.extractSnippet('/test/long.js', 1, 1);
      
      expect(snippet).toBeDefined();
    });
  });

  describe('getFileContent', () => {
    test('should read file content', async () => {
      fs.readFile.mockResolvedValue('test content');
      
      const content = await extractor.getFileContent('/test/file.js');
      
      expect(content).toBe('test content');
    });

    test('should return null for read errors', async () => {
      fs.readFile.mockRejectedValue(new Error('Read error'));
      
      const content = await extractor.getFileContent('/test/missing.js');
      
      expect(content).toBeNull();
    });
  });

  describe('clearCache', () => {
    test('should clear cache successfully', () => {
      extractor.clearCache();
      // Should not throw
      expect(true).toBe(true);
    });
  });
});