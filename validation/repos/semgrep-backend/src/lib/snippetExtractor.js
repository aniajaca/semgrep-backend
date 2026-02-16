// src/lib/snippetExtractor.js
const fs = require('fs').promises;

/**
 * SnippetExtractor - Extracts code snippets with context for vulnerability reporting
 * Features:
 * - File content caching with LRU eviction
 * - Snippet caching for repeated extractions
 * - Configurable context lines
 * - Line number annotations
 * - Target line highlighting
 * - Length truncation for readability
 */
class SnippetExtractor {
  constructor(config = {}) {
    this.fileCache = new Map();
    this.snippetCache = new Map();
    this.fileCacheMaxSize = config.fileCacheMaxSize || 100;
    this.snippetCacheMaxSize = config.snippetCacheMaxSize || 200;
    this.config = config;
  }

  /**
   * Extract a code snippet with context
   * @param {string} filePath - Path to the source file
   * @param {number} startLine - Start line number (1-indexed)
   * @param {number|null} endLine - End line number (1-indexed)
   * @param {object} options - Extraction options
   * @returns {Promise<string|null>} The extracted snippet or null if error
   */
  async extractSnippet(filePath, startLine, endLine = null, options = {}) {
    const {
      contextLines = 3,
      includeLineNumbers = true,
      highlightLines = true,
      maxLength = 1000
    } = options;

    // Handle null endLine
    if (endLine === null) {
      endLine = startLine;
    }

    // Create cache key
    const cacheKey = `${filePath}:${startLine}:${endLine}:${contextLines}`;
    if (this.snippetCache.has(cacheKey)) {
      return this.snippetCache.get(cacheKey);
    }

    // Get file content
    const fileContent = await this.getFileContent(filePath);
    if (!fileContent) {
      return null;
    }

    // Split into lines
    const lines = fileContent.split('\n');

    // Handle invalid line numbers
    const actualStartLine = Math.max(1, Math.min(startLine, lines.length));
    const actualEndLine = Math.max(1, Math.min(endLine || startLine, lines.length));

    // Calculate context boundaries
    const contextStart = Math.max(0, actualStartLine - 1 - contextLines);
    const contextEnd = Math.min(lines.length, actualEndLine + contextLines);

    // Extract lines with annotations
    const snippetLines = [];
    for (let i = contextStart; i < contextEnd; i++) {
      const lineNum = i + 1;
      const line = lines[i];
      
      // Determine if this is a target line
      const isTarget = lineNum >= actualStartLine && lineNum <= actualEndLine;
      
      // Build line string
      let lineStr = '';
      
      if (includeLineNumbers) {
        lineStr += `${lineNum.toString().padStart(4, ' ')}: `;
      }
      
      if (highlightLines && isTarget) {
        lineStr += '→ ';
      } else if (includeLineNumbers) {
        lineStr += '  ';
      }
      
      lineStr += line;
      snippetLines.push(lineStr);
    }

    let snippet = snippetLines.join('\n');

    // Truncate if too long
    if (snippet.length > maxLength) {
      snippet = snippet.substring(0, maxLength);
      snippet += '\n... (truncated)';
    }

    // Cache the result
    this.cacheSnippet(cacheKey, snippet);

    return snippet;
  }

  /**
   * Read and cache file content
   * @param {string} filePath - Path to the file
   * @returns {Promise<string|null>} File content or null if error
   */
  async getFileContent(filePath) {
    // Check cache
    if (this.fileCache.has(filePath)) {
      return this.fileCache.get(filePath);
    }

    try {
      // Read file
      const content = await fs.readFile(filePath, 'utf8');
      
      // Cache it
      this.cacheFile(filePath, content);
      
      return content;
    } catch (error) {
      // File doesn't exist or can't be read
      return null;
    }
  }

  /**
   * Cache file content with LRU eviction
   * @param {string} filePath - File path
   * @param {string} content - File content
   */
  cacheFile(filePath, content) {
    // Evict oldest if at capacity
    if (this.fileCache.size >= this.fileCacheMaxSize) {
      const firstKey = this.fileCache.keys().next().value;
      this.fileCache.delete(firstKey);
    }
    
    this.fileCache.set(filePath, content);
  }

  /**
   * Cache snippet with LRU eviction
   * @param {string} key - Cache key
   * @param {string} snippet - Snippet content
   */
  cacheSnippet(key, snippet) {
    // Evict oldest if at capacity
    if (this.snippetCache.size >= this.snippetCacheMaxSize) {
      const firstKey = this.snippetCache.keys().next().value;
      this.snippetCache.delete(firstKey);
    }
    
    this.snippetCache.set(key, snippet);
  }

  /**
   * Clear all caches
   */
  clearCache() {
    this.fileCache.clear();
    this.snippetCache.clear();
  }
}

module.exports = SnippetExtractor;