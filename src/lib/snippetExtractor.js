// lib/snippetExtractor.js
const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');

class SnippetExtractor {
  constructor() {
    // Cache to avoid re-reading files
    this.fileCache = new Map();
    this.maxCacheSize = 100;
    this.snippetCache = new Map();
  }

  /**
   * Extract code snippet with context
   */
  async extractSnippet(filePath, startLine, endLine, options = {}) {
    const {
      contextLines = 3,
      maxLength = 500,
      highlightLines = true,
      includeLineNumbers = true
    } = options;

    // Create cache key
    const cacheKey = `${filePath}:${startLine}:${endLine}:${contextLines}`;
    
    // Check snippet cache first
    if (this.snippetCache.has(cacheKey)) {
      return this.snippetCache.get(cacheKey);
    }

    try {
      // Get file content (with caching)
      const content = await this.getFileContent(filePath);
      if (!content) return null;

      const lines = content.split('\n');
      
      // Calculate boundaries
      const snippetStart = Math.max(0, startLine - contextLines - 1);
      const snippetEnd = Math.min(lines.length, (endLine || startLine) + contextLines);
      
      // Extract lines
      const snippetLines = lines.slice(snippetStart, snippetEnd);
      
      // Format snippet
      let formattedSnippet;
      if (includeLineNumbers) {
        formattedSnippet = snippetLines.map((line, idx) => {
          const lineNum = snippetStart + idx + 1;
          const isTarget = lineNum >= startLine && lineNum <= (endLine || startLine);
          
          if (highlightLines && isTarget) {
            // Highlight the vulnerable line(s)
            return `→ ${lineNum.toString().padStart(4)}: ${line}`;
          } else {
            return `  ${lineNum.toString().padStart(4)}: ${line}`;
          }
        }).join('\n');
      } else {
        formattedSnippet = snippetLines.join('\n');
      }
      
      // Truncate if too long
      if (formattedSnippet.length > maxLength) {
        formattedSnippet = formattedSnippet.substring(0, maxLength) + '\n  ... (truncated)';
      }
      
      // Cache the result
      this.cacheSnippet(cacheKey, formattedSnippet);
      
      return formattedSnippet;
    } catch (error) {
      console.error(`Failed to extract snippet from ${filePath}:`, error.message);
      return null;
    }
  }

  /**
   * Get file content with caching
   */
  async getFileContent(filePath) {
    // Check cache
    if (this.fileCache.has(filePath)) {
      return this.fileCache.get(filePath).content;
    }

    try {
      const content = await fs.readFile(filePath, 'utf8');
      
      // Cache management
      if (this.fileCache.size >= this.maxCacheSize) {
        // Remove oldest entry
        const firstKey = this.fileCache.keys().next().value;
        this.fileCache.delete(firstKey);
      }
      
      this.fileCache.set(filePath, {
        content,
        timestamp: Date.now()
      });
      
      return content;
    } catch (error) {
      return null;
    }
  }

  /**
   * Cache snippet with size management
   */
  cacheSnippet(key, snippet) {
    if (this.snippetCache.size >= this.maxCacheSize * 2) {
      // Clear half of cache when it gets too large
      const entriesToDelete = Math.floor(this.snippetCache.size / 2);
      const keys = Array.from(this.snippetCache.keys());
      for (let i = 0; i < entriesToDelete; i++) {
        this.snippetCache.delete(keys[i]);
      }
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