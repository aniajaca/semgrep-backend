// reachabilityAnalyzer.js - Efficient project-wide reachability analysis
const fs = require('fs').promises;
const path = require('path');

class ReachabilityAnalyzer {
  constructor() {
    // Framework-specific entrypoint patterns
    this.entrypointPatterns = [
      /server\.js$/i,
      /app\.js$/i,
      /\/routes\//i,
      /\/controllers\//i,
      /\/api\//i,
      /\/handlers\//i
    ];
    
    // Import/require patterns
    this.importPatterns = [
      /require\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
      /import\s+.*from\s+['"]([^'"]+)['"]/g,
      /import\s*\(\s*['"]([^'"]+)['"]\s*\)/g
    ];
  }
  
  /**
   * Analyze entire project - CALL THIS ONCE PER SCAN
   * Returns: { reachableSet, entrypointsSet, totalFiles, ... }
   */
  async analyzeProject(projectPath) {
    const graph = new Map(); // file -> [dependencies]
    const entrypoints = new Set();
    
    // Find all JS files
    const files = await this.findJavaScriptFiles(projectPath);
    
    // Build dependency graph
    for (const file of files) {
      const relativePath = path.relative(projectPath, file);
      
      // Check if this is an entrypoint
      if (this.isEntrypoint(relativePath)) {
        entrypoints.add(file);
      }
      
      // Parse imports
      try {
        const content = await fs.readFile(file, 'utf-8');
        const deps = this.extractDependencies(content, file, projectPath);
        graph.set(file, deps);
      } catch (err) {
        graph.set(file, []);
      }
    }
    
    // Compute reachability via BFS
    const reachableSet = this.computeReachability(graph, entrypoints);
    
    return {
      reachableSet,         // Set of reachable file paths
      entrypointsSet: entrypoints,
      totalFiles: graph.size,
      reachableCount: reachableSet.size,
      entrypointCount: entrypoints.size
    };
  }
  
  /**
   * Check if file is an entrypoint
   */
  isEntrypoint(filepath) {
    const lower = filepath.toLowerCase();
    return this.entrypointPatterns.some(pattern => pattern.test(lower));
  }
  
  /**
   * Extract dependencies from file
   */
  extractDependencies(content, currentFile, projectPath) {
    const deps = new Set();
    
    for (const pattern of this.importPatterns) {
      let match;
      pattern.lastIndex = 0; // Reset regex
      while ((match = pattern.exec(content)) !== null) {
        const importPath = match[1];
        
        // Only track relative imports (skip node_modules)
        if (importPath.startsWith('.')) {
          const resolved = this.resolveImport(importPath, currentFile, projectPath);
          if (resolved) {
            deps.add(resolved);
          }
        }
      }
    }
    
    return Array.from(deps);
  }
  
  /**
   * Resolve relative import
   */
  resolveImport(importPath, currentFile, projectPath) {
    try {
      const currentDir = path.dirname(currentFile);
      let resolved = path.resolve(currentDir, importPath);
      
      // Try adding .js if not present
      if (!path.extname(resolved)) {
        resolved += '.js';
      }
      
      return resolved;
    } catch (err) {
      return null;
    }
  }
  
  /**
   * Find all JS files in project
   */
  async findJavaScriptFiles(projectPath) {
    const files = [];
    
    async function walk(dir) {
      try {
        const entries = await fs.readdir(dir, { withFileTypes: true });
        
        for (const entry of entries) {
          const fullPath = path.join(dir, entry.name);
          
          // Skip excluded directories
          if (entry.isDirectory()) {
            if (!['node_modules', '.git', 'dist', 'build', 'coverage'].includes(entry.name)) {
              await walk(fullPath);
            }
          } else if (entry.isFile() && /\.(js|jsx)$/i.test(entry.name)) {
            files.push(fullPath);
          }
        }
      } catch (err) {
        // Skip unreadable directories
      }
    }
    
    await walk(projectPath);
    return files;
  }
  
  /**
   * BFS to find all reachable files
   */
  computeReachability(graph, entrypoints) {
    const reachable = new Set();
    const queue = [...entrypoints];
    
    while (queue.length > 0) {
      const current = queue.shift();
      
      if (reachable.has(current)) {
        continue;
      }
      
      reachable.add(current);
      
      // Add dependencies to queue
      const deps = graph.get(current) || [];
      for (const dep of deps) {
        if (!reachable.has(dep)) {
          queue.push(dep);
        }
      }
    }
    
    return reachable;
  }
}

module.exports = ReachabilityAnalyzer;
