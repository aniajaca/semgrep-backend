// semgrepAdapter.js - Production-ready Semgrep integration
const { spawn } = require('child_process');
const fs = require('fs').promises;
const path = require('path');
const { exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);
const SnippetExtractor = require('./lib/snippetExtractor');
const snippetExtractor = new SnippetExtractor();

/**
 * Execute Semgrep with real security rules
 * @param {string} targetPath - Path to scan
 * @param {object} options - Scanning options
 * @returns {Promise<Array>} Normalized findings
 */
async function runSemgrep(targetPath, options = {}) {
  // Validate target path exists
  try {
    await fs.access(targetPath);
  } catch (error) {
    throw new Error(`Target path does not exist: ${targetPath}`);
  }

  return new Promise((resolve, reject) => {
    const semgrepArgs = [];
    
    // Use production rules based on configuration
    if (options.useCustomRules) {
      semgrepArgs.push('--config', options.rulesPath || './rules');
    } else if (options.rulesets && options.rulesets.length > 0) {
      options.rulesets.forEach(ruleset => {
        semgrepArgs.push('--config', ruleset);
      });
    } else {
      semgrepArgs.push('--config', 'auto');
      
      if (options.languages) {
        if (options.languages.includes('javascript')) {
          semgrepArgs.push('--config', 'p/javascript');
        }
        if (options.languages.includes('python')) {
          semgrepArgs.push('--config', 'p/python');
        }
        if (options.languages.includes('java')) {
          semgrepArgs.push('--config', 'p/java');
        }
      }
    }
    
    // Core arguments
    semgrepArgs.push(
      '--json',
      '--verbose',
      '--no-git-ignore',
      '--metrics', 'on',
      '--no-rewrite-rule-ids',
      '--max-lines-per-finding', '10'  // Add this for better snippets
    );

    // Add timeout
    semgrepArgs.push('--timeout', options.timeout?.toString() || '30');
    
    // Add max target bytes
    semgrepArgs.push('--max-target-bytes', options.maxBytes || '1000000');
    
    // Language filtering
    if (options.languages && options.languages.length > 0) {
      const extensions = {
        javascript: ['*.js', '*.jsx', '*.ts', '*.tsx', '*.mjs'],
        python: ['*.py', '*.pyi'],
        java: ['*.java'],
        go: ['*.go'],
        ruby: ['*.rb'],
        php: ['*.php'],
        csharp: ['*.cs'],
        kotlin: ['*.kt'],
        swift: ['*.swift'],
        rust: ['*.rs']
      };
      
      options.languages.forEach(lang => {
        if (extensions[lang]) {
          extensions[lang].forEach(ext => {
            semgrepArgs.push('--include', ext);
          });
        }
      });
    }
    
    // Exclude patterns
    const defaultExcludes = [
      'node_modules', '.git', 'dist', 'build', '__pycache__', 
      '.venv', 'venv', 'target', 'vendor', '.next', '.nuxt',
      'coverage', '*.min.js', '*.bundle.js', 'package-lock.json',
      'yarn.lock', 'poetry.lock', 'Gemfile.lock'
    ];
    
    const excludes = options.exclude || defaultExcludes;
    excludes.forEach(pattern => {
      semgrepArgs.push('--exclude', pattern);
    });
    
    // Add target path
    semgrepArgs.push(targetPath);

    console.log('Running Semgrep with args:', semgrepArgs.join(' '));

    const semgrepCommand = global.SEMGREP_PATH || 'semgrep';
    const [cmd, ...cmdArgs] = semgrepCommand.split(' ');
    const semgrep = spawn(cmd, [...cmdArgs, ...semgrepArgs], {
      maxBuffer: 100 * 1024 * 1024,
      timeout: options.processTimeout || 600000
    });

    let stdout = '';
    let stderr = '';
    let outputSize = 0;
    const maxOutputSize = 100 * 1024 * 1024;

    semgrep.stdout.on('data', (chunk) => {
      outputSize += chunk.length;
      if (outputSize > maxOutputSize) {
        semgrep.kill();
        reject(new Error('Semgrep output too large (>100MB)'));
        return;
      }
      stdout += chunk.toString();
    });

    semgrep.stderr.on('data', (chunk) => {
      stderr += chunk.toString();
    });

    semgrep.on('error', (error) => {
      if (error.code === 'ENOENT') {
        reject(new Error('Semgrep not found. Install with: pip install semgrep'));
      } else {
        reject(error);
      }
    });

    semgrep.on('close', async (code) => {
      // Semgrep returns non-zero when it finds issues, which is expected
      if (code !== 0 && code !== 1 && !stdout) {
        reject(new Error(`Semgrep failed with code ${code}: ${stderr}`));
        return;
      }

      try {
        const results = JSON.parse(stdout || '{}');
        // Pass targetPath to normalizeResults for snippet extraction
        const findings = await normalizeResults(results, targetPath);
        console.log(`Semgrep scan complete: ${findings.length} findings`);
        resolve(findings);
      } catch (parseError) {
        reject(new Error(`Failed to parse Semgrep output: ${parseError.message}`));
      }
    });
  });
}

/**
 * Normalize Semgrep results to our finding format
 * @param {Object} semgrepOutput - Raw Semgrep JSON output
 * @param {string} targetPath - Target path for resolving file paths
 * @returns {Promise<Array>} Normalized findings
 */
async function normalizeResults(semgrepOutput, targetPath = '.') {
  if (!semgrepOutput.results || !Array.isArray(semgrepOutput.results)) {
    return [];
  }

  // Process results with proper snippet extraction
  const enrichedResults = await Promise.all(
    semgrepOutput.results.map(async (result) => {
      // Map Semgrep severity to our format
      const severityMap = {
        'ERROR': 'CRITICAL',
        'WARNING': 'HIGH',
        'INFO': 'MEDIUM',
        'INVENTORY': 'LOW',
        'EXPERIMENTAL': 'LOW'
      };

      const severity = result.extra?.severity 
        ? severityMap[result.extra.severity.toUpperCase()] || 'MEDIUM'
        : 'MEDIUM';

      // Extract metadata
      const metadata = result.extra?.metadata || {};
      const cweList = extractCWE(metadata, result.check_id);
      const owaspList = extractOWASP(metadata, result.check_id);
      
      // Get the snippet
      let snippet = result.extra?.lines || '';
      
      // Check if snippet needs enhancement
      const needsEnhancement = !snippet || 
                               snippet.length < 30 || 
                               snippet.toLowerCase().includes('requires') ||
                               snippet.toLowerCase().includes('login');
      
      if (needsEnhancement) {
        // Build full file path
        const fullPath = path.isAbsolute(result.path) 
          ? result.path 
          : path.join(targetPath, result.path);
        
        // Extract proper snippet
        const extractedSnippet = await snippetExtractor.extractSnippet(
          fullPath,
          result.start?.line || 1,
          result.end?.line || result.start?.line || 1,
          {
            contextLines: 3,
            maxLength: 600,
            highlightLines: true,
            includeLineNumbers: true
          }
        );
        
        if (extractedSnippet) {
          snippet = extractedSnippet;
        }
      }
      
      return {
        engine: 'semgrep',
        ruleId: result.check_id || 'unknown',
        category: metadata.category || 'sast',
        severity: severity,
        message: result.extra?.message || result.message || 'Security issue detected',
        cwe: cweList,
        owasp: owaspList,
        file: result.path || 'unknown',
        startLine: result.start?.line || 0,
        endLine: result.end?.line || 0,
        startColumn: result.start?.col || 0,
        endColumn: result.end?.col || 0,
        snippet: snippet,  // Now contains proper code
        confidence: metadata.confidence || 'MEDIUM',
        impact: metadata.impact || 'MEDIUM',
        likelihood: metadata.likelihood || 'MEDIUM',
        references: metadata.references || [],
        fix: result.extra?.fix || metadata.fix || null,
        fixRegex: result.extra?.fix_regex || null
      };
    })
  );

  return enrichedResults;
}

/**
 * Extract CWE identifiers from metadata and rule ID
 */
function extractCWE(metadata, ruleId) {
  const cweList = [];
  
  if (metadata.cwe) {
    if (Array.isArray(metadata.cwe)) {
      cweList.push(...metadata.cwe.map(formatCWE));
    } else if (typeof metadata.cwe === 'string') {
      metadata.cwe.split(',').forEach(cwe => {
        cweList.push(formatCWE(cwe.trim()));
      });
    }
  }
  
  if (metadata['cwe-id']) {
    if (Array.isArray(metadata['cwe-id'])) {
      cweList.push(...metadata['cwe-id'].map(formatCWE));
    } else {
      cweList.push(formatCWE(metadata['cwe-id']));
    }
  }
  
  const cweMatch = ruleId.match(/cwe[- ]?(\d+)/i);
  if (cweMatch) {
    cweList.push(`CWE-${cweMatch[1]}`);
  }
  
  return [...new Set(cweList)];
}

/**
 * Extract OWASP categories from metadata
 */
function extractOWASP(metadata, ruleId) {
  const owaspList = [];
  
  if (metadata.owasp) {
    if (Array.isArray(metadata.owasp)) {
      owaspList.push(...metadata.owasp);
    } else if (typeof metadata.owasp === 'string') {
      metadata.owasp.split(',').forEach(cat => {
        owaspList.push(cat.trim());
      });
    }
  }
  
  ['owasp-top-10', 'owasp_category', 'owasp-2021', 'owasp-2017'].forEach(field => {
    if (metadata[field]) {
      owaspList.push(metadata[field]);
    }
  });
  
  if (owaspList.length === 0) {
    const owaspMapping = {
      'injection': 'A03:2021',
      'sql': 'A03:2021',
      'xss': 'A03:2021',
      'auth': 'A07:2021',
      'crypto': 'A02:2021',
      'access': 'A01:2021',
      'xxe': 'A05:2021',
      'deserialization': 'A08:2021'
    };
    
    const lowerRuleId = ruleId.toLowerCase();
    for (const [key, owasp] of Object.entries(owaspMapping)) {
      if (lowerRuleId.includes(key)) {
        owaspList.push(owasp);
        break;
      }
    }
  }
  
  return [...new Set(owaspList)];
}

/**
 * Format CWE identifier to consistent format
 */
function formatCWE(cwe) {
  const cweStr = String(cwe);
  
  if (cweStr.match(/^CWE-\d+$/i)) {
    return cweStr.toUpperCase();
  }
  
  const match = cweStr.match(/\d+/);
  if (match) {
    return `CWE-${match[0]}`;
  }
  
  return cweStr;
}

/**
 * Check if Semgrep is available
 */
async function checkSemgrepAvailable() {
  try {
    // Try python -m semgrep first (ignoring stderr deprecation warning)
    const result1 = await execAsync('python -m semgrep --version');
    // Even with stderr warning, it still works if we get stdout
    global.SEMGREP_PATH = 'python -m semgrep';
    return true;
  } catch (e) {
    // Check if the error contains version info (sometimes version goes to stderr)
    if (e.stderr && e.stderr.includes('1.')) {
      global.SEMGREP_PATH = 'python -m semgrep';
      return true;
    }
  }

  // Don't try regular semgrep since it's broken
  return false;
}

/**
 * Get Semgrep version
 */
async function getSemgrepVersion() {
  return new Promise((resolve) => {
    const semgrepCommand = global.SEMGREP_PATH || 'python -m semgrep';
    const [cmd, ...cmdArgs] = semgrepCommand.split(' ');
    const check = spawn(cmd, [...cmdArgs, '--version']);
    let output = '';
    let errorOutput = '';
    
    check.stdout.on('data', (data) => {
      output += data.toString();
    });
    
    check.stderr.on('data', (data) => {
      errorOutput += data.toString();
    });
    
    check.on('error', () => resolve(null));
    check.on('close', (code) => {
      // Extract version from output or error (sometimes version is in stderr)
      const versionMatch = (output + errorOutput).match(/\d+\.\d+\.\d+/);
      if (versionMatch) {
        resolve(versionMatch[0]);
      } else {
        resolve(null);
      }
    });
  });
}

module.exports = {
  runSemgrep,
  checkSemgrepAvailable,
  getSemgrepVersion,
  normalizeResults
};