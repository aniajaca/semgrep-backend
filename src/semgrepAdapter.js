// semgrepAdapter.js - Production-ready Semgrep integration
const { spawn } = require('child_process');
const fs = require('fs').promises;
const path = require('path');
const { exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);

/**
 * Execute Semgrep with real security rules
 * @param {string} targetPath - Path to scan
 * @param {object} options - Scanning options
 * @returns {Promise<Array>} Normalized findings
 */
async function runSemgrep(targetPath, options = {}) {
  // Debug checks - INSIDE the function
  const homeDir = process.env.HOME || '/root';
  const semgrepDir = path.join(homeDir, '.semgrep');
  console.log('Semgrep cache directory:', semgrepDir);
  console.log('Directory exists?', await fs.access(semgrepDir).then(() => true).catch(() => false));
  
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
      // Use local custom rules if specifically requested
      semgrepArgs.push('--config', options.rulesPath || './rules');
    } else if (options.rulesets && options.rulesets.length > 0) {
      // Use specific Semgrep registry rulesets
      options.rulesets.forEach(ruleset => {
        semgrepArgs.push('--config', ruleset);
      });
    } else {
      // DEFAULT: Use comprehensive security rules from Semgrep registry
      semgrepArgs.push('--config', 'p/security');
      semgrepArgs.push('--config', 'p/owasp-top-ten');
      semgrepArgs.push('--config', 'p/r2c-security-audit');

      // Add language-specific rulesets based on what's being scanned
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
      '--json',           // JSON output for parsing
      '--verbose',        // Show what is happening
      '--no-git-ignore',  // Scan everything (we handle excludes)
      '--metrics', 'on',  // Enable metrics for registry access
      '--no-rewrite-rule-ids' // Keep original rule IDs
    );

    // Add timeout (important for large codebases)
    if (options.timeout) {
      semgrepArgs.push('--timeout', options.timeout.toString());
    } else {
      semgrepArgs.push('--timeout', '30'); // 30 seconds per rule
    }
    
    // Add max target bytes (skip huge files)
    semgrepArgs.push('--max-target-bytes', options.maxBytes || '1000000'); // 1MB default
    
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
    
    // Exclude patterns (critical for performance)
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
    
    // Add target path at the end
    semgrepArgs.push(targetPath);

    console.log('Running Semgrep with args:', semgrepArgs.join(' '));

    const semgrep = spawn('semgrep', semgrepArgs, {
      maxBuffer: 100 * 1024 * 1024, // 100MB buffer for large outputs
      timeout: options.processTimeout || 600000 // 10 minute process timeout
    });

    let stdout = '';
    let stderr = '';
    let outputSize = 0;
    const maxOutputSize = 100 * 1024 * 1024; // 100MB max

    // Collect stdout in chunks to handle large outputs
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
      console.log('Semgrep stderr chunk:', chunk.toString()); // Debug output
    });

    semgrep.on('error', (error) => {
      if (error.code === 'ENOENT') {
        reject(new Error('Semgrep not found. Install with: pip install semgrep'));
      } else {
        reject(error);
      }
    });

    semgrep.on('close', (code) => {
      // Add debugging
      console.log('Semgrep exit code:', code);
      console.log('Semgrep stdout length:', stdout.length);
      console.log('Semgrep stderr (first 500 chars):', stderr.substring(0, 500));
      
      if (stdout) {
        try {
          const parsed = JSON.parse(stdout || '{}');
          console.log('Semgrep raw results count:', parsed.results?.length || 0);
          if (parsed.results && parsed.results.length > 0) {
            console.log('First result:', JSON.stringify(parsed.results[0], null, 2));
          }
        } catch (e) {
          console.log('Could not parse stdout as JSON');
        }
      }

      // Semgrep returns non-zero when it finds issues, which is expected
      if (code !== 0 && code !== 1 && !stdout) {
        reject(new Error(`Semgrep failed with code ${code}: ${stderr}`));
        return;
      }

      try {
        const results = JSON.parse(stdout || '{}');
        const findings = normalizeResults(results);
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
 * @returns {Array} Normalized findings
 */
function normalizeResults(semgrepOutput) {
  if (!semgrepOutput.results || !Array.isArray(semgrepOutput.results)) {
    return [];
  }

  return semgrepOutput.results.map(result => {
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

    // Build the normalized finding
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
      snippet: result.extra?.lines || '',
      confidence: metadata.confidence || 'MEDIUM',
      impact: metadata.impact || 'MEDIUM',
      likelihood: metadata.likelihood || 'MEDIUM',
      references: metadata.references || [],
      fix: result.extra?.fix || metadata.fix || null,
      fixRegex: result.extra?.fix_regex || null
    };
  });
}

/**
 * Extract CWE identifiers from metadata and rule ID
 * @param {Object} metadata - Semgrep metadata
 * @param {string} ruleId - Rule identifier
 * @returns {Array<string>} CWE identifiers
 */
function extractCWE(metadata, ruleId) {
  const cweList = [];
  
  // Check various possible locations for CWE
  if (metadata.cwe) {
    if (Array.isArray(metadata.cwe)) {
      cweList.push(...metadata.cwe.map(formatCWE));
    } else if (typeof metadata.cwe === 'string') {
      // Handle comma-separated CWEs
      metadata.cwe.split(',').forEach(cwe => {
        cweList.push(formatCWE(cwe.trim()));
      });
    }
  }
  
  // Check 'cwe-id' field
  if (metadata['cwe-id']) {
    if (Array.isArray(metadata['cwe-id'])) {
      cweList.push(...metadata['cwe-id'].map(formatCWE));
    } else {
      cweList.push(formatCWE(metadata['cwe-id']));
    }
  }
  
  // Try to extract from rule ID (many Semgrep rules include CWE in the ID)
  const cweMatch = ruleId.match(/cwe[- ]?(\d+)/i);
  if (cweMatch) {
    cweList.push(`CWE-${cweMatch[1]}`);
  }
  
  return [...new Set(cweList)]; // Remove duplicates
}

/**
 * Extract OWASP categories from metadata
 * @param {Object} metadata - Semgrep metadata
 * @param {string} ruleId - Rule identifier
 * @returns {Array<string>} OWASP categories
 */
function extractOWASP(metadata, ruleId) {
  const owaspList = [];
  
  if (metadata.owasp) {
    if (Array.isArray(metadata.owasp)) {
      owaspList.push(...metadata.owasp);
    } else if (typeof metadata.owasp === 'string') {
      // Handle comma-separated OWASP categories
      metadata.owasp.split(',').forEach(cat => {
        owaspList.push(cat.trim());
      });
    }
  }
  
  // Check common OWASP field variations
  ['owasp-top-10', 'owasp_category', 'owasp-2021', 'owasp-2017'].forEach(field => {
    if (metadata[field]) {
      owaspList.push(metadata[field]);
    }
  });
  
  // Map common vulnerability types to OWASP if not present
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
 * @param {string} cwe - CWE identifier in various formats
 * @returns {string} Formatted CWE (e.g., "CWE-89")
 */
function formatCWE(cwe) {
  const cweStr = String(cwe);
  
  // Already formatted
  if (cweStr.match(/^CWE-\d+$/i)) {
    return cweStr.toUpperCase();
  }
  
  // Extract number from various formats
  const match = cweStr.match(/\d+/);
  if (match) {
    return `CWE-${match[0]}`;
  }
  
  return cweStr;
}

/**
 * Check if Semgrep is available
 * @returns {Promise<boolean>} True if Semgrep is available
 */
async function checkSemgrepAvailable() {
  try {
    // Try different possible paths
    const paths = [
      'semgrep',
      '/root/.local/bin/semgrep',
      '/usr/local/bin/semgrep'
    ];
    
    for (const semgrepPath of paths) {
      try {
        const result = await execAsync(`${semgrepPath} --version`);
        if (result.stdout) {
          // Store the working path
          global.SEMGREP_PATH = semgrepPath;
          return true;
        }
      } catch (e) {
        continue;
      }
    }
    return false;
  } catch (error) {
    return false;
  }
}

/**
 * Get Semgrep version
 * @returns {Promise<string|null>} Version string or null
 */
async function getSemgrepVersion() {
  return new Promise((resolve) => {
    const check = spawn('semgrep', ['--version']);
    let output = '';
    
    check.stdout.on('data', (data) => {
      output += data.toString();
    });
    
    check.on('error', () => resolve(null));
    check.on('close', (code) => {
      if (code === 0) {
        const version = output.trim();
        resolve(version);
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