#!/usr/bin/env node

// scripts/scan.js - CLI scanner for code analysis
const { runSemgrep, checkSemgrepAvailable } = require('../src/semgrepAdapter');
const { ASTVulnerabilityScanner } = require('../src/astScanner');
const { normalizeFindings, enrichFindings } = require('../src/data/lib/normalize');
const EnhancedRiskCalculator = require('../src/enhancedRiskCalculator');
const fs = require('fs').promises;
const path = require('path');

// Parse command line arguments
function parseArgs() {
  const args = process.argv.slice(2);
  const options = {
    path: '.',
    languages: [],
    output: 'console',
    outputFile: null,
    context: {},
    verbose: false,
    help: false
  };
  
  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '--path':
      case '-p':
        options.path = args[++i];
        break;
      case '--languages':
      case '-l':
        options.languages = args[++i].split(',');
        break;
      case '--output':
      case '-o':
        options.output = args[++i]; // console, json, html
        break;
      case '--output-file':
      case '-f':
        options.outputFile = args[++i];
        break;
      case '--context':
      case '-c':
        // Parse context flags: --context production,internet-facing
        const contexts = args[++i].split(',');
        contexts.forEach(ctx => {
          const kebab = ctx.trim().toLowerCase();
          // Convert kebab-case to camelCase
          const camel = kebab.replace(/-([a-z])/g, (m, p1) => p1.toUpperCase());
          options.context[camel] = true;
        });
        break;
      case '--verbose':
      case '-v':
        options.verbose = true;
        break;
      case '--help':
      case '-h':
        options.help = true;
        break;
    }
  }
  
  return options;
}

// Display help message
function showHelp() {
  console.log(`
Neperia Security Scanner - Multi-language vulnerability detection

Usage: npm run scan -- [options]

Options:
  --path, -p <path>         Target directory to scan (default: current directory)
  --languages, -l <langs>   Comma-separated languages: javascript,python,java
  --context, -c <flags>     Context flags: production,internet-facing,handles-pi
  --output, -o <format>     Output format: console, json, html (default: console)
  --output-file, -f <file>  Save output to file
  --verbose, -v             Show detailed progress
  --help, -h               Show this help message

Examples:
  # Scan current directory for all languages
  npm run scan
  
  # Scan specific path for Python only
  npm run scan -- --path ./src --languages python
  
  # Scan with production context and save JSON
  npm run scan -- --path ./app --context production,internet-facing --output json -f results.json
  
  # Scan Java code with verbose output
  npm run scan -- --path ./java-app --languages java --verbose

Context Flags:
  production          Code runs in production (+0.4 risk score)
  internet-facing     Exposed to internet (+0.6 risk score)
  handles-pi          Processes personal data (+0.4 risk score)
  legacy-code         Legacy system (+0.2 risk score)
  business-critical   Critical to business (+0.6 risk score)
`);
}

// Detect languages in target directory
async function detectLanguages(targetPath) {
  const languages = new Set();
  
  async function scanDir(dir) {
    const items = await fs.readdir(dir, { withFileTypes: true });
    
    for (const item of items) {
      // Skip common directories
      if (['node_modules', '.git', 'dist', 'build', '__pycache__', '.venv', 'venv', 'target'].includes(item.name)) {
        continue;
      }
      
      const fullPath = path.join(dir, item.name);
      
      if (item.isDirectory()) {
        await scanDir(fullPath);
      } else {
        const ext = path.extname(item.name);
        if (['.js', '.jsx', '.ts', '.tsx'].includes(ext)) {
          languages.add('javascript');
        } else if (ext === '.py') {
          languages.add('python');
        } else if (ext === '.java') {
          languages.add('java');
        }
      }
    }
  }
  
  await scanDir(targetPath);
  return Array.from(languages);
}

// Format output based on type
function formatOutput(findings, summary, format) {
  switch (format) {
    case 'json':
      return JSON.stringify({ findings, summary }, null, 2);
    
    case 'html':
      return generateHtmlReport(findings, summary);
    
    case 'console':
    default:
      return formatConsoleOutput(findings, summary);
  }
}

// Generate console output
function formatConsoleOutput(findings, summary) {
  let output = '\n╔══════════════════════════════════════════════════════════════╗\n';
  output += '║            NEPERIA SECURITY SCAN RESULTS                    ║\n';
  output += '╚══════════════════════════════════════════════════════════════╝\n\n';
  
  output += `📊 Summary\n`;
  output += `────────────────────────────────────────────────────────────────\n`;
  output += `Total Issues: ${summary.totalFindings}\n`;
  output += `Critical: ${summary.countsBySeverity.critical || 0} | `;
  output += `High: ${summary.countsBySeverity.high || 0} | `;
  output += `Medium: ${summary.countsBySeverity.medium || 0} | `;
  output += `Low: ${summary.countsBySeverity.low || 0}\n`;
  output += `Risk Index: ${summary.adjustedRiskIndex}/100\n\n`;
  
  if (summary.top5 && summary.top5.length > 0) {
    output += `🔴 Top Priority Issues\n`;
    output += `────────────────────────────────────────────────────────────────\n`;
    
    summary.top5.forEach((issue, i) => {
      output += `${i + 1}. [${issue.severity.toUpperCase()}] ${issue.message}\n`;
      output += `   📁 ${issue.file}:${issue.line}\n`;
      output += `   📊 Score: ${issue.score.toFixed(1)}/10\n\n`;
    });
  }
  
  output += `\n💡 Recommendations\n`;
  output += `────────────────────────────────────────────────────────────────\n`;
  
  if (summary.countsBySeverity.critical > 0) {
    output += `• Fix ${summary.countsBySeverity.critical} critical issues immediately\n`;
  }
  if (summary.countsBySeverity.high > 0) {
    output += `• Address ${summary.countsBySeverity.high} high-severity issues within 48 hours\n`;
  }
  if (summary.totalFindings === 0) {
    output += `• No security issues detected - maintain security best practices\n`;
  }
  
  return output;
}

// Generate HTML report
function generateHtmlReport(findings, summary) {
  return `
<!DOCTYPE html>
<html>
<head>
  <title>Neperia Security Scan Report</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; }
    .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; }
    .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 30px 0; }
    .metric { background: #f7f7f7; padding: 20px; border-radius: 8px; }
    .metric h3 { margin: 0 0 10px 0; color: #333; }
    .metric .value { font-size: 2em; font-weight: bold; }
    .critical { color: #dc2626; }
    .high { color: #ea580c; }
    .medium { color: #ca8a04; }
    .low { color: #65a30d; }
    .finding { background: white; border: 1px solid #e5e5e5; padding: 20px; margin: 10px 0; border-radius: 8px; }
    .finding-header { display: flex; justify-content: space-between; align-items: center; }
    .severity-badge { padding: 4px 12px; border-radius: 20px; color: white; font-weight: bold; font-size: 0.9em; }
    .severity-critical { background: #dc2626; }
    .severity-high { background: #ea580c; }
    .severity-medium { background: #ca8a04; }
    .severity-low { background: #65a30d; }
  </style>
</head>
<body>
  <div class="header">
    <h1>Security Scan Report</h1>
    <p>Generated: ${new Date().toLocaleString()}</p>
  </div>
  
  <div class="summary">
    <div class="metric">
      <h3>Total Issues</h3>
      <div class="value">${summary.totalFindings}</div>
    </div>
    <div class="metric">
      <h3>Critical</h3>
      <div class="value critical">${summary.countsBySeverity.critical || 0}</div>
    </div>
    <div class="metric">
      <h3>High</h3>
      <div class="value high">${summary.countsBySeverity.high || 0}</div>
    </div>
    <div class="metric">
      <h3>Medium</h3>
      <div class="value medium">${summary.countsBySeverity.medium || 0}</div>
    </div>
    <div class="metric">
      <h3>Low</h3>
      <div class="value low">${summary.countsBySeverity.low || 0}</div>
    </div>
    <div class="metric">
      <h3>Risk Index</h3>
      <div class="value">${summary.adjustedRiskIndex}/100</div>
    </div>
  </div>
  
  <h2>Findings</h2>
  ${findings.slice(0, 50).map(f => `
    <div class="finding">
      <div class="finding-header">
        <h3>${f.message}</h3>
        <span class="severity-badge severity-${f.adjustedSeverity}">${f.adjustedSeverity.toUpperCase()}</span>
      </div>
      <p><strong>File:</strong> ${f.file}:${f.startLine}</p>
      <p><strong>Score:</strong> ${f.adjustedScore.toFixed(1)}/10 | <strong>Priority:</strong> ${f.priority}</p>
      <p><strong>CWE:</strong> ${f.cwe.join(', ')} | <strong>OWASP:</strong> ${f.owasp.join(', ')}</p>
      ${f.snippet ? `<pre>${f.snippet}</pre>` : ''}
    </div>
  `).join('')}
</body>
</html>
  `;
}

// Main scanning function
async function scan(options) {
  const startTime = Date.now();
  
  if (options.verbose) {
    console.log('🔍 Starting security scan...');
    console.log(`Target: ${options.path}`);
  }
  
  // Check if target exists
  try {
    await fs.access(options.path);
  } catch (error) {
    console.error(`❌ Error: Target path does not exist: ${options.path}`);
    process.exit(1);
  }
  
  // Auto-detect languages if not specified
  if (options.languages.length === 0) {
    if (options.verbose) console.log('🔎 Detecting languages...');
    options.languages = await detectLanguages(options.path);
    if (options.verbose) console.log(`Found: ${options.languages.join(', ')}`);
  }
  
  const allFindings = [];
  
  // Check if Semgrep is available
  const semgrepAvailable = await checkSemgrepAvailable();
  
  if (semgrepAvailable) {
    if (options.verbose) console.log('✅ Semgrep is available');
    
    try {
      // Use real Semgrep registry rules
      const semgrepOptions = {
        useCustomRules: false,  // Use registry, not custom rules
        rulesets: ['auto'],     // 'auto' uses all security rules
        languages: options.languages,
        exclude: ['node_modules', '.git', 'dist', 'build', '__pycache__', '.venv', 'venv', 'target'],
        severity: 'ERROR,WARNING',  // Skip INFO to reduce noise
        timeout: 30  // 30 seconds per rule
      };
      
      if (options.verbose) {
        console.log(`🚀 Running Semgrep with production security rules...`);
        console.log(`   Rulesets: ${semgrepOptions.rulesets.join(', ')}`);
        console.log(`   Languages: ${options.languages.join(', ')}`);
      }
      
      const findings = await runSemgrep(options.path, semgrepOptions);
      allFindings.push(...findings);
      
      if (options.verbose) console.log(`✅ Semgrep found ${findings.length} security issues`);
    } catch (error) {
      console.error('⚠️  Semgrep scan failed:', error.message);
    }
  } else {
    console.warn('⚠️  Semgrep not available - using limited custom scanner');
    
    // Fallback to custom scanner for JavaScript only
    if (options.languages.includes('javascript')) {
      const scanner = new ASTVulnerabilityScanner();
      const jsFiles = await getJavaScriptFiles(options.path);
      
      for (const file of jsFiles.slice(0, 50)) {
        try {
          const code = await fs.readFile(file, 'utf8');
          const findings = scanner.scan(code, file, 'javascript');
          
          const normalized = findings.map(f => ({
            engine: 'custom',
            ruleId: f.check_id,
            category: 'sast',
            severity: f.severity.toUpperCase(),
            message: f.message,
            cwe: [f.cweId],
            owasp: [f.owasp?.category || 'A06:2021'],
            file: f.file,
            startLine: f.line,
            endLine: f.line,
            snippet: f.snippet
          }));
          
          allFindings.push(...normalized);
        } catch (error) {
          // Skip files with errors
        }
      }
    }
  }
  
  // Normalize and enrich findings
  const normalized = normalizeFindings(allFindings);
  const enriched = enrichFindings(normalized);
  
  // Score findings with risk calculator
  const riskCalculator = new EnhancedRiskCalculator();
  const scoredFindings = enriched.map(finding => {
    const vuln = {
      severity: finding.severity.toLowerCase(),
      cwe: finding.cwe[0] || 'CWE-1',
      cweId: finding.cwe[0] || 'CWE-1',
      file: finding.file,
      line: finding.startLine
    };
    
    const riskResult = riskCalculator.calculateVulnerabilityRisk(vuln, options.context);
    
    return {
      ...finding,
      cvssBase: riskResult.original.cvss,
      adjustedScore: riskResult.adjusted.score,
      adjustedSeverity: riskResult.adjusted.severity,
      priority: riskResult.adjusted.priority.priority
    };
  });
  
  // Sort by adjusted score
  scoredFindings.sort((a, b) => b.adjustedScore - a.adjustedScore);
  
  // Generate summary
  const summary = {
    totalFindings: scoredFindings.length,
    languages: options.languages,
    countsBySeverity: {
      critical: scoredFindings.filter(f => f.adjustedSeverity === 'critical').length,
      high: scoredFindings.filter(f => f.adjustedSeverity === 'high').length,
      medium: scoredFindings.filter(f => f.adjustedSeverity === 'medium').length,
      low: scoredFindings.filter(f => f.adjustedSeverity === 'low').length,
      info: scoredFindings.filter(f => f.adjustedSeverity === 'info').length
    },
    top5: scoredFindings.slice(0, 5).map(f => ({
      file: path.basename(f.file),
      line: f.startLine,
      severity: f.adjustedSeverity,
      score: f.adjustedScore,
      message: f.message
    })),
    adjustedRiskIndex: calculateRiskIndex(scoredFindings),
    scanTime: ((Date.now() - startTime) / 1000).toFixed(2) + 's'
  };
  
  // Format output
  const output = formatOutput(scoredFindings, summary, options.output);
  
  // Save to file if specified
  if (options.outputFile) {
    await fs.writeFile(options.outputFile, output);
    console.log(`✅ Results saved to ${options.outputFile}`);
  } else if (options.output === 'console') {
    console.log(output);
  } else {
    // For non-console output without file, print to stdout
    process.stdout.write(output);
  }
  
  if (options.verbose) {
    console.log(`\n⏱️  Scan completed in ${summary.scanTime}`);
  }
  
  // Exit with error code if critical issues found
  if (summary.countsBySeverity.critical > 0) {
    process.exit(1);
  }
}

// Helper to get JavaScript files
async function getJavaScriptFiles(dir, files = []) {
  const items = await fs.readdir(dir, { withFileTypes: true });
  
  for (const item of items) {
    const fullPath = path.join(dir, item.name);
    
    if (item.name === 'node_modules' || item.name.startsWith('.')) {
      continue;
    }
    
    if (item.isDirectory()) {
      await getJavaScriptFiles(fullPath, files);
    } else if (item.name.endsWith('.js') || item.name.endsWith('.ts')) {
      files.push(fullPath);
    }
  }
  
  return files;
}

// Calculate risk index
function calculateRiskIndex(findings) {
  if (findings.length === 0) return 0;
  
  const weights = {
    critical: 10,
    high: 5,
    medium: 2,
    low: 0.5,
    info: 0.1
  };
  
  let totalRisk = 0;
  findings.forEach(f => {
    const weight = weights[f.adjustedSeverity] || 1;
    totalRisk += f.adjustedScore * weight;
  });
  
  return Math.min(100, Math.round(totalRisk / findings.length));
}

// Main execution
async function main() {
  const options = parseArgs();
  
  if (options.help) {
    showHelp();
    process.exit(0);
  }
  
  try {
    await scan(options);
  } catch (error) {
    console.error('❌ Scan failed:', error.message);
    if (options.verbose) {
      console.error(error.stack);
    }
    process.exit(1);
  }
}

// Run if executed directly
if (require.main === module) {
  main();
}

module.exports = { scan };