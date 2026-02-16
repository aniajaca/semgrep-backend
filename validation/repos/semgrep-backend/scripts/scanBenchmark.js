#!/usr/bin/env node

/**
 * OWASP Benchmark Scanner
 * Scans all 2,740 BenchmarkJava test cases and outputs results for validation
 * 
 * Usage: node scripts/scanBenchmark.js
 */

const { spawn } = require('child_process');
const fs = require('fs').promises;
const path = require('path');

// Configuration
const BENCHMARK_DIR = path.join(__dirname, '..', 'BenchmarkJava', 'src', 'main', 'java', 'org', 'owasp', 'benchmark', 'testcode');
const OUTPUT_FILE = path.join(__dirname, '..', 'BenchmarkJava', 'scanner_results_raw.json');
const MAPPED_OUTPUT = path.join(__dirname, '..', 'BenchmarkJava', 'scanner_results_mapped.csv');
const META_OUTPUT = path.join(__dirname, '..', 'BenchmarkJava', 'scanner_run_meta.json');

// CWE to category mapping (from OWASP Benchmark)
const CWE_TO_CATEGORY = {
  '22': 'pathtraver',
  '78': 'cmdi',
  '79': 'xss',
  '89': 'sqli',
  '90': 'ldapi',
  '327': 'crypto',
  '328': 'hash',
  '330': 'weakrand',
  '501': 'trustbound',
  '614': 'securecookie',
  '643': 'xpathi'
};

// Category to CWE mapping (reverse)
const CATEGORY_TO_CWE = Object.fromEntries(
  Object.entries(CWE_TO_CATEGORY).map(([cwe, cat]) => [cat, cwe])
);

/**
 * Run Semgrep on the entire benchmark
 */
async function runBenchmarkScan() {
  console.log('================================');
  console.log('OWASP Benchmark Scanner');
  console.log('================================\n');
  
  // Verify benchmark directory exists
  try {
    await fs.access(BENCHMARK_DIR);
    console.log(`✓ Benchmark directory found: ${BENCHMARK_DIR}\n`);
  } catch (error) {
    console.error(`✗ ERROR: Benchmark directory not found: ${BENCHMARK_DIR}`);
    console.error('Please ensure BenchmarkJava is cloned in the parent directory.');
    process.exit(1);
  }

  console.log('Starting Semgrep scan...');
  console.log('This will take approximately 2-5 minutes...\n');

  const startTime = Date.now();

  return new Promise((resolve, reject) => {
    const semgrepArgs = [
      '--json',
      '--config', 'auto',
      '--config', 'p/security-audit',
      '--config', 'p/owasp-top-ten',
      '--severity', 'INFO',
      '--severity', 'WARNING',
      '--severity', 'ERROR',
      '--max-target-bytes', '5MB',
      '--timeout', '30',
      BENCHMARK_DIR
    ];

    console.log(`Command: semgrep ${semgrepArgs.join(' ')}\n`);

    const semgrep = spawn('semgrep', semgrepArgs, {
      maxBuffer: 50 * 1024 * 1024 // 50MB buffer
    });

    let stdout = '';
    let stderr = '';

    semgrep.stdout.on('data', (data) => {
      stdout += data.toString();
      // Show progress
      process.stdout.write('.');
    });

    semgrep.stderr.on('data', (data) => {
      stderr += data.toString();
    });

    semgrep.on('close', async (code) => {
      const duration = ((Date.now() - startTime) / 1000).toFixed(2);
      console.log(`\n\n✓ Scan completed in ${duration} seconds\n`);

      if (code !== 0 && code !== 1) { // Semgrep returns 1 if findings found
        console.error('Semgrep error:', stderr);
        reject(new Error(`Semgrep exited with code ${code}`));
        return;
      }

      try {
        const results = JSON.parse(stdout);
        
        // Save raw results
        await fs.writeFile(OUTPUT_FILE, JSON.stringify(results, null, 2));
        console.log(`✓ Raw results saved: ${OUTPUT_FILE}`);
        console.log(`  Total findings: ${results.results ? results.results.length : 0}\n`);

        // Map results to benchmark format
        await mapResultsToBenchmarkFormat(results);
        
        resolve(results);
      } catch (error) {
        console.error('Error parsing Semgrep output:', error.message);
        console.error('Raw output:', stdout.substring(0, 500));
        reject(error);
      }
    });

    semgrep.on('error', (error) => {
      console.error('Failed to start Semgrep:', error.message);
      console.error('Is Semgrep installed? Run: pip install semgrep');
      reject(error);
    });
  });
}

/**
 * Map Semgrep findings to OWASP Benchmark CSV format
 */
async function mapResultsToBenchmarkFormat(semgrepResults) {
  console.log('Mapping results to benchmark format...\n');

  // Load ground truth to get all test case names
  const groundTruthPath = path.join(__dirname, '..', 'BenchmarkJava', 'ground_truth_full.csv');
  const groundTruthContent = await fs.readFile(groundTruthPath, 'utf-8');
  const groundTruthLines = groundTruthContent.trim().split('\n').slice(1); // Skip header
  
  // Create a map: testName -> { category, expectedVuln }
  const testCases = new Map();
  for (const line of groundTruthLines) {
    const [testName, category, isVuln, cwe] = line.split(',');
    testCases.set(testName, {
      category,
      expectedVuln: isVuln === 'true',
      cwe
    });
  }

  console.log(`Total test cases in ground truth: ${testCases.size}`);

  // Create findings map: testName -> [findings]
  const findingsMap = new Map();
  
  if (semgrepResults.results) {
    for (const finding of semgrepResults.results) {
      // Extract test name from file path
      const fileName = path.basename(finding.path, '.java');
      
      if (fileName.startsWith('BenchmarkTest')) {
        if (!findingsMap.has(fileName)) {
          findingsMap.set(fileName, []);
        }
        findingsMap.get(fileName).push(finding);
      }
    }
  }

  console.log(`Test cases with findings: ${findingsMap.size}\n`);

  // Generate CSV output
  const csvLines = ['# test name,category,scanner detected vuln,confidence,cwe,rule_id'];
  
  let detectedCount = 0;
  let missedCount = 0;
  let categoryMismatchCount = 0;

  for (const [testName, groundTruth] of testCases) {
    const findings = findingsMap.get(testName) || [];
    
    if (findings.length === 0) {
      // No finding detected
      csvLines.push(`${testName},${groundTruth.category},false,0.0,${groundTruth.cwe},none`);
      if (groundTruth.expectedVuln) {
        missedCount++;
      }
    } else {
      // One or more findings detected
      // Try to match finding category to expected category
      let bestMatch = null;
      let bestConfidence = 0;

      for (const finding of findings) {
        const findingCWE = extractCWE(finding);
        const findingCategory = CWE_TO_CATEGORY[findingCWE] || 'unknown';
        const confidence = calculateConfidence(finding);

        if (findingCategory === groundTruth.category && confidence > bestConfidence) {
          bestMatch = finding;
          bestConfidence = confidence;
        } else if (!bestMatch) {
          bestMatch = finding; // Use any finding if no category match
        }
      }

      const detectedCWE = extractCWE(bestMatch);
      const detectedCategory = CWE_TO_CATEGORY[detectedCWE] || 'unknown';
      const confidence = calculateConfidence(bestMatch);
      const ruleId = bestMatch.check_id || 'unknown';

      csvLines.push(`${testName},${detectedCategory},true,${confidence.toFixed(2)},${detectedCWE},${ruleId}`);
      
      detectedCount++;
      if (detectedCategory !== groundTruth.category) {
        categoryMismatchCount++;
      }
    }
  }

  // Write CSV file
  await fs.writeFile(MAPPED_OUTPUT, csvLines.join('\n'));
  
  console.log('================================');
  console.log('Mapping Summary:');
  console.log('================================');
  console.log(`Total test cases: ${testCases.size}`);
  console.log(`Vulnerabilities detected: ${detectedCount}`);
  console.log(`Vulnerabilities missed: ${missedCount}`);
  console.log(`Category mismatches: ${categoryMismatchCount}`);
  console.log(`\n✓ Mapped results saved: ${MAPPED_OUTPUT}\n`);
}

/**
 * Extract CWE from Semgrep finding
 */
function extractCWE(finding) {
  // Try to extract from metadata
  if (finding.extra && finding.extra.metadata) {
    const metadata = finding.extra.metadata;
    
    // Check various CWE fields
    if (metadata.cwe) {
      if (Array.isArray(metadata.cwe) && metadata.cwe.length > 0) {
        return metadata.cwe[0].replace('CWE-', '');
      } else if (typeof metadata.cwe === 'string') {
        return metadata.cwe.replace('CWE-', '');
      }
    }
    
    // Check category field
    if (metadata.category) {
      const categoryLower = metadata.category.toLowerCase();
      for (const [cwe, category] of Object.entries(CWE_TO_CATEGORY)) {
        if (categoryLower.includes(category) || category.includes(categoryLower)) {
          return cwe;
        }
      }
    }
  }

  // Try to infer from rule ID
  const ruleId = (finding.check_id || '').toLowerCase();
  if (ruleId.includes('sql-injection') || ruleId.includes('sqli')) return '89';
  if (ruleId.includes('xss') || ruleId.includes('cross-site')) return '79';
  if (ruleId.includes('command-injection') || ruleId.includes('cmdi')) return '78';
  if (ruleId.includes('path-traversal') || ruleId.includes('directory')) return '22';
  if (ruleId.includes('weak-crypto') || ruleId.includes('encryption')) return '327';
  if (ruleId.includes('weak-hash') || ruleId.includes('md5') || ruleId.includes('sha1')) return '328';
  if (ruleId.includes('weak-random') || ruleId.includes('predictable')) return '330';
  if (ruleId.includes('ldap')) return '90';
  if (ruleId.includes('xpath')) return '643';
  if (ruleId.includes('cookie') && ruleId.includes('secure')) return '614';
  if (ruleId.includes('trust-boundary')) return '501';

  return 'unknown';
}

/**
 * Calculate confidence score for finding
 */
function calculateConfidence(finding) {
  // Use severity as base confidence
  const severityMap = {
    'ERROR': 0.9,
    'WARNING': 0.7,
    'INFO': 0.5
  };

  const baseConfidence = severityMap[finding.extra?.severity] || 0.5;
  
  // Adjust based on metadata confidence
  if (finding.extra?.metadata?.confidence) {
    const metaConfidence = finding.extra.metadata.confidence.toLowerCase();
    if (metaConfidence === 'high') return Math.max(baseConfidence, 0.8);
    if (metaConfidence === 'medium') return Math.max(baseConfidence, 0.6);
    if (metaConfidence === 'low') return Math.min(baseConfidence, 0.4);
  }

  return baseConfidence;
}

/**
 * Main execution
 */
async function main() {
  try {
    await runBenchmarkScan();
    
    console.log('================================');
    console.log('Next Steps:');
    console.log('================================');
    console.log('1. Review scanner_results_mapped.csv');
    console.log('2. Run metrics calculation script');
    console.log('3. Generate performance visualizations');
    console.log('4. Document results in thesis\n');
    
    process.exit(0);
  } catch (error) {
    console.error('\n✗ ERROR:', error.message);
    process.exit(1);
  }
}

// Run if called directly
if (require.main === module) {
  main();
}

module.exports = { runBenchmarkScan, mapResultsToBenchmarkFormat };