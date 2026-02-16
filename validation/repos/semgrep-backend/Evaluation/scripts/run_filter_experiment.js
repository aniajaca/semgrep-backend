#!/usr/bin/env node
// Evaluation/scripts/run_filter_experiment.js
// Experiment 3: Contextual Filter Effectiveness

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

// Import the contextual filter
const EnhancedContextualFilter = require('../../src/contextInference/contextualFilter');

const OUTPUT_DIR = path.join(__dirname, '../03_filter_effectiveness');

async function runFilterExperiment(repoPath, repoName) {
  console.log('=== EXPERIMENT 3: CONTEXTUAL FILTER EFFECTIVENESS ===\n');
  console.log(`Repository: ${repoName}`);
  console.log(`Path: ${repoPath}\n`);
  
  // Step 1: Run Semgrep scan
  console.log('Step 1/5: Running Semgrep scan...');
  const rawFindingsPath = path.join(OUTPUT_DIR, 'raw_findings.json');
  
  try {
    // Use execSync with explicit output capture
    const output = execSync(
      `semgrep --config auto --json ${repoPath}`,
      { encoding: 'utf-8', maxBuffer: 50 * 1024 * 1024 }
    );
    
    // Write output to file
    fs.writeFileSync(rawFindingsPath, output);
    console.log(`✅ Raw findings saved to: ${rawFindingsPath}\n`);
  } catch (error) {
    // Semgrep returns non-zero when findings exist - capture stdout anyway
    if (error.stdout) {
      fs.writeFileSync(rawFindingsPath, error.stdout);
      console.log(`✅ Raw findings saved (${error.status} exit code is normal)\n`);
    } else {
      console.error('❌ Semgrep failed:', error.message);
      throw error;
    }
  }
  
  // Verify file exists
  if (!fs.existsSync(rawFindingsPath)) {
    throw new Error(`Semgrep output file not created: ${rawFindingsPath}`);
  }
  
  // Step 2: Load and parse Semgrep results
  console.log('Step 2/5: Parsing Semgrep results...');
  const rawData = JSON.parse(fs.readFileSync(rawFindingsPath, 'utf-8'));
  const rawFindings = rawData.results || [];
  console.log(`   Found ${rawFindings.length} raw findings\n`);
  
  if (rawFindings.length === 0) {
    console.log('⚠️  No findings to filter. Repository may be very clean or scan failed.');
    console.log('   Try running with a different repository or check Semgrep configuration.\n');
    return;
  }
  
  // Step 3: Map Semgrep format to internal format
  console.log('Step 3/5: Mapping findings to internal format...');
  const mappedFindings = rawFindings.map(f => ({
    id: f.check_id || f.extra?.metadata?.id,
    ruleId: f.check_id,
    severity: mapSeverity(f.extra?.severity),
    message: f.extra?.message || f.check_id,
    file: f.path,
    startLine: f.start?.line || f.line,
    endLine: f.end?.line || f.line,
    cwe: extractCWE(f),
    cweId: extractCWE(f),
    category: f.extra?.metadata?.category || 'unknown',
    confidence: f.extra?.metadata?.confidence || 'medium'
  }));
  console.log(`   Mapped ${mappedFindings.length} findings\n`);
  
  // Step 4: Apply contextual filter
  console.log('Step 4/5: Applying contextual filter...');
  const filter = new EnhancedContextualFilter({
    filterTestFiles: true,
    filterExampleCode: true,
    filterBuildArtifacts: true,
    filterInjectionWithoutInput: true,
    detectSanitization: true,
    benchmarkMode: false,
    verbose: false
  });
  
  const filteredFindings = await filter.filterFindings(
    mappedFindings,
    repoPath,
    null // No context inference needed for this experiment
  );
  
  const stats = filter.getStats();
  console.log(`   Filtered: ${stats.filtered} findings`);
  console.log(`   Downgraded: ${stats.downgraded} findings`);
  console.log(`   Passed: ${stats.passed} findings\n`);
  
  // Step 5: Generate artifacts
  console.log('Step 5/5: Generating artifacts...\n');
  
  // Artifact 1: filtered_findings.json
  const filteredPath = path.join(OUTPUT_DIR, 'filtered_findings.json');
  fs.writeFileSync(filteredPath, JSON.stringify(filteredFindings, null, 2));
  console.log(`✅ ${filteredPath}`);
  
  // Artifact 2: delta_metrics.json
  const deltaMetrics = {
    repository: repoName,
    raw_count: rawFindings.length,
    filtered_count: filteredFindings.length,
    removed_count: stats.filtered,
    downgraded_count: stats.downgraded,
    passed_count: stats.passed,
    reduction_rate: ((stats.filtered / rawFindings.length) * 100).toFixed(1) + '%',
    filter_reasons: stats.filterReasons,
    timestamp: new Date().toISOString()
  };
  
  const deltaPath = path.join(OUTPUT_DIR, 'delta_metrics.json');
  fs.writeFileSync(deltaPath, JSON.stringify(deltaMetrics, null, 2));
  console.log(`✅ ${deltaPath}`);
  
  // Artifact 3: filtered_examples.csv
  const examplesPath = path.join(OUTPUT_DIR, 'filtered_examples.csv');
  const csvLines = ['file,line,rule,severity,reason,confidence'];
  
  // Get first 50 filtered findings
  let exampleCount = 0;
  for (const finding of mappedFindings) {
    if (exampleCount >= 50) break;
    
    // Check if this finding was filtered
    const wasFiltered = !filteredFindings.some(f => 
      f.file === finding.file && f.startLine === finding.startLine && f.ruleId === finding.ruleId
    );
    
    if (wasFiltered) {
      const reason = guessFilterReason(finding, stats.filterReasons);
      csvLines.push(
        `"${finding.file}",${finding.startLine},"${finding.ruleId}","${finding.severity}","${reason}","N/A"`
      );
      exampleCount++;
    }
  }
  
  fs.writeFileSync(examplesPath, csvLines.join('\n'));
  console.log(`✅ ${examplesPath}`);
  
  // Artifact 4: summary.md
  const summaryPath = path.join(OUTPUT_DIR, 'summary.md');
  const summary = generateSummary(repoName, deltaMetrics, stats);
  fs.writeFileSync(summaryPath, summary);
  console.log(`✅ ${summaryPath}`);
  
  console.log('\n=== EXPERIMENT COMPLETE ===');
  console.log(`\nResults:`);
  console.log(`  Raw findings: ${deltaMetrics.raw_count}`);
  console.log(`  Filtered out: ${deltaMetrics.removed_count} (${deltaMetrics.reduction_rate})`);
  console.log(`  Downgraded: ${deltaMetrics.downgraded_count}`);
  console.log(`  Final output: ${deltaMetrics.filtered_count}`);
  console.log(`\nArtifacts saved to: ${OUTPUT_DIR}/\n`);
}

// Helper: Map Semgrep severity to internal format
function mapSeverity(semgrepSeverity) {
  const map = {
    'ERROR': 'HIGH',
    'WARNING': 'MEDIUM',
    'INFO': 'LOW'
  };
  return map[semgrepSeverity] || semgrepSeverity || 'MEDIUM';
}

// Helper: Extract CWE from Semgrep metadata
function extractCWE(finding) {
  const metadata = finding.extra?.metadata || {};
  if (metadata.cwe) {
    return Array.isArray(metadata.cwe) ? metadata.cwe[0] : metadata.cwe;
  }
  const ruleId = finding.check_id || '';
  if (ruleId.includes('sqli')) return 'CWE-89';
  if (ruleId.includes('xss')) return 'CWE-79';
  if (ruleId.includes('path-traversal')) return 'CWE-22';
  if (ruleId.includes('command-injection')) return 'CWE-78';
  return 'CWE-1';
}

// Helper: Guess filter reason
function guessFilterReason(finding, filterReasons) {
  const file = finding.file.toLowerCase();
  
  if (file.includes('/test/') || file.includes('.test.')) return 'test file';
  if (file.includes('/example/') || file.includes('.example.')) return 'example code';
  if (file.includes('/dist/') || file.includes('/build/')) return 'build artifact';
  if (file.includes('node_modules')) return 'build artifact';
  
  const topReason = Object.entries(filterReasons)
    .sort((a, b) => b[1] - a[1])[0];
  
  return topReason ? topReason[0] : 'filtered';
}

// Helper: Generate summary
function generateSummary(repoName, metrics, stats) {
  return `# Experiment 3 — Contextual Filter Effectiveness

## Repository
${repoName}

## Objective
Demonstrate measurable noise reduction through contextual filtering of static analysis findings.

## Methodology
1. Run Semgrep with default ruleset (\`--config auto\`)
2. Apply contextual filter with production configuration

## Results

### Quantitative Metrics
| Metric | Value |
|--------|-------|
| Raw findings | ${metrics.raw_count} |
| Filtered out | ${metrics.removed_count} |
| Downgraded | ${metrics.downgraded_count} |
| Final output | ${metrics.filtered_count} |
| **Reduction rate** | **${metrics.reduction_rate}** |

### Filter Breakdown
${Object.entries(stats.filterReasons || {})
  .sort((a, b) => b[1] - a[1])
  .map(([reason, count]) => `- ${reason}: ${count}`)
  .join('\n')}

## Interpretation

The contextual filter reduced noise by ${metrics.reduction_rate}, removing ${metrics.removed_count} findings that are not production-relevant.

---
*Generated: ${metrics.timestamp}*
`;
}

// Main execution
if (require.main === module) {
  const args = process.argv.slice(2);
  
  if (args.length < 1) {
    console.error('Usage: node run_filter_experiment.js <repo-path> [repo-name]');
    process.exit(1);
  }
  
  const repoPath = path.resolve(args[0]);
  const repoName = args[1] || path.basename(repoPath);
  
  if (!fs.existsSync(repoPath)) {
    console.error(`Error: Repository not found at ${repoPath}`);
    process.exit(1);
  }
  
  runFilterExperiment(repoPath, repoName).catch(error => {
    console.error('Error:', error.message);
    process.exit(1);
  });
}
