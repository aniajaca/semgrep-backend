#!/usr/bin/env node
// calculate-metrics.js - Calculate filter validation metrics

const fs = require('fs');
const path = require('path');

console.log('════════════════════════════════════════════════════');
console.log('  Filter Validation Metrics Calculator');
console.log('════════════════════════════════════════════════════\n');

// Parse labeled CSV files
function parseCSV(filepath) {
  const content = fs.readFileSync(filepath, 'utf8');
  const lines = content.trim().split('\n');
  const headers = lines[0].split(',');
  
  const findings = [];
  for (let i = 1; i < lines.length; i++) {
    // Simple CSV parse (handles quotes)
    const values = lines[i].match(/(".*?"|[^,]+)(?=\s*,|\s*$)/g) || [];
    const row = {};
    headers.forEach((header, idx) => {
      row[header] = values[idx] ? values[idx].replace(/^"|"$/g, '') : '';
    });
    findings.push(row);
  }
  
  return findings;
}

// Calculate metrics for a single repository
function calculateRepoMetrics(repo, labeledPath) {
  console.log(`\n📊 ${repo.toUpperCase()}`);
  console.log('─'.repeat(50));
  
  if (!fs.existsSync(labeledPath)) {
    console.log('  ⚠️  No labeled file found');
    return null;
  }
  
  const findings = parseCSV(labeledPath);
  
  // Separate by status (removed vs retained)
  const removed = findings.filter(f => f.status === 'removed');
  const retained = findings.filter(f => f.status === 'retained');
  
  console.log(`  Total findings: ${findings.length}`);
  console.log(`    Removed: ${removed.length}`);
  console.log(`    Retained: ${retained.length}`);
  
  // Count labels in removed findings
  const removedByLabel = {
    NON_ACTIONABLE: removed.filter(f => f.label === 'NON_ACTIONABLE').length,
    ACTIONABLE: removed.filter(f => f.label === 'ACTIONABLE').length,
    UNCERTAIN: removed.filter(f => f.label === 'UNCERTAIN').length
  };
  
  console.log(`\n  Removed findings breakdown:`);
  console.log(`    NON_ACTIONABLE: ${removedByLabel.NON_ACTIONABLE}`);
  console.log(`    ACTIONABLE: ${removedByLabel.ACTIONABLE}`);
  console.log(`    UNCERTAIN: ${removedByLabel.UNCERTAIN}`);
  
  // Calculate Removal Precision (RP)
  // RP = (NON_ACTIONABLE removed) / (total removed)
  const rp = removed.length > 0 
    ? (removedByLabel.NON_ACTIONABLE / removed.length) * 100 
    : 0;
  
  // Calculate Actionable Loss Rate (ALR)
  // ALR = (ACTIONABLE removed) / (total removed)
  const alr = removed.length > 0
    ? (removedByLabel.ACTIONABLE / removed.length) * 100
    : 0;
  
  // Check for critical losses
  const criticalRemoved = removed.filter(f => 
    f.label === 'ACTIONABLE' && 
    (f.severity === 'HIGH' || f.severity === 'CRITICAL')
  );
  
  console.log(`\n  📈 Metrics:`);
  console.log(`    Removal Precision (RP): ${rp.toFixed(1)}% (target: ≥90%)`);
  console.log(`    Actionable Loss Rate (ALR): ${alr.toFixed(1)}% (target: ≤5%)`);
  console.log(`    Critical Loss: ${criticalRemoved.length} findings (target: 0)`);
  
  // Pass/Fail
  const rpPass = rp >= 90;
  const alrPass = alr <= 5;
  const criticalPass = criticalRemoved.length === 0;
  
  console.log(`\n  ✅/❌ Status:`);
  console.log(`    ${rpPass ? '✅' : '❌'} Removal Precision: ${rpPass ? 'PASS' : 'FAIL'}`);
  console.log(`    ${alrPass ? '✅' : '❌'} Actionable Loss Rate: ${alrPass ? 'PASS' : 'FAIL'}`);
  console.log(`    ${criticalPass ? '✅' : '❌'} Critical Loss: ${criticalPass ? 'PASS' : 'FAIL'}`);
  
  if (criticalRemoved.length > 0) {
    console.log(`\n  ⚠️  Critical findings removed:`);
    criticalRemoved.forEach(f => {
      console.log(`    - ${f.file}:${f.line} [${f.severity}] ${f.ruleId}`);
    });
  }
  
  return {
    repo,
    totalFindings: findings.length,
    removed: removed.length,
    retained: retained.length,
    removedByLabel,
    rp,
    alr,
    criticalLoss: criticalRemoved.length,
    criticalLossDetails: criticalRemoved.map(f => ({
      file: f.file,
      line: f.line,
      severity: f.severity,
      ruleId: f.ruleId
    })),
    passed: rpPass && alrPass && criticalPass
  };
}

// Main execution
const repos = ['semgrep-backend', 'express', 'lodash'];
const results = {};

for (const repo of repos) {
  const labeledPath = `validation/samples/${repo}_sample_labeled.csv`;
  results[repo] = calculateRepoMetrics(repo, labeledPath);
}

// Aggregate metrics
console.log('\n\n════════════════════════════════════════════════════');
console.log('  📊 AGGREGATE METRICS');
console.log('════════════════════════════════════════════════════\n');

const validRepos = Object.values(results).filter(r => r !== null);

if (validRepos.length === 0) {
  console.log('❌ No valid results found');
  process.exit(1);
}

const totalRemoved = validRepos.reduce((sum, r) => sum + r.removed, 0);
const totalNonActionableRemoved = validRepos.reduce((sum, r) => sum + r.removedByLabel.NON_ACTIONABLE, 0);
const totalActionableRemoved = validRepos.reduce((sum, r) => sum + r.removedByLabel.ACTIONABLE, 0);
const totalCriticalLoss = validRepos.reduce((sum, r) => sum + r.criticalLoss, 0);

const aggregateRP = totalRemoved > 0 ? (totalNonActionableRemoved / totalRemoved) * 100 : 0;
const aggregateALR = totalRemoved > 0 ? (totalActionableRemoved / totalRemoved) * 100 : 0;

console.log(`Total findings removed: ${totalRemoved}`);
console.log(`  NON_ACTIONABLE: ${totalNonActionableRemoved}`);
console.log(`  ACTIONABLE: ${totalActionableRemoved}`);
console.log(`\nAggregate Metrics:`);
console.log(`  Removal Precision (RP): ${aggregateRP.toFixed(1)}%`);
console.log(`  Actionable Loss Rate (ALR): ${aggregateALR.toFixed(1)}%`);
console.log(`  Critical Loss: ${totalCriticalLoss}`);

const aggregatePass = aggregateRP >= 90 && aggregateALR <= 5 && totalCriticalLoss === 0;

console.log(`\n${aggregatePass ? '✅' : '❌'} Overall Status: ${aggregatePass ? 'PASS' : 'FAIL'}`);

// Save results
const output = {
  timestamp: new Date().toISOString(),
  perRepository: results,
  aggregate: {
    totalRemoved,
    totalNonActionableRemoved,
    totalActionableRemoved,
    totalCriticalLoss,
    removalPrecision: aggregateRP,
    actionableLossRate: aggregateALR,
    passed: aggregatePass
  },
  thresholds: {
    removalPrecision: 90,
    actionableLossRate: 5,
    criticalLoss: 0
  }
};

const outputPath = 'validation/reports/metrics_summary.json';
fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, JSON.stringify(output, null, 2));

console.log(`\n📄 Results saved to: ${outputPath}`);

console.log('\n════════════════════════════════════════════════════');
console.log('  🎓 THESIS SUMMARY');
console.log('════════════════════════════════════════════════════\n');

console.log('Key findings for your thesis:');
console.log(`  • Filter evaluated on ${validRepos.length} real-world repositories`);
console.log(`  • Removal Precision: ${aggregateRP.toFixed(1)}% (demonstrates accurate noise detection)`);
console.log(`  • Actionable Loss Rate: ${aggregateALR.toFixed(1)}% (demonstrates production code preservation)`);
console.log(`  • Critical Loss: ${totalCriticalLoss} (demonstrates safety)`);

if (aggregatePass) {
  console.log(`\n✅ Filter validation PASSED all acceptance criteria!`);
} else {
  console.log(`\n⚠️  Filter validation did not meet all criteria. Review results above.`);
}

console.log('');