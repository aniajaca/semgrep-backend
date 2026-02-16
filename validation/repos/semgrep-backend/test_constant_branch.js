const { runSemgrep } = require('./src/semgrepAdapter');
const EnhancedContextualFilter = require('./src/contextInference/contextualFilter');
const fs = require('fs');

async function test() {
  console.log('=== Testing Constant Branch Detector ===\n');
  
  const filter = new EnhancedContextualFilter({
    verbose: true,
    benchmarkMode: false
  });
  
  const targetPath = 'BenchmarkJava/src/main/java/org/owasp/benchmark/testcode';
  
  console.log('Step 1: Running Semgrep scan...');
  const rawFindings = await runSemgrep(targetPath, {
    languages: ['java'],
    severity: 'ERROR,WARNING'
  });
  console.log(`Raw findings: ${rawFindings.length}\n`);
  
  console.log('Step 2: Applying contextual filter with constant branch detection...');
  const filteredFindings = await filter.filterFindings(rawFindings, process.cwd());
  
  console.log('\n=== RESULTS ===');
  console.log(`Total findings: ${rawFindings.length}`);
  console.log(`After filter: ${filteredFindings.length}`);
  console.log(`Filtered: ${rawFindings.length - filteredFindings.length}`);
  
  const stats = filter.getStats();
  console.log('\nFilter stats:', stats);
  
  // Save to file
  fs.writeFileSync('/tmp/owasp-constant-branch.json', JSON.stringify({
    findings: filteredFindings,
    stats: stats
  }, null, 2));
  
  console.log('\n✓ Saved to /tmp/owasp-constant-branch.json');
}

test().catch(console.error);
