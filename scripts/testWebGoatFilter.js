const fs = require('fs');
const path = require('path');
const EnhancedContextualFilter = require('../src/contextInference/contextualFilter');

async function test() {
  const raw = require('../webgoat_baseline.json');
  
  // Normalize
  const normalized = raw.results.map(r => ({
    engine: 'semgrep',
    ruleId: r.check_id,
    category: r.extra?.metadata?.category || 'security',
    severity: r.extra?.severity || 'WARNING',
    message: r.extra?.message || r.message,
    cwe: r.extra?.metadata?.cwe || [],
    owasp: r.extra?.metadata?.owasp || [],
    file: r.path,
    startLine: r.start?.line || 0,
    endLine: r.end?.line || 0,
    startColumn: r.start?.col || 0,
    endColumn: r.end?.col || 0,
    snippet: r.extra?.lines || '',
    confidence: 'MEDIUM',
    impact: 'MEDIUM',
    likelihood: 'MEDIUM'
  }));
  
  console.log('=== WEBGOAT CONTEXTUAL FILTER TEST ===');
  console.log('Baseline findings:', normalized.length);
  
  const filter = new EnhancedContextualFilter({
    filterTestFiles: true,
    filterExampleCode: true,
    filterBuildArtifacts: true,
    filterInjectionWithoutInput: true,
    detectSanitization: true,
    benchmarkMode: false,
    verbose: true
  });
  
  const webgoatPath = path.join(__dirname, '..', '..', 'WebGoat');
  const filtered = await filter.filterFindings(normalized, webgoatPath);
  
  console.log('\nAfter filter:', filtered.length);
  console.log('Reduction:', (normalized.length - filtered.length), 
    '(' + ((normalized.length - filtered.length) / normalized.length * 100).toFixed(1) + '%)');
  
  fs.writeFileSync(path.join(__dirname, '..', 'webgoat_filtered.json'), 
    JSON.stringify({results: filtered}, null, 2));
  console.log('\n✓ Saved to webgoat_filtered.json');
}

test().catch(console.error);
