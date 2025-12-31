const path = require('path');
const fs = require('fs').promises;
const ContextInferenceSystem = require('../../src/contextInference/index');

async function scanRepoForContext(repoPath, repoName) {
  const contextSystem = new ContextInferenceSystem();
  const results = {
    hasRoutes: false,
    hasPII: false,
    hasProduction: false
  };
  
  try {
    // Get repo-level context
    const repoContext = await contextSystem.repoCollector.collectRepoContext(repoPath);
    results.hasProduction = repoContext.production?.value || false;
    
    // Sample some source files to detect routes/PII
    const filesToCheck = await findSourceFiles(repoPath, repoName);
    
    for (const file of filesToCheck.slice(0, 20)) { // Check first 20 files
      try {
        const content = await fs.readFile(file, 'utf-8');
        const finding = { file };
        
        const language = contextSystem.detectLanguage(file);
        if (!language) continue;
        
        const detector = contextSystem.detectors[language];
        if (!detector) continue;
        
        // Check for routes
        const routeResult = await detector.detectRoutes(content, finding);
        if (routeResult.detected) results.hasRoutes = true;
        
        // Check for PII
        const piiResult = await detector.detectPII(content, finding);
        if (piiResult.detected) results.hasPII = true;
        
        if (results.hasRoutes && results.hasPII && results.hasProduction) {
          break; // Found everything
        }
      } catch (err) {
        // Skip files that can't be read
      }
    }
    
  } catch (error) {
    console.log(`  Error: ${error.message}`);
  }
  
  return results;
}

async function findSourceFiles(repoPath, repoName) {
  const files = [];
  const extensions = ['.java', '.js', '.ts', '.py'];
  
  // Repo-specific paths
  const searchPaths = {
    'juice-shop': ['routes', 'models', 'lib'],
    'WebGoat': ['src/main/java'],
    'spring-petclinic': ['src/main/java'],
    'semgrep-backend': ['src']
  };
  
  const paths = searchPaths[repoName] || ['src'];
  
  for (const p of paths) {
    const fullPath = path.join(repoPath, p);
    try {
      const found = await walkDir(fullPath, extensions);
      files.push(...found);
    } catch (err) {
      // Path doesn't exist
    }
  }
  
  return files;
}

async function walkDir(dir, extensions) {
  const files = [];
  try {
    const entries = await fs.readdir(dir, { withFileTypes: true });
    
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      
      if (entry.isDirectory()) {
        const nested = await walkDir(fullPath, extensions);
        files.push(...nested);
      } else if (extensions.some(ext => entry.name.endsWith(ext))) {
        files.push(fullPath);
      }
    }
  } catch (err) {
    // Skip unreadable directories
  }
  
  return files;
}

async function main() {
  const expected = {
    'juice-shop': { internet_facing: true, handles_pii: true, prod_signals: true },
    'WebGoat': { internet_facing: true, handles_pii: false, prod_signals: true },
    'spring-petclinic': { internet_facing: true, handles_pii: true, prod_signals: false },
    'semgrep-backend': { internet_facing: false, handles_pii: false, prod_signals: false }
  };
  
  console.log('=== REPO-LEVEL CONTEXT VALIDATION ===\n');
  
  let correct = 0;
  let total = 0;
  
  for (const [repo, expectedCtx] of Object.entries(expected)) {
    const repoPath = path.join(__dirname, '..', '..', '..', repo);
    
    console.log(`Testing: ${repo}`);
    
    const detected = await scanRepoForContext(repoPath, repo);
    
    const checks = [
      ['internet_facing', detected.hasRoutes, expectedCtx.internet_facing],
      ['handles_pii', detected.hasPII, expectedCtx.handles_pii],
      ['prod_signals', detected.hasProduction, expectedCtx.prod_signals]
    ];
    
    for (const [attr, got, expected] of checks) {
      const match = got === expected;
      total++;
      if (match) correct++;
      
      const symbol = match ? '✅' : '❌';
      console.log(`  ${symbol} ${attr}: expected=${expected}, got=${got}`);
    }
    
    console.log('');
  }
  
  const accuracy = (correct / total * 100).toFixed(1);
  console.log(`\n=== SUMMARY ===`);
  console.log(`Accuracy: ${correct}/${total} (${accuracy}%)`);
}

main().catch(console.error);
