const RepoContextCollector = require('../../src/contextInference/collectors/repoContextCollector');
const path = require('path');

async function debug() {
  const repos = ['juice-shop', 'WebGoat', 'spring-petclinic', 'semgrep-backend'];
  const collector = new RepoContextCollector();
  
  for (const repo of repos) {
    const repoPath = path.join(__dirname, '..', '..', '..', repo);
    console.log(`\n=== ${repo} ===`);
    console.log(`Path: ${repoPath}`);
    
    try {
      const context = await collector.collectRepoContext(repoPath);
      console.log('Raw context:', JSON.stringify(context, null, 2));
      
      // Translate to our expected format
      console.log('\nTranslated:');
      console.log('  internet_facing:', context.internetFacing?.value || false);
      console.log('  handles_pii:', context.handlesPI?.value || false);
      console.log('  prod_signals:', context.production?.value || false);
      console.log('  test_only:', false);
      
    } catch (error) {
      console.log('Error:', error.message);
    }
  }
}

debug().catch(console.error);
