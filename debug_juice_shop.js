const RepoContextCollector = require('./src/contextInference/collectors/repoContextCollector');
const path = require('path');

async function debugJuiceShop() {
  const collector = new RepoContextCollector({ verbose: true });
  const repoPath = path.join(__dirname, '..', 'juice-shop');
  
  console.log('🔍 Checking Juice Shop...\n');
  console.log('Repo path:', repoPath);
  
  // Get the files it samples
  const files = await collector.listSourceFiles(repoPath, 200);
  
  console.log(`\n📁 Sampled ${files.length} files total`);
  
  console.log('\n🎯 Route files found:');
  const routeFiles = files.filter(f => f.includes('route'));
  console.log(`  Total route files: ${routeFiles.length}`);
  if (routeFiles.length > 0) {
    console.log('  First 10 route files:');
    routeFiles.slice(0, 10).forEach(f => console.log(`    - ${path.basename(f)}`));
  }
  
  console.log('\n📊 File extensions:');
  const exts = {};
  files.forEach(f => {
    const ext = path.extname(f);
    exts[ext] = (exts[ext] || 0) + 1;
  });
  console.log(exts);
  
  console.log('\n📂 Top directories sampled:');
  const dirs = {};
  files.forEach(f => {
    const dir = path.dirname(f).split('/').slice(-2).join('/');
    dirs[dir] = (dirs[dir] || 0) + 1;
  });
  Object.entries(dirs)
    .sort((a,b) => b[1] - a[1])
    .slice(0, 10)
    .forEach(([dir, count]) => {
      console.log(`  ${dir}: ${count} files`);
    });
  
  // Now test the actual detection
  console.log('\n🧪 Testing detectPublicAPI on a route file...');
  const JSDetector = require('./src/contextInference/detectors/jsDetector');
  const fs = require('fs').promises;
  
  if (routeFiles.length > 0) {
    const testFile = routeFiles[0];
    const content = await fs.readFile(testFile, 'utf-8');
    const detector = new JSDetector();
    const result = await detector.detectPublicAPI(content);
    
    console.log(`  File: ${path.basename(testFile)}`);
    console.log(`  Detected: ${result.detected}`);
    console.log(`  Confidence: ${result.confidence}`);
    console.log(`  Route count: ${result.metadata?.routeCount || 0}`);
    console.log(`  Evidence:`, result.evidence);
  }
}

debugJuiceShop().catch(console.error);
