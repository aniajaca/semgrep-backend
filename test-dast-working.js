// Clear require cache
delete require.cache[require.resolve('./src/dast')];
delete require.cache[require.resolve('./src/dast/crawler')];

const dast = require('./src/dast');

async function testScan() {
  console.log('🧪 Testing DAST on DVWA...\n');
  
  try {
    const result = await dast.quickScan('http://localhost:8080');
    
    console.log('\n📊 SCAN RESULTS:');
    console.log('Status:', result.status);
    console.log('Duration:', result.metadata.durationMs + 'ms');
    console.log('Forms found:', result.metadata.formsFound);
    console.log('Findings:', result.findings.length);
    
    if (result.findings.length > 0) {
      console.log('\n🚨 VULNERABILITIES:');
      result.findings.forEach((f, i) => {
        console.log(`\n[${i+1}] ${f.severity} - ${f.message}`);
        console.log('    Parameter:', f.metadata.parameter);
        console.log('    CWE:', f.metadata.cwe);
        console.log('    Confidence:', (f.confidence * 100).toFixed(0) + '%');
      });
    }
    
    console.log('\n✅ Test complete!\n');
    
  } catch (error) {
    console.error('❌ Error:', error.message);
    console.error(error.stack);
    process.exit(1);
  }
}

testScan();