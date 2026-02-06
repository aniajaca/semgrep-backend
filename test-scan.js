const dast = require('./src/dast');

dast.quickScan('http://localhost:8080')
  .then(result => {
    console.log('\n📊 RESULTS:');
    console.log('Status:', result.status);
    console.log('Duration:', result.metadata.durationMs + 'ms');
    console.log('Forms found:', result.metadata.formsFound);
    console.log('Findings:', result.findings.length);
    
    if (result.error) {
      console.log('\n❌ Error:', result.error);
    }
    
    if (result.findings.length > 0) {
      console.log('\n🚨 VULNERABILITIES:\n');
      result.findings.forEach((f, i) => {
        console.log(`[${i+1}] ${f.severity} - ${f.message}`);
        console.log('    CWE:', f.metadata.cwe);
        console.log('    Parameter:', f.metadata.parameter);
        console.log('    Confidence:', (f.confidence * 100).toFixed(0) + '%\n');
      });
    }
    
    console.log('✅ Test complete!\n');
  })
  .catch(err => {
    console.error('❌ Caught error:', err.message);
    console.error(err.stack);
  });
