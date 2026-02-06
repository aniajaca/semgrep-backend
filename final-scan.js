delete require.cache[require.resolve('./src/dast')];
const dast = require('./src/dast');

const cookies = {
  PHPSESSID: 'lb697jksj4r3n6d6cdq33sh0s3',
  security: 'low'
};

dast.quickScan('http://localhost:8080/vulnerabilities/sqli/', { cookies })
  .then(result => {
    console.log('\n' + '='.repeat(70));
    console.log('🎯 DAST SCAN RESULTS');
    console.log('='.repeat(70));
    console.log('Status:', result.status);
    console.log('Forms found:', result.metadata.formsFound);
    console.log('Findings:', result.findings.length);
    
    if (result.findings.length > 0) {
      console.log('\n' + '🚨 SQL INJECTION DETECTED! 🚨'.padStart(50));
      console.log('='.repeat(70));
      result.findings.forEach((f, i) => {
        console.log(`\n[${i+1}] ${f.severity} - ${f.message}`);
        console.log('    CWE:', f.metadata.cwe);
        console.log('    OWASP:', f.metadata.owasp);
        console.log('    Parameter:', f.metadata.parameter);
        console.log('    Payload:', f.metadata.testPayload);
        console.log('    Evidence:', f.metadata.evidence);
      });
      console.log('\n' + '='.repeat(70));
      console.log('✅ SUCCESS! DAST WORKS! THESIS VALIDATED! 🎓🎉');
      console.log('='.repeat(70) + '\n');
    }
  });
