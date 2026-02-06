const dast = require('./src/dast');

console.log('🧪 Scanning DVWA SQLi page with authentication...\n');

const cookies = {
  PHPSESSID: 'lforop4bmja8onpsut6kjk8655',
  security: 'low'
};

dast.quickScan('http://localhost:8080/vulnerabilities/sqli/', { cookies })
  .then(result => {
    console.log('\n📊 SCAN RESULTS:');
    console.log('Status:', result.status);
    console.log('Authenticated:', result.metadata.authenticated);
    console.log('Forms found:', result.metadata.formsFound);
    console.log('Findings:', result.findings.length);
    
    if (result.findings.length > 0) {
      console.log('\n�� SQL INJECTION DETECTED!\n');
      result.findings.forEach((f, i) => {
        console.log(`[${i+1}] ${f.severity} - ${f.message}`);
        console.log('    CWE:', f.metadata.cwe);
        console.log('    OWASP:', f.metadata.owasp);
        console.log('    Parameter:', f.metadata.parameter);
        console.log('    Payload:', f.metadata.testPayload);
        console.log('    Evidence:', f.metadata.evidence.substring(0, 100) + '...\n');
      });
      console.log('✅ SUCCESS! DAST works! 🎉\n');
    } else {
      console.log('\n⚠️  No vulnerabilities found\n');
    }
    
    process.exit(0);
  })
  .catch(err => {
    console.error('❌ Error:', err.message);
    console.error(err.stack);
    process.exit(1);
  });
