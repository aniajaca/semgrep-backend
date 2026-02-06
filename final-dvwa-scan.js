// Force fresh module load
delete require.cache[require.resolve('./src/dast')];
delete require.cache[require.resolve('./src/dast/crawler')];
delete require.cache[require.resolve('./src/dast/probes/sqlInjection')];

const dast = require('./src/dast');

console.log('🎯 FINAL DAST SCAN - DVWA SQLi with Authentication\n');

const cookies = {
  PHPSESSID: 'lforop4bmja8onpsut6kjk8655',
  security: 'low'
};

dast.quickScan('http://localhost:8080/vulnerabilities/sqli/', { cookies })
  .then(result => {
    console.log('\n' + '='.repeat(60));
    console.log('📊 SCAN RESULTS');
    console.log('='.repeat(60));
    console.log('Status:', result.status);
    console.log('Authenticated:', result.metadata.authenticated);
    console.log('Forms found:', result.metadata.formsFound);
    console.log('Findings:', result.findings.length);
    
    if (result.findings.length > 0) {
      console.log('\n' + '🚨 VULNERABILITY DETECTED! 🚨'.padStart(40));
      console.log('='.repeat(60) + '\n');
      result.findings.forEach((f, i) => {
        console.log(`[${i+1}] ${f.severity} - ${f.message}`);
        console.log('    CWE:', f.metadata.cwe);
        console.log('    OWASP:', f.metadata.owasp);
        console.log('    Parameter:', f.metadata.parameter);
        console.log('    Method:', f.metadata.detectionMethod);
        console.log('    Payload:', f.metadata.testPayload);
        console.log('    Evidence:', f.metadata.evidence.substring(0, 150) + '...\n');
      });
      console.log('='.repeat(60));
      console.log('✅ SUCCESS! DAST DETECTED SQL INJECTION! 🎉');
      console.log('='.repeat(60) + '\n');
    } else {
      console.log('\n⚠️  No vulnerabilities detected');
      console.log('This might mean:');
      console.log('1. The baseline/diff check filtered it out');
      console.log('2. The session expired');
      console.log('3. DVWA is not responding with SQL errors\n');
    }
    
    process.exit(0);
  })
  .catch(err => {
    console.error('\n❌ SCAN FAILED:', err.message);
    console.error(err.stack);
    process.exit(1);
  });
