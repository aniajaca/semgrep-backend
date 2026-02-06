const dast = require('./src/dast');

// REPLACE WITH YOUR ACTUAL COOKIES
const PHPSESSID = 'YOUR_PHPSESSID_HERE';
const SECURITY = 'low';

console.log('🧪 Scanning DVWA with authentication...\n');

const cookies = {
  PHPSESSID: PHPSESSID,
  security: SECURITY
};

dast.quickScan('http://localhost:8080/vulnerabilities/sqli/', { cookies })
  .then(result => {
    console.log('\n📊 RESULTS:');
    console.log('Status:', result.status);
    console.log('Authenticated:', result.metadata.authenticated);
    console.log('Forms found:', result.metadata.formsFound);
    console.log('Findings:', result.findings.length);
    
    if (result.findings.length > 0) {
      console.log('\n🚨 SQL INJECTION DETECTED!\n');
      result.findings.forEach((f, i) => {
        console.log(`[${i+1}] ${f.severity} - ${f.message}`);
        console.log('    CWE:', f.metadata.cwe);
        console.log('    Parameter:', f.metadata.parameter);
        console.log('    Payload:', f.metadata.testPayload, '\n');
      });
      console.log('✅ SUCCESS! DAST detected SQLi in authenticated DVWA page! 🎉\n');
    } else {
      console.log('\n⚠️  No vulnerabilities detected\n');
    }
  })
  .catch(err => {
    console.error('❌ Error:', err.message);
  });
