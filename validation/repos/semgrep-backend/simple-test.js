const dast = require('./src/dast');

dast.quickScan('http://localhost:8080')
  .then(result => {
    console.log('Status:', result.status);
    console.log('Findings:', result.findings.length);
    if (result.findings.length > 0) {
      result.findings.forEach((f, i) => {
        console.log(`[${i+1}] ${f.severity} - ${f.message}`);
      });
    }
  })
  .catch(err => console.error('Error:', err.message));