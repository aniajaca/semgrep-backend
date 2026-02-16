const dast = require('./src/dast');
dast.quickScan('http://localhost:8080')
  .then(result => {
    console.log('Status:', result.status);
    if (result.error) {
      console.log('ERROR MESSAGE:', result.error);
    }
    console.log('Findings:', result.findings.length);
  })
  .catch(err => {
    console.error('Caught error:', err.message);
    console.error(err.stack);
  });
