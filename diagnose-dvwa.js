const dast = require('./src/dast');
const crawler = require('./src/dast/crawler');

async function diagnose() {
  console.log('🔍 Diagnosing DVWA forms...\n');
  
  try {
    // Scan the main page
    const result1 = await crawler.quickScan('http://localhost:8080');
    console.log('Main page (http://localhost:8080):');
    console.log('Forms found:', result1.forms.length);
    result1.forms.forEach((form, i) => {
      console.log(`\nForm ${i + 1}:`);
      console.log('  Action:', form.action);
      console.log('  Method:', form.method);
      console.log('  Inputs:');
      form.inputs.forEach(input => {
        console.log(`    - ${input.name} (${input.type})`);
      });
    });
    
    // Try the SQLi page
    console.log('\n' + '='.repeat(60));
    const result2 = await crawler.quickScan('http://localhost:8080/vulnerabilities/sqli/');
    console.log('\nSQLi page (http://localhost:8080/vulnerabilities/sqli/):');
    console.log('Forms found:', result2.forms.length);
    result2.forms.forEach((form, i) => {
      console.log(`\nForm ${i + 1}:`);
      console.log('  Action:', form.action);
      console.log('  Method:', form.method);
      console.log('  Inputs:');
      form.inputs.forEach(input => {
        console.log(`    - ${input.name} (${input.type})`);
      });
    });
    
  } catch (error) {
    console.error('Error:', error.message);
  }
}

diagnose();
