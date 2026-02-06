const axios = require('axios');

async function testAPI() {
  console.log('🧪 Testing DAST API Endpoint...\n');

  const payload = {
    targetUrl: 'http://localhost:8080/vulnerabilities/sqli/',
    cookies: {
      PHPSESSID: 'lb697jksj4r3n6d6cdq33sh0s3',
      security: 'low'
    }
  };

  try {
    // Assuming server runs on port 3000
    const response = await axios.post('http://localhost:3000/v1/scan-dast', payload, {
      timeout: 30000
    });

    console.log('📊 API Response:');
    console.log('Status:', response.data.status);
    console.log('Scan ID:', response.data.scanId);
    console.log('Findings:', response.data.summary.totalFindings);
    console.log('Critical:', response.data.summary.criticalFindings);
    
    if (response.data.findings.length > 0) {
      console.log('\n🚨 Vulnerabilities:');
      response.data.findings.forEach((f, i) => {
        console.log(`[${i+1}] ${f.severity} - ${f.message}`);
      });
    }

    console.log('\n✅ API Test Passed!\n');
  } catch (error) {
    if (error.code === 'ECONNREFUSED') {
      console.log('⚠️  Server not running. To test:');
      console.log('1. Add DAST route to your main server.js');
      console.log('2. Start server: node server.js');
      console.log('3. Run: node test-dast-api.js\n');
    } else {
      console.error('❌ Error:', error.message);
    }
  }
}

testAPI();
