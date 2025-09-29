
const axios = require('axios');

async function runDemo() {

  const API = 'http://localhost:3000';

  

  console.log('Neperia Security Scanner Demo\n');

  

  // Vulnerable code example

  const vulnCode = `

    app.post('/login', (req, res) => {

      const { username, password } = req.body;

      const query = \`SELECT * FROM users WHERE username = '\${username}' AND password = '\${password}'\`;

      db.query(query, (err, results) => {

        if (results.length > 0) {

          const token = "hardcoded-jwt-secret";

          res.json({ token });

        }

      });

    });

  `;

  

  const scan = await axios.post(`${API}/scan-code`, {

    code: vulnCode,

    language: 'javascript',

    manualContext: {

      production: true,

      internetFacing: true

    }

  });

  

  console.log('Scan Results:');

  console.log(`Total Issues: ${scan.data.findings.length}`);

  console.log(`Engine Used: ${scan.data.engine}`);

  scan.data.findings.forEach((f, i) => {

    console.log(`\n${i+1}. [${f.severity}] ${f.message}`);

    console.log(`   CWE: ${f.cwe}`);

    console.log(`   Line: ${f.startLine}`);

  });

}

runDemo().catch(console.error);

