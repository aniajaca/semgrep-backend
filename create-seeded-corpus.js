#!/usr/bin/env node
// create-seeded-corpus.js - Generate seeded vulnerability test files
// Usage: node create-seeded-corpus.js --output=./seeded_vulnerabilities

const fs = require('fs');
const path = require('path');
const minimist = require('minimist');

const vulnerabilities = [
  // SQL Injection (3 files)
  {
    file: 'src/api/users.js',
    type: 'sqli',
    cwe: 'CWE-89',
    severity: 'high',
    description: 'User input directly concatenated into SQL query',
    code: `// Seeded Vulnerability: SQL Injection
const express = require('express');
const db = require('../../lib/db');

const router = express.Router();

// VULNERABILITY: SQL Injection
router.get('/search', async (req, res) => {
  const username = req.query.username; // User input
  const query = \`SELECT * FROM users WHERE username = '\${username}'\`; // Vulnerable!
  const results = await db.query(query);
  res.json(results);
});

module.exports = router;
`
  },
  {
    file: 'lib/db-query.js',
    type: 'sqli',
    cwe: 'CWE-89',
    severity: 'critical',
    description: 'Dynamic SQL with user input',
    code: `// Seeded Vulnerability: SQL Injection in utility function
const pg = require('pg');

class DatabaseQuery {
  async findByEmail(email) {
    // VULNERABILITY: Email parameter directly interpolated
    const sql = \`SELECT id, name FROM accounts WHERE email = '\${email}'\`;
    return await this.pool.query(sql);
  }
}

module.exports = DatabaseQuery;
`
  },
  {
    file: 'services/auth.js',
    type: 'sqli',
    cwe: 'CWE-89',
    severity: 'critical',
    description: 'Authentication bypass via SQL injection',
    code: `// Seeded Vulnerability: SQL Injection in authentication
const db = require('../lib/db');

async function login(username, password) {
  // VULNERABILITY: Both username and password interpolated unsafely
  const query = \`
    SELECT * FROM users 
    WHERE username = '\${username}' 
    AND password = '\${password}'
  \`;
  const result = await db.query(query);
  return result.rows[0];
}

module.exports = { login };
`
  },

  // XSS (3 files)
  {
    file: 'src/templates/render.js',
    type: 'xss',
    cwe: 'CWE-79',
    severity: 'high',
    description: 'Unescaped user input in HTML',
    code: `// Seeded Vulnerability: Cross-Site Scripting
function renderUserProfile(user) {
  // VULNERABILITY: User name directly interpolated into HTML
  return \`
    <div class="profile">
      <h1>Welcome, \${user.name}</h1>
      <p>Email: \${user.email}</p>
    </div>
  \`;
}

module.exports = { renderUserProfile };
`
  },
  {
    file: 'lib/html-builder.js',
    type: 'xss',
    cwe: 'CWE-79',
    severity: 'medium',
    description: 'DOM XSS via innerHTML',
    code: `// Seeded Vulnerability: DOM-based XSS
class HtmlBuilder {
  setTitle(title) {
    // VULNERABILITY: Direct innerHTML assignment
    document.getElementById('page-title').innerHTML = title;
  }
  
  renderComment(comment) {
    // VULNERABILITY: User comment rendered unsafely
    return \`<div class="comment">\${comment.text}</div>\`;
  }
}

module.exports = HtmlBuilder;
`
  },
  {
    file: 'src/api/messages.js',
    type: 'xss',
    cwe: 'CWE-79',
    severity: 'high',
    description: 'Reflected XSS in error messages',
    code: `// Seeded Vulnerability: Reflected XSS
const express = require('express');
const router = express.Router();

router.get('/error', (req, res) => {
  const errorMsg = req.query.msg;
  // VULNERABILITY: Error message reflected without encoding
  res.send(\`<html><body><h1>Error: \${errorMsg}</h1></body></html>\`);
});

module.exports = router;
`
  },

  // Command Injection (2 files)
  {
    file: 'src/utils/exec.js',
    type: 'cmdi',
    cwe: 'CWE-78',
    severity: 'critical',
    description: 'Shell command injection',
    code: `// Seeded Vulnerability: Command Injection
const { exec } = require('child_process');

function runDiagnostics(hostname) {
  // VULNERABILITY: User input in shell command
  exec(\`ping -c 4 \${hostname}\`, (error, stdout, stderr) => {
    console.log(stdout);
  });
}

module.exports = { runDiagnostics };
`
  },
  {
    file: 'services/deploy.js',
    type: 'cmdi',
    cwe: 'CWE-78',
    severity: 'critical',
    description: 'Command injection in deployment script',
    code: `// Seeded Vulnerability: Command Injection in deployment
const { execSync } = require('child_process');

function deployToServer(branch, server) {
  // VULNERABILITY: Branch name and server directly in command
  const cmd = \`git push \${server} \${branch}\`;
  execSync(cmd);
}

module.exports = { deployToServer };
`
  },

  // Path Traversal (3 files)
  {
    file: 'api/files.js',
    type: 'path-traversal',
    cwe: 'CWE-22',
    severity: 'high',
    description: 'Directory traversal in file download',
    code: `// Seeded Vulnerability: Path Traversal
const express = require('express');
const fs = require('fs');
const path = require('path');

const router = express.Router();

router.get('/download', (req, res) => {
  const filename = req.query.file;
  // VULNERABILITY: No path sanitization
  const filePath = path.join(__dirname, '../uploads/', filename);
  res.sendFile(filePath);
});

module.exports = router;
`
  },
  {
    file: 'lib/storage.js',
    type: 'path-traversal',
    cwe: 'CWE-22',
    severity: 'critical',
    description: 'Path traversal in file read',
    code: `// Seeded Vulnerability: Path Traversal in storage
const fs = require('fs');

class Storage {
  readFile(filename) {
    // VULNERABILITY: User-controlled path
    const content = fs.readFileSync(\`./data/\${filename}\`, 'utf8');
    return content;
  }
}

module.exports = Storage;
`
  },
  {
    file: 'services/upload.js',
    type: 'path-traversal',
    cwe: 'CWE-22',
    severity: 'high',
    description: 'Path traversal in file upload',
    code: `// Seeded Vulnerability: Path Traversal in upload
const fs = require('fs').promises;

async function saveUpload(filename, content) {
  // VULNERABILITY: Filename not validated
  await fs.writeFile(\`./uploads/\${filename}\`, content);
}

module.exports = { saveUpload };
`
  },

  // Hardcoded Secret (1 file)
  {
    file: 'src/config/keys.js',
    type: 'hardcoded-secret',
    cwe: 'CWE-798',
    severity: 'high',
    description: 'Hardcoded credentials',
    code: `// Seeded Vulnerability: Hardcoded Secret
module.exports = {
  // VULNERABILITY: Hardcoded database password
  dbPassword: 'SuperSecret123!',
  apiKey: 'sk-1234567890abcdef',
  jwtSecret: 'my-jwt-secret-key'
};
`
  },

  // Safe Control (1 file) - This should NOT trigger
  {
    file: 'src/utils/safe-validator.js',
    type: 'safe-control',
    cwe: 'N/A',
    severity: 'none',
    description: 'Safe validation function (negative control)',
    code: `// Safe Control File - No vulnerability
const validator = require('validator');

function validateEmail(email) {
  // SAFE: Using proper validation library
  return validator.isEmail(email);
}

function sanitizeInput(input) {
  // SAFE: Proper sanitization
  return input.trim().replace(/[<>]/g, '');
}

module.exports = { validateEmail, sanitizeInput };
`
  }
];

function createSeededCorpus(outputDir) {
  console.log('Creating seeded vulnerability corpus...');
  
  // Create directory structure
  const dirs = ['src/api', 'src/templates', 'src/utils', 'src/config', 'lib', 'services', 'api'];
  dirs.forEach(dir => {
    const fullPath = path.join(outputDir, dir);
    fs.mkdirSync(fullPath, { recursive: true });
  });
  
  // Create manifest
  const manifest = {
    created: new Date().toISOString(),
    description: 'Seeded vulnerability corpus for safety validation',
    totalVulnerabilities: vulnerabilities.filter(v => v.type !== 'safe-control').length,
    vulnerabilities: vulnerabilities.map((v, idx) => ({
      id: idx + 1,
      file: v.file,
      line: getVulnerableLine(v.code),
      type: v.type,
      cwe: v.cwe,
      severity: v.severity,
      description: v.description,
      expectedRuleId: getExpectedRuleId(v.type)
    }))
  };
  
  // Write manifest
  fs.writeFileSync(
    path.join(outputDir, 'manifest.json'),
    JSON.stringify(manifest, null, 2)
  );
  
  // Create vulnerability files
  let created = 0;
  vulnerabilities.forEach(vuln => {
    const filePath = path.join(outputDir, vuln.file);
    fs.writeFileSync(filePath, vuln.code);
    created++;
    console.log(`  ✓ Created ${vuln.file} (${vuln.type})`);
  });
  
  console.log('');
  console.log(`✓ Created ${created} files`);
  console.log(`✓ Manifest: ${path.join(outputDir, 'manifest.json')}`);
  console.log('');
  console.log('Vulnerability breakdown:');
  const counts = {};
  vulnerabilities.forEach(v => {
    counts[v.type] = (counts[v.type] || 0) + 1;
  });
  Object.entries(counts).forEach(([type, count]) => {
    console.log(`  ${type}: ${count} files`);
  });
  
  return manifest;
}

function getVulnerableLine(code) {
  // Find the line with "VULNERABILITY:" comment
  const lines = code.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].includes('VULNERABILITY:')) {
      return i + 2; // Return line after comment
    }
  }
  return 1;
}

function getExpectedRuleId(type) {
  const ruleMap = {
    'sqli': 'javascript.lang.security.audit.sqli',
    'xss': 'javascript.lang.security.audit.xss',
    'cmdi': 'javascript.lang.security.audit.child-process-exec-non-literal',
    'path-traversal': 'javascript.lang.security.audit.path-traversal',
    'hardcoded-secret': 'javascript.lang.security.detect-hardcoded-credentials',
    'safe-control': null
  };
  return ruleMap[type] || 'unknown';
}

// Main execution
if (require.main === module) {
  const args = minimist(process.argv.slice(2));
  
  if (!args.output) {
    console.error('Usage: node create-seeded-corpus.js --output=./seeded_vulnerabilities');
    process.exit(1);
  }
  
  try {
    createSeededCorpus(args.output);
    console.log('');
    console.log('✅ Seeded corpus created successfully!');
    console.log('');
    console.log('Next steps:');
    console.log('  1. Run scan without filter: npm run scan -- --target=./seeded_vulnerabilities --filter=OFF');
    console.log('  2. Run scan with filter:    npm run scan -- --target=./seeded_vulnerabilities --filter=ON');
    console.log('  3. Calculate SVR:           node calculate-svr.js --baseline=... --filtered=...');
  } catch (error) {
    console.error('Error:', error.message);
    process.exit(1);
  }
}

module.exports = { createSeededCorpus };
