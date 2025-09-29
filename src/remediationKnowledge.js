// remediationKnowledge.js - Comprehensive remediation guidance for all vulnerabilities
module.exports = {
  // SQL Injection remediations
  'CWE-89': {
    title: 'SQL Injection',
    risk: 'Attackers can read, modify, or delete database contents',
    remediation: {
      javascript: {
        fix: 'Use parameterized queries with prepared statements',
        example: `// Instead of:
const query = \`SELECT * FROM users WHERE id = \${userId}\`;

// Use:
const query = 'SELECT * FROM users WHERE id = ?';
db.query(query, [userId], callback);`,
        libraries: ['mysql2', 'pg', 'sequelize'],
        prevention: [
          'Always use parameterized queries',
          'Validate and sanitize all inputs',
          'Use stored procedures when possible',
          'Apply principle of least privilege to database users'
        ]
      },
      python: {
        fix: 'Use parameterized queries with placeholders',
        example: `# Instead of:
query = f"SELECT * FROM users WHERE id = {user_id}"

# Use:
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))`,
        libraries: ['psycopg2', 'pymysql', 'sqlalchemy'],
        prevention: [
          'Use ORM frameworks like SQLAlchemy',
          'Never concatenate user input into queries',
          'Use query builders that handle escaping'
        ]
      },
      java: {
        fix: 'Use PreparedStatement instead of Statement',
        example: `// Instead of:
String query = "SELECT * FROM users WHERE id = " + userId;
Statement stmt = conn.createStatement();
ResultSet rs = stmt.executeQuery(query);

// Use:
String query = "SELECT * FROM users WHERE id = ?";
PreparedStatement pstmt = conn.prepareStatement(query);
pstmt.setInt(1, userId);
ResultSet rs = pstmt.executeQuery();`,
        libraries: ['JDBC', 'Hibernate', 'JPA'],
        prevention: [
          'Use ORM frameworks like Hibernate',
          'Enable SQL query logging in development',
          'Use static analysis tools to detect SQL injection'
        ]
      }
    },
    testing: {
      manual: 'Test with SQL metacharacters like quotes, semicolons, and OR 1=1',
      tools: ['SQLMap', 'Burp Suite', 'OWASP ZAP'],
      automation: 'Include SQL injection tests in CI/CD pipeline'
    },
    references: [
      'https://owasp.org/www-community/attacks/SQL_Injection',
      'https://cwe.mitre.org/data/definitions/89.html'
    ]
  },

  // Command Injection remediations
  'CWE-78': {
    title: 'OS Command Injection',
    risk: 'Attackers can execute arbitrary system commands',
    remediation: {
      javascript: {
        fix: 'Avoid shell commands or use safe alternatives',
        example: `// Instead of:
const exec = require('child_process').exec;
exec(\`ls -la \${userInput}\`, callback);

// Use:
const spawn = require('child_process').spawn;
const ls = spawn('ls', ['-la', userInput]);`,
        libraries: ['child_process.spawn', 'execa'],
        prevention: [
          'Avoid system commands when possible',
          'Use language-specific libraries instead of shell commands',
          'Whitelist allowed commands and arguments',
          'Never pass user input directly to shell commands'
        ]
      },
      python: {
        fix: 'Use subprocess with shell=False',
        example: `# Instead of:
os.system(f"ls -la {user_input}")

# Use:
subprocess.run(['ls', '-la', user_input], shell=False)`,
        libraries: ['subprocess', 'shlex'],
        prevention: [
          'Use subprocess.run with shell=False',
          'Use shlex.quote() for escaping if shell is needed',
          'Validate input against a whitelist'
        ]
      },
      java: {
        fix: 'Use ProcessBuilder with separate arguments',
        example: `// Instead of:
Runtime.getRuntime().exec("ls -la " + userInput);

// Use:
ProcessBuilder pb = new ProcessBuilder("ls", "-la", userInput);
Process p = pb.start();`,
        libraries: ['ProcessBuilder', 'Apache Commons Exec'],
        prevention: [
          'Never use Runtime.exec() with user input',
          'Use ProcessBuilder with argument arrays',
          'Validate and sanitize all external input'
        ]
      }
    },
    testing: {
      manual: 'Test with command separators like ;, &&, ||, and backticks',
      tools: ['Commix', 'Burp Suite'],
      automation: 'Add command injection tests to security test suite'
    },
    references: [
      'https://owasp.org/www-community/attacks/Command_Injection',
      'https://cwe.mitre.org/data/definitions/78.html'
    ]
  },

  // Cross-Site Scripting remediations
  'CWE-79': {
    title: 'Cross-Site Scripting (XSS)',
    risk: 'Attackers can inject malicious scripts into web pages',
    remediation: {
      javascript: {
        fix: 'Encode output and use Content Security Policy',
        example: `// Instead of:
element.innerHTML = userInput;

// Use:
element.textContent = userInput;
// Or with a library:
element.innerHTML = DOMPurify.sanitize(userInput);`,
        libraries: ['DOMPurify', 'xss', 'sanitize-html'],
        prevention: [
          'Use textContent instead of innerHTML',
          'Implement Content Security Policy (CSP)',
          'Validate input on both client and server',
          'Use templating engines with auto-escaping'
        ]
      },
      python: {
        fix: 'Use template auto-escaping and validation',
        example: `# Flask/Jinja2 auto-escapes by default
{{ user_input }}

# For Django:
from django.utils.html import escape
safe_input = escape(user_input)`,
        libraries: ['markupsafe', 'bleach', 'html'],
        prevention: [
          'Enable auto-escaping in templates',
          'Use bleach for HTML sanitization',
          'Set X-XSS-Protection header'
        ]
      },
      java: {
        fix: 'Use OWASP Java Encoder',
        example: `// Instead of:
out.println("<div>" + userInput + "</div>");

// Use:
import org.owasp.encoder.Encode;
out.println("<div>" + Encode.forHtml(userInput) + "</div>");`,
        libraries: ['OWASP Java Encoder', 'Apache Commons Text'],
        prevention: [
          'Use JSTL <c:out> tags in JSP',
          'Enable auto-escaping in template engines',
          'Implement CSP headers'
        ]
      }
    },
    testing: {
      manual: 'Test with <script>alert(1)</script> and other XSS payloads',
      tools: ['XSStrike', 'Burp Suite', 'OWASP ZAP'],
      automation: 'Include XSS scanning in CI/CD pipeline'
    },
    references: [
      'https://owasp.org/www-community/attacks/xss/',
      'https://cwe.mitre.org/data/definitions/79.html'
    ]
  },

  // Hardcoded Credentials remediations
  'CWE-798': {
    title: 'Use of Hard-coded Credentials',
    risk: 'Exposed credentials can lead to unauthorized access',
    remediation: {
      javascript: {
        fix: 'Use environment variables or secure vaults',
        example: `// Instead of:
const apiKey = "sk_live_abcd1234";

// Use:
const apiKey = process.env.API_KEY;
// Or with dotenv:
require('dotenv').config();
const apiKey = process.env.API_KEY;`,
        libraries: ['dotenv', 'node-vault', 'aws-sdk'],
        prevention: [
          'Never commit credentials to version control',
          'Use .env files with .gitignore',
          'Use secret management services (AWS Secrets Manager, HashiCorp Vault)',
          'Rotate credentials regularly'
        ]
      },
      python: {
        fix: 'Use environment variables or config files',
        example: `# Instead of:
api_key = "sk_live_abcd1234"

# Use:
import os
api_key = os.environ.get('API_KEY')
# Or with python-dotenv:
from dotenv import load_dotenv
load_dotenv()
api_key = os.getenv('API_KEY')`,
        libraries: ['python-dotenv', 'hvac', 'boto3'],
        prevention: [
          'Use python-dotenv for local development',
          'Use cloud secret managers in production',
          'Implement credential rotation policies'
        ]
      },
      java: {
        fix: 'Use external configuration',
        example: `// Instead of:
String apiKey = "sk_live_abcd1234";

// Use:
String apiKey = System.getenv("API_KEY");
// Or with Spring:
@Value("\${api.key}")
private String apiKey;`,
        libraries: ['Spring Cloud Config', 'HashiCorp Vault', 'AWS SDK'],
        prevention: [
          'Use Spring Cloud Config Server',
          'Store secrets in external vaults',
          'Use Java KeyStore for certificates'
        ]
      }
    },
    testing: {
      manual: 'Search for patterns like password=, apikey=, secret=',
      tools: ['TruffleHog', 'GitLeaks', 'detect-secrets'],
      automation: 'Add secret scanning to pre-commit hooks'
    },
    references: [
      'https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password',
      'https://cwe.mitre.org/data/definitions/798.html'
    ]
  },

  // Weak Cryptography remediations
  'CWE-327': {
    title: 'Use of Broken or Weak Cryptographic Algorithm',
    risk: 'Weak encryption can be broken, exposing sensitive data',
    remediation: {
      javascript: {
        fix: 'Use strong, modern cryptographic algorithms',
        example: `// Instead of:
const crypto = require('crypto');
const hash = crypto.createHash('md5').update(data).digest('hex');

// Use:
const hash = crypto.createHash('sha256').update(data).digest('hex');
// For passwords, use bcrypt:
const bcrypt = require('bcrypt');
const hash = await bcrypt.hash(password, 10);`,
        libraries: ['bcrypt', 'argon2', 'scrypt'],
        prevention: [
          'Use SHA-256 or SHA-3 for hashing',
          'Use bcrypt/argon2 for passwords',
          'Use AES-256-GCM for encryption',
          'Keep cryptographic libraries updated'
        ]
      },
      python: {
        fix: 'Use recommended cryptographic libraries',
        example: `# Instead of:
import hashlib
hash = hashlib.md5(data).hexdigest()

# Use:
hash = hashlib.sha256(data).hexdigest()
# For passwords:
from passlib.hash import argon2
hash = argon2.hash(password)`,
        libraries: ['cryptography', 'passlib', 'bcrypt'],
        prevention: [
          'Use cryptography library for encryption',
          'Use passlib for password hashing',
          'Avoid MD5, SHA1, DES, RC4'
        ]
      },
      java: {
        fix: 'Use Java Cryptography Architecture properly',
        example: `// Instead of:
MessageDigest md = MessageDigest.getInstance("MD5");

// Use:
MessageDigest md = MessageDigest.getInstance("SHA-256");
// For passwords:
BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
String hash = encoder.encode(password);`,
        libraries: ['Spring Security', 'Bouncy Castle', 'JCA'],
        prevention: [
          'Use BCrypt for password hashing',
          'Use AES with GCM mode for encryption',
          'Use SecureRandom for random numbers'
        ]
      }
    },
    testing: {
      manual: 'Review all cryptographic operations',
      tools: ['CryptoGuard', 'FindSecBugs'],
      automation: 'Add cryptographic misuse detection to static analysis'
    },
    references: [
      'https://owasp.org/www-community/vulnerabilities/Cryptographic_Storage',
      'https://cwe.mitre.org/data/definitions/327.html'
    ]
  },

  // Path Traversal remediations
  'CWE-22': {
    title: 'Path Traversal',
    risk: 'Attackers can access files outside intended directories',
    remediation: {
      javascript: {
        fix: 'Validate and sanitize file paths',
        example: `// Instead of:
const file = fs.readFileSync(userInput);

// Use:
const path = require('path');
const safePath = path.normalize(userInput).replace(/^(\\.\\.\\/)+/, '');
if (safePath.startsWith(allowedDir)) {
  const file = fs.readFileSync(safePath);
}`,
        libraries: ['path', 'sanitize-filename'],
        prevention: [
          'Use path.join() and path.resolve()',
          'Validate against whitelist of allowed paths',
          'Use chroot jails or containers',
          'Set proper file permissions'
        ]
      },
      python: {
        fix: 'Use os.path for safe path handling',
        example: `# Instead of:
with open(user_input, 'r') as f:
    content = f.read()

# Use:
import os
safe_path = os.path.normpath(user_input)
if safe_path.startswith(allowed_dir):
    with open(safe_path, 'r') as f:
        content = f.read()`,
        libraries: ['pathlib', 'os.path'],
        prevention: [
          'Use pathlib for path operations',
          'Implement access control lists',
          'Run with minimal privileges'
        ]
      },
      java: {
        fix: 'Use File.getCanonicalPath() for validation',
        example: `// Instead of:
File file = new File(userInput);

// Use:
File file = new File(userInput);
String canonical = file.getCanonicalPath();
if (canonical.startsWith(allowedDir)) {
    // Process file
}`,
        libraries: ['java.nio.file', 'Apache Commons IO'],
        prevention: [
          'Use getCanonicalPath() for validation',
          'Implement strict access controls',
          'Use security managers'
        ]
      }
    },
    testing: {
      manual: 'Test with ../, ..\\ and encoded traversal sequences',
      tools: ['DotDotPwn', 'Burp Suite'],
      automation: 'Add path traversal tests to security suite'
    },
    references: [
      'https://owasp.org/www-community/attacks/Path_Traversal',
      'https://cwe.mitre.org/data/definitions/22.html'
    ]
  },

  // Insecure Deserialization remediations
  'CWE-502': {
    title: 'Deserialization of Untrusted Data',
    risk: 'Can lead to remote code execution',
    remediation: {
      javascript: {
        fix: 'Avoid deserializing untrusted data',
        example: `// Instead of:
const obj = eval('(' + userInput + ')');

// Use:
const obj = JSON.parse(userInput);
// With validation:
const schema = { type: 'object', properties: {...} };
const valid = ajv.validate(schema, JSON.parse(userInput));`,
        libraries: ['ajv', 'joi', 'yup'],
        prevention: [
          'Use JSON.parse() instead of eval()',
          'Validate deserialized data against schemas',
          'Implement input validation',
          'Use safe serialization formats'
        ]
      },
      python: {
        fix: 'Use safe serialization methods',
        example: `# Instead of:
import pickle
obj = pickle.loads(user_input)

# Use:
import json
obj = json.loads(user_input)
# With validation:
from jsonschema import validate
validate(instance=obj, schema=schema)`,
        libraries: ['json', 'jsonschema', 'marshmallow'],
        prevention: [
          'Never use pickle with untrusted data',
          'Use JSON for data exchange',
          'Implement schema validation',
          'Sign serialized data'
        ]
      },
      java: {
        fix: 'Implement serialization filters',
        example: `// Instead of:
ObjectInputStream ois = new ObjectInputStream(inputStream);
Object obj = ois.readObject();

// Use:
ObjectInputFilter filter = ObjectInputFilter.Config.createFilter("maxdepth=5;java.base/*;!*");
ois.setObjectInputFilter(filter);
Object obj = ois.readObject();`,
        libraries: ['Jackson', 'Gson', 'Java Serialization Filters'],
        prevention: [
          'Use JSON instead of Java serialization',
          'Implement serialization filters',
          'Use look-ahead deserialization',
          'Sign and encrypt serialized data'
        ]
      }
    },
    testing: {
      manual: 'Test with malicious serialized payloads',
      tools: ['ysoserial', 'marshalsec'],
      automation: 'Add deserialization tests to security pipeline'
    },
    references: [
      'https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data',
      'https://cwe.mitre.org/data/definitions/502.html'
    ]
  },

  // XML External Entity remediations
  'CWE-611': {
    title: 'XML External Entity (XXE) Processing',
    risk: 'Can lead to file disclosure and SSRF attacks',
    remediation: {
      javascript: {
        fix: 'Disable external entity processing',
        example: `// Use safe XML parsers
const parser = new DOMParser();
const doc = parser.parseFromString(xmlString, "text/xml");

// Or with libxmljs:
const libxmljs = require("libxmljs");
const doc = libxmljs.parseXml(xmlString, {
  noent: false,
  noblanks: true,
  nonet: true
});`,
        libraries: ['DOMParser', 'libxmljs', 'fast-xml-parser'],
        prevention: [
          'Disable DTD processing entirely',
          'Use JSON instead of XML when possible',
          'Validate XML against schemas',
          'Use safe XML parsing libraries'
        ]
      },
      python: {
        fix: 'Use defusedxml or configure parsers safely',
        example: `# Instead of:
import xml.etree.ElementTree as ET
tree = ET.parse(user_input)

# Use:
import defusedxml.ElementTree as ET
tree = ET.parse(user_input)
# Or configure safely:
from lxml import etree
parser = etree.XMLParser(resolve_entities=False, no_network=True)`,
        libraries: ['defusedxml', 'lxml'],
        prevention: [
          'Use defusedxml library',
          'Disable entity resolution',
          'Validate against XSD schemas'
        ]
      },
      java: {
        fix: 'Configure XML parsers to prevent XXE',
        example: `// Configure DocumentBuilderFactory
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setExpandEntityReferences(false);`,
        libraries: ['DOM4J', 'JDOM', 'SAX'],
        prevention: [
          'Disable DTD and external entities',
          'Use OWASP XML Security guidelines',
          'Prefer JSON over XML'
        ]
      }
    },
    testing: {
      manual: 'Test with XXE payloads containing external entities',
      tools: ['XXEinjector', 'Burp Suite'],
      automation: 'Add XXE tests to security testing'
    },
    references: [
      'https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing',
      'https://cwe.mitre.org/data/definitions/611.html'
    ]
  },

  // LDAP Injection remediations
  'CWE-90': {
    title: 'LDAP Injection',
    risk: 'Attackers can modify LDAP queries to access unauthorized data',
    remediation: {
      javascript: {
        fix: 'Escape special characters in LDAP queries',
        example: `// Instead of:
const filter = \`(uid=\${username})\`;

// Use:
const ldapEscape = require('ldap-escape');
const filter = \`(uid=\${ldapEscape.filter(username)})\`;`,
        libraries: ['ldapjs', 'ldap-escape'],
        prevention: [
          'Use parameterized LDAP queries',
          'Escape special LDAP characters',
          'Validate input against whitelist',
          'Use prepared statements where available'
        ]
      },
      python: {
        fix: 'Use proper LDAP escaping',
        example: `# Instead of:
filter = f"(uid={username})"

# Use:
import ldap.filter
filter = ldap.filter.filter_format("(uid=%s)", [username])`,
        libraries: ['python-ldap', 'ldap3'],
        prevention: [
          'Use ldap.filter.escape_filter_chars()',
          'Implement input validation',
          'Use allowlists for valid characters'
        ]
      },
      java: {
        fix: 'Use JNDI with proper escaping',
        example: `// Use Spring LDAP with proper encoding
LdapQuery query = LdapQueryBuilder.query()
    .where("uid").is(LdapEncoder.filterEncode(username));`,
        libraries: ['Spring LDAP', 'UnboundID LDAP SDK'],
        prevention: [
          'Use LDAP encoding utilities',
          'Implement strict input validation',
          'Use LDAP query builders'
        ]
      }
    },
    testing: {
      manual: 'Test with LDAP metacharacters like *, (, ), \\, /',
      tools: ['LDAP injection tools'],
      automation: 'Add LDAP injection tests to test suite'
    },
    references: [
      'https://owasp.org/www-community/attacks/LDAP_Injection',
      'https://cwe.mitre.org/data/definitions/90.html'
    ]
  }
};

// Export helper functions
const Taxonomy = require('../data/taxonomy');

module.exports.getRemediation = function(cweId, language = 'javascript') {
  const remediation = module.exports[cweId];
  if (!remediation) {
    return {
      title: 'Security Issue',
      risk: 'Potential security vulnerability detected',
      remediation: {
        fix: 'Review and fix the security issue',
        prevention: ['Follow secure coding practices']
      }
    };
  }
  
  return {
    ...remediation,
    languageSpecific: remediation.remediation[language] || remediation.remediation.javascript
  };
};

// Delegate severity to taxonomy (single source of truth)
module.exports.getSeverity = function(cweId) {
  const info = Taxonomy.getByCwe(cweId);
  return info?.defaultSeverity || 'medium';
};

// Delegate OWASP to taxonomy (single source of truth)
module.exports.getOWASP = function(cweId) {
  const info = Taxonomy.getByCwe(cweId);
  return info?.owasp || 'A06:2021 - Vulnerable and Outdated Components';
};

// Keep the one-liner helper as is
module.exports.getOneLiner = function(cweId) {
  const r = module.exports[cweId];
  if (!r) return 'Review and apply security best practices';
  
  // Try to get the JavaScript fix first (most common), then fallback to general fix
  return r.remediation?.javascript?.fix || 
         r.remediation?.fix || 
         r.title || 
         'Remediate per OWASP guidance';
};