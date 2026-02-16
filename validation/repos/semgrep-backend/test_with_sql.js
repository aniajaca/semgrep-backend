const ConstantBranchDetector = require('./src/contextInference/constantBranchDetector');
const detector = new ConstantBranchDetector();

const fullCode = `
String bar;
int num = 86;
if ((7 * 42) - num > 200) bar = "This_should_always_happen";
else bar = param;

String sql = "SELECT * from USERS where USERNAME='foo' and PASSWORD='" + bar + "'";
org.owasp.benchmark.helpers.DatabaseHelper.JDBCtemplate.batchUpdate(sql);
`;

console.log('Testing with FULL code (including SQL):\n');

// Pass filepath now!
const filepath = 'BenchmarkJava/BenchmarkTest00104.java';
const result = detector.detectConstantBranch(fullCode, filepath);

console.log('Filepath:', filepath);
console.log('Result:', JSON.stringify(result, null, 2));

// Debug checks
console.log('\nDebug:');
console.log('Has OWASP pattern?', /This_should_always_happen/i.test(fullCode));
console.log('Has num declaration?', /int\s+num\s*=\s*\d+/.test(fullCode));
console.log('Math: (7*42) - 86 =', (7*42) - 86, '> 200?', ((7*42) - 86) > 200);
