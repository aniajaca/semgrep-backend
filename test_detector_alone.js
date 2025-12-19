const ConstantBranchDetector = require('./src/contextInference/constantBranchDetector');

const detector = new ConstantBranchDetector();

// Test code from OWASP Benchmark
const testCode = `
String bar;
int num = 86;
if ((7 * 42) - num > 200) bar = "This_should_always_happen";
else bar = param;

String sql = "SELECT * FROM users WHERE id = '" + bar + "'";
`;

console.log('Testing constant branch detector...\n');
const result = detector.detectConstantBranch(testCode);
console.log('Result:', JSON.stringify(result, null, 2));
