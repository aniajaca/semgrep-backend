const ConstantBranchDetector = require('./src/contextInference/constantBranchDetector');
const detector = new ConstantBranchDetector();

// EXACT code from BenchmarkTest00104.java (lines 60-70)
const realJavaCode = `
String bar;
// Simple if statement that assigns constant to bar on true condition
int num = 86;
if ((7 * 42) - num > 200) bar = "This_should_always_happen";
else bar = param;
`;

console.log('Testing with REAL Java code from BenchmarkTest00104.java:\n');
console.log('Code:');
console.log(realJavaCode);
console.log('\n---\n');

const result = detector.detectConstantBranch(realJavaCode);
console.log('Result:', JSON.stringify(result, null, 2));

// Also test the math
console.log('\nMath check:');
console.log('(7 * 42) - 86 =', (7 * 42) - 86);
console.log('Is 208 > 200?', 208 > 200);
