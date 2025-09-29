const { exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);

async function testSemgrep() {
  console.log('Testing Semgrep detection...\n');
  
  // Test 1: python -m semgrep
  try {
    console.log('Test 1: python -m semgrep --version');
    const result1 = await execAsync('python -m semgrep --version');
    console.log('stdout:', result1.stdout);
    console.log('stderr:', result1.stderr);
    console.log('✓ Method 1 works!\n');
  } catch (e) {
    console.log('✗ Method 1 failed:', e.message, '\n');
  }
  
  // Test 2: plain semgrep
  try {
    console.log('Test 2: semgrep --version');
    const result2 = await execAsync('semgrep --version');
    console.log('stdout:', result2.stdout);
    console.log('stderr:', result2.stderr);
    console.log('✓ Method 2 works!\n');
  } catch (e) {
    console.log('✗ Method 2 failed:', e.message, '\n');
  }
}

testSemgrep();
