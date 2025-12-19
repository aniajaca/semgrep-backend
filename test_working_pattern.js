const code = `if ((7 * 42) - num > 200) bar = "This_should_always_happen";
else bar = param;`;

console.log('Testing working pattern:\n');

// WORKING: Capture var name, then reference it
const pattern = /if\s*\([^)]+\)\s+(\w+)\s*=\s*"([^"]+)"\s*;\s*else\s+(\w+)\s*=\s*(\w+)/g;

const match = pattern.exec(code);

if (match) {
  console.log('✅ MATCH!');
  console.log('Full match:', match[0]);
  console.log('Groups:');
  console.log('  [1] var in if:', match[1]);
  console.log('  [2] const value:', match[2]);
  console.log('  [3] var in else:', match[3]);
  console.log('  [4] user param:', match[4]);
  
  // Check if same variable
  if (match[1] === match[3]) {
    console.log('\n✅ Same variable in both branches!');
    console.log(`Pattern: if (condition) ${match[1]} = "${match[2]}"; else ${match[1]} = ${match[4]}`);
  }
} else {
  console.log('❌ No match');
}
