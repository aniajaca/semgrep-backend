const code = `if ((7 * 42) - num > 200) bar = "This_should_always_happen";
else bar = param;`;

console.log('Code with newline:');
console.log(JSON.stringify(code));
console.log('\n');

// Pattern that handles newlines
const pattern = /if\s*\([^)]+\)\s+(\w+)\s*=\s*"([^"]+)"\s*;\s*else\s+(\w+)\s*=\s*(\w+)/gs;

const match = pattern.exec(code);

if (match) {
  console.log('✅ MATCH!');
  console.log('Groups:', match.slice(1));
  
  if (match[1] === match[3]) {
    console.log('✅ Same variable!');
  }
} else {
  console.log('❌ No match with /gs flags');
  
  // Try without newline
  const oneLine = code.replace(/\n/g, ' ');
  console.log('\nTrying with spaces instead of newlines:');
  console.log(JSON.stringify(oneLine));
  
  const match2 = pattern.exec(oneLine);
  if (match2) {
    console.log('✅ WORKS when newline removed!');
    console.log('Groups:', match2.slice(1));
  }
}
