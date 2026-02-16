const code = `if ((7 * 42) - num > 200) bar = "This_should_always_happen";
else bar = param;`;

console.log('Code to match:');
console.log(code);
console.log('\n---\n');

// Try simpler patterns
const patterns = [
  {
    name: 'Full pattern (original)',
    regex: /if\s*\(\s*\(?\s*([0-9\s\+\-\*\/\(\)]+)\s*\)?\s*([><=!]+)\s*(\d+)\s*\)\s+(\w+)\s*=\s*"([^"]+)"\s*;\s*else\s+\4\s*=\s*\w+/gs
  },
  {
    name: 'Just the if part',
    regex: /if\s*\(\s*.*\)\s+(\w+)\s*=\s*"([^"]+)"/g
  },
  {
    name: 'Just the else part',  
    regex: /else\s+(\w+)\s*=\s*(\w+)/g
  },
  {
    name: 'Complete but flexible',
    regex: /if\s*\([^)]+\)\s+(\w+)\s*=\s*"([^"]+)"\s*;\s*else\s+\1\s*=\s*(\w+)/g
  }
];

patterns.forEach(({name, regex}) => {
  console.log(`Testing: ${name}`);
  const match = regex.exec(code);
  if (match) {
    console.log('✅ MATCH!');
    console.log('Groups:', match.slice(1));
  } else {
    console.log('❌ No match');
  }
  console.log('');
});
