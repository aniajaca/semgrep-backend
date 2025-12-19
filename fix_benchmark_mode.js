const fs = require('fs');
const file = 'src/contextInference/contextualFilter.js';
let content = fs.readFileSync(file, 'utf8');

// Change benchmarkMode default to FALSE
content = content.replace(
  /benchmarkMode: config\.benchmarkMode !== false,  \/\/ Default TRUE/,
  'benchmarkMode: config.benchmarkMode || false,  // Default FALSE'
);

fs.writeFileSync(file, content);
console.log('✓ Disabled benchmark mode (default = false)');
