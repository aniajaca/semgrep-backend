const fs = require('fs');
const file = 'src/contextInference/contextualFilter.js';
let content = fs.readFileSync(file, 'utf8');

// Find and replace the detector call
content = content.replace(
  /const branchCheck = this\.constantBranchDetector\.detectConstantBranch\(fileContent\);/g,
  'const branchCheck = this.constantBranchDetector.detectConstantBranch(fileContent, finding.file);'
);

fs.writeFileSync(file, content);
console.log('✓ Updated contextualFilter.js to pass filepath');
