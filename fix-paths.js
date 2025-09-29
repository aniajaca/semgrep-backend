// fix-paths.js
const fs = require('fs').promises;
const path = require('path');

async function fixImports() {
  const fixes = [
    // Fix server.js imports
    ['src/server.js', [
      ['./astScanner', './astScanner'],
      ['./dependencyScanner', './dependencyScanner'],
      ['./semgrepAdapter', './semgrepAdapter'],
      ['./lib/normalize', './lib/normalize'],
      ['./lib/snippetExtractor', './lib/snippetExtractor'],
      ['./contextInference', './contextInference'],
      ['./contextInference/profiles/profileManager', './contextInference/profiles/profileManager'],
      ['./enhancedRiskCalculator', './enhancedRiskCalculator'],
      ['./taxonomy', './taxonomy'],
      ['./config/scanner.config.json', '../config/scanner.config.json']
    ]],
    
    // Fix other module imports
    ['src/enhancedRiskCalculator.js', [
      ['./customEnvironmentalFactors', './customEnvironmentalFactors'],
      ['./taxonomy', './taxonomy']
    ]],
    
    ['src/taxonomy.js', [
      ['../data/security-taxonomy.json', '../data/security-taxonomy.json']
    ]]
  ];

  for (const [file, replacements] of fixes) {
    try {
      let content = await fs.readFile(file, 'utf8');
      for (const [oldPath, newPath] of replacements) {
        const regex = new RegExp(`require\\(['"]${oldPath.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}['"]\\)`, 'g');
        content = content.replace(regex, `require('${newPath}')`);
      }
      await fs.writeFile(file, content);
      console.log(`✅ Fixed imports in ${file}`);
    } catch (error) {
      console.error(`❌ Error fixing ${file}:`, error.message);
    }
  }
}

fixImports();