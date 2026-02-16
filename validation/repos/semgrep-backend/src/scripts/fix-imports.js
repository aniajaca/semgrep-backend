#!/usr/bin/env node

// fix-imports.js - Fix all import paths after consolidation
const fs = require('fs').promises;
      if (requireRegex.test(content)) {
        content = content.replace(requireRegex, `require('${newPath}')`);
        modified = true;
        console.log(`  ✓ ${oldPath} → ${newPath}`);
      }
      
      // Handle import statements
      const importRegex = new RegExp(`from ['"]${oldPath.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}['"]`, 'g');
      if (importRegex.test(content)) {
        content = content.replace(importRegex, `from '${newPath}'`);
        modified = true;
        console.log(`  ✓ ${oldPath} → ${newPath}`);
      }
    }
    
    if (modified) {
      await fs.writeFile(filePath, content);
      return true;
    }
    return false;
  } catch (error) {
    console.error(`  ✗ Error: ${error.message}`);
    return false;
  }
}

async function main() {
  console.log('🔧 Fixing import paths after consolidation...\n');
  
  // Files that import dataModels need to import normalize instead
  const dataModelsToNormalize = [
    'src/enhancedRiskCalculator.js',
    'src/customEnvironmentalFactors.js'
  ];
  
  for (const file of dataModelsToNormalize) {
    console.log(`Updating ${file}:`);
    await updateImports(file, [
      ['./lib/dataModels', './lib/normalize'],
      ['./dataModels', './lib/normalize']
    ]);
  }
  
  // Update any remaining references to deleted calculators
  const filesToCheck = [
    'src/server.js',
    'scripts/scan.js'
  ];
  
  for (const file of filesToCheck) {
    console.log(`\nChecking ${file}:`);
    try {
      let content = await fs.readFile(file, 'utf8');
      
      // Remove any imports of deleted calculators
      const toRemove = [
        /const.*?SophisticatedRiskCalculator.*?=.*?require\(.*?\);?\n/g,
        /const.*?ProductionRiskCalculator.*?=.*?require\(.*?\);?\n/g,
        /import.*?SophisticatedRiskCalculator.*?from.*?;?\n/g,
        /import.*?ProductionRiskCalculator.*?from.*?;?\n/g
      ];
      
      let modified = false;
      for (const regex of toRemove) {
        if (regex.test(content)) {
          content = content.replace(regex, '');
          modified = true;
          console.log('  ✓ Removed import of deleted calculator');
        }
      }
      
      if (modified) {
        await fs.writeFile(file, content);
      }
    } catch (error) {
      console.log(`  ⚠ File not found or error: ${error.message}`);
    }
  }
  
  console.log('\n✅ Import paths fixed!');
}

main().catch(console.error);