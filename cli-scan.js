#!/usr/bin/env node
const fs = require('fs');
const path = require('path');

const args = process.argv.slice(2).reduce((acc, arg) => {
  const [key, val] = arg.replace('--', '').split('=');
  acc[key] = val;
  return acc;
}, {});

if (!args.target || !args.output) {
  console.error('Usage: node cli-scan.js --target=<path> --filter=<ON|OFF> --output=<file>');
  process.exit(1);
}

const targetPath = args.target;
const filterEnabled = args.filter !== 'OFF';
const outputPath = args.output;

console.log(`Scanning: ${targetPath}`);
console.log(`Filter: ${filterEnabled ? 'ON' : 'OFF'}`);

async function runScan() {
  try {
    const srcPath = path.join(__dirname, 'src');
    
    if (!fs.existsSync(srcPath)) {
      throw new Error('src/ directory not found');
    }
    
    console.log(`✓ Found src directory: ${srcPath}`);
    
    const semgrepAdapterPath = path.join(srcPath, 'semgrepAdapter.js');
    const normalizePath = path.join(srcPath, 'lib', 'normalize.js');
    const filterPath = path.join(srcPath, 'contextInference', 'contextualFilter.js');
    const contextPath = path.join(srcPath, 'contextInference', 'index.js');
    
    const requiredFiles = [semgrepAdapterPath, normalizePath, filterPath, contextPath];
    
    for (const file of requiredFiles) {
      if (!fs.existsSync(file)) {
        throw new Error(`Required file not found: ${file}`);
      }
    }
    
    console.log('✓ All required modules found');
    
    const { runSemgrep, checkSemgrepAvailable } = require(semgrepAdapterPath);
    const { normalizeFindings, enrichFindings, deduplicateFindings } = require(normalizePath);
    const ContextualFilter = require(filterPath);
    const ContextInferenceSystem = require(contextPath);
    
    console.log('✓ Modules imported successfully');
    
    console.log('Checking Semgrep availability...');
    const semgrepAvailable = await checkSemgrepAvailable();
    
    if (!semgrepAvailable) {
      console.error('❌ Semgrep not available');
      process.exit(1);
    }
    
    console.log('✓ Semgrep available');
    
    if (!fs.existsSync(targetPath)) {
      throw new Error(`Target path does not exist: ${targetPath}`);
    }
    
    console.log(`✓ Target path exists: ${targetPath}`);
    
    const languages = ['javascript', 'typescript'];
    
    console.log('Running Semgrep scan...');
    const startTime = Date.now();
    
    const semgrepFindings = await runSemgrep(targetPath, {
      languages: languages,
      severity: 'ERROR,WARNING',
      timeout: 300,
      rulesets: ['auto']
    });
    
    const scanDuration = ((Date.now() - startTime) / 1000).toFixed(1);
    console.log(`✓ Semgrep completed in ${scanDuration}s`);
    console.log(`  Found ${semgrepFindings.length} raw findings`);
    
    console.log('Normalizing findings...');
    const normalized = normalizeFindings(semgrepFindings);
    console.log(`  Normalized: ${normalized.length} findings`);
    
    const enriched = enrichFindings(normalized);
    console.log(`  Enriched: ${enriched.length} findings`);
    
    const deduplicated = deduplicateFindings(enriched);
    console.log(`  Deduplicated: ${deduplicated.length} findings`);
    
    let finalFindings = deduplicated;
    
    if (filterEnabled) {
      console.log('');
      console.log('Applying contextual filter...');
      
      const contextualFilter = new ContextualFilter({
        filterTestFiles: true,
        filterExampleCode: true,
        filterBuildArtifacts: true,
        filterInjectionWithoutInput: true,
        detectSanitization: true,
        aggressiveMode: false,
        verbose: false,
        benchmarkMode: false
      });
      
      const contextInference = new ContextInferenceSystem();
      
      finalFindings = await contextualFilter.filterFindings(
        deduplicated,
        targetPath,
        contextInference,
        null
      );
      
      const filtered = deduplicated.length - finalFindings.length;
      const filterRate = ((filtered / deduplicated.length) * 100).toFixed(1);
      
      console.log(`✓ Filter applied`);
      console.log(`  Retained: ${finalFindings.length} findings`);
      console.log(`  Filtered: ${filtered} findings (${filterRate}%)`);
    }
    
    const output = {
      target: targetPath,
      timestamp: new Date().toISOString(),
      scanDuration: `${scanDuration}s`,
      filterEnabled: filterEnabled,
      findings: finalFindings,
      results: finalFindings,
      summary: {
        total: finalFindings.length,
        beforeFilter: deduplicated.length,
        filtered: deduplicated.length - finalFindings.length,
        filterRate: ((deduplicated.length - finalFindings.length) / deduplicated.length * 100).toFixed(1) + '%'
      }
    };
    
    const outputDir = path.dirname(outputPath);
    if (!fs.existsSync(outputDir)) {
      fs.mkdirSync(outputDir, { recursive: true });
    }
    
    fs.writeFileSync(outputPath, JSON.stringify(output, null, 2));
    
    console.log('');
    console.log('═══════════════════════════════════════════');
    console.log(`✅ Scan complete!`);
    console.log(`   Total findings: ${finalFindings.length}`);
    console.log(`   Output: ${outputPath}`);
    console.log('═══════════════════════════════════════════');
    
    process.exit(0);
    
  } catch (error) {
    console.error('');
    console.error('═══════════════════════════════════════════');
    console.error('❌ Scan failed!');
    console.error('═══════════════════════════════════════════');
    console.error('Error:', error.message);
    console.error('Stack trace:', error.stack);
    process.exit(1);
  }
}

process.on('unhandledRejection', (error) => {
  console.error('Unhandled error:', error);
  process.exit(1);
});

runScan();
