const fs = require('fs').promises;
const path = require('path');

async function main() {
  const BENCHMARK_DIR = path.join(__dirname, '..', 'BenchmarkJava');
  
  const csvContent = await fs.readFile(
    path.join(BENCHMARK_DIR, 'mapped_results.csv'),
    'utf-8'
  );
  
  const lines = csvContent.split('\n').filter(l => l && !l.startsWith('testName'));
  
  let TP = 0, FP = 0, FN = 0, TN = 0;
  
  for (const line of lines) {
    const parts = line.split(',');
    const expectedVuln = parts[2] === 'true';
    const detected = parts[4] === 'true';
    
    if (expectedVuln && detected) TP++;
    else if (!expectedVuln && detected) FP++;
    else if (expectedVuln && !detected) FN++;
    else if (!expectedVuln && !detected) TN++;
  }
  
  const TPR = (TP / (TP + FN) * 100).toFixed(2);
  const FPR = (FP / (FP + TN) * 100).toFixed(2);
  const Precision = (TP / (TP + FP) * 100).toFixed(2);
  const F1 = (2 * (Precision * TPR) / (Precision * 1 + TPR * 1)).toFixed(2);
  
  console.log('============================================================');
  console.log('🎯 OWASP BENCHMARK VALIDATION - SEMGREP BASELINE');
  console.log('============================================================');
  console.log('CONFUSION MATRIX:');
  console.log(`  TP: ${TP.toString().padStart(4)}   FP: ${FP.toString().padStart(4)}`);
  console.log(`  FN: ${FN.toString().padStart(4)}   TN: ${TN.toString().padStart(4)}`);
  console.log('');
  console.log('METRICS:');
  console.log(`  TPR (Recall):    ${TPR}%`);
  console.log(`  FPR:             ${FPR}%`);
  console.log(`  Precision:       ${Precision}%`);
  console.log(`  F1 Score:        ${F1}%`);
  console.log('');
  console.log('OWASP BENCHMARK TARGETS:');
  console.log(`  TPR ≥ 85%:       ${TPR >= 85 ? '✅ PASS' : '❌ FAIL'}`);
  console.log(`  FPR ≤ 15%:       ${FPR <= 15 ? '✅ PASS' : '❌ FAIL'}`);
  console.log(`  F1 ≥ 70%:        ${F1 >= 70 ? '✅ PASS' : '❌ FAIL'}`);
  console.log('============================================================');
}

main().catch(console.error);
