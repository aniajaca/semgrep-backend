const fs = require('fs');
const path = require('path');

// Load JSON and CSV
function loadJson(p) { return JSON.parse(fs.readFileSync(p, 'utf8')); }

function parseGroundTruthCSV(csvPath) {
  const map = new Map();
  const lines = fs.readFileSync(csvPath, 'utf8').split('\n');
  for (const line of lines) {
    if (line && line[0] !== '#') {
      const [testName, category, isVuln, cwe] = line.split(',');
      if (testName && testName.startsWith('BenchmarkTest')) {
        map.set(testName, {
          isVuln: isVuln.trim() === 'true',
          category: category.trim(),
          cwe: parseInt(cwe.trim())
        });
      }
    }
  }
  return map;
}

// Extract CWE number from Semgrep metadata
function extractCWE(finding) {
  const cweArray = finding.extra?.metadata?.cwe || [];
  if (cweArray.length > 0) {
    const match = cweArray[0].match(/CWE-(\d+)/);
    if (match) return parseInt(match[1]);
  }
  return null;
}

// Main
const results = loadJson('BenchmarkJava/scanner_results_raw.json');
const expectedMap = parseGroundTruthCSV('BenchmarkJava/ground_truth_full.csv');

// Group findings by test case
const findingsByTest = new Map();
let totalFindings = 0;
let findingsWithCWE = 0;

for (const f of results.results || []) {
  totalFindings++;
  const testName = path.basename(f.path || '', '.java');
  if (!testName.startsWith('BenchmarkTest')) continue;
  
  if (!findingsByTest.has(testName)) {
    findingsByTest.set(testName, []);
  }
  
  const cwe = extractCWE(f);
  if (cwe) findingsWithCWE++;
  
  findingsByTest.get(testName).push({
    check_id: f.check_id,
    cwe: cwe
  });
}

console.log(`Total Semgrep findings: ${totalFindings}`);
console.log(`Findings with CWE: ${findingsWithCWE}`);
console.log(`Test cases with findings: ${findingsByTest.size}\n`);

// CWE-aligned scoring
let TP = 0, FP = 0, FN = 0, TN = 0;
let categoryMatched = 0;
let categoryMismatched = 0;

for (const [testName, gt] of expectedMap) {
  const findings = findingsByTest.get(testName) || [];
  
  // Check if ANY finding matches the expected CWE
  const hasMatchingCWE = findings.some(f => f.cwe === gt.cwe);
  
  if (findings.length > 0) {
    if (hasMatchingCWE) {
      categoryMatched++;
    } else {
      categoryMismatched++;
    }
  }
  
  // Count detection only if CWE matches
  const detected = hasMatchingCWE;
  
  if (gt.isVuln && detected) TP++;
  else if (!gt.isVuln && detected) FP++;
  else if (gt.isVuln && !detected) FN++;
  else TN++;
}

const TPR = (TP / (TP + FN) * 100).toFixed(2);
const FNR = (FN / (TP + FN) * 100).toFixed(2);
const FPR = (FP / (FP + TN) * 100).toFixed(2);
const Precision = (TP / (TP + FP) * 100).toFixed(2);
const F1 = (2 * Precision * TPR / (Precision * 1 + TPR * 1)).toFixed(2);

console.log('============================================================');
console.log('OWASP BENCHMARK - CWE-ALIGNED SCORING');
console.log('============================================================');
console.log('SCORING METHOD:');
console.log('  Detection counted ONLY if finding CWE matches ground truth CWE');
console.log('  Mismatched-category findings discarded\n');
console.log('FINDINGS ANALYSIS:');
console.log(`  Category-matched findings: ${categoryMatched}`);
console.log(`  Category-mismatched (discarded): ${categoryMismatched}\n`);
console.log('CONFUSION MATRIX:');
console.log(`  TP: ${TP.toString().padStart(4)}   FP: ${FP.toString().padStart(4)}`);
console.log(`  FN: ${FN.toString().padStart(4)}   TN: ${TN.toString().padStart(4)}\n`);
console.log('METRICS:');
console.log(`  TPR (Recall):    ${TPR.padStart(6)}% ${TPR >= 85 ? '✅' : '❌'} (target ≥85%)`);
console.log(`  FNR:             ${FNR.padStart(6)}% ${FNR <= 15 ? '✅' : '❌'} (target ≤15%)`);
console.log(`  FPR:             ${FPR.padStart(6)}% ${FPR <= 15 ? '✅' : '❌'} (target ≤15%)`);
console.log(`  Precision:       ${Precision.padStart(6)}%`);
console.log(`  F1 Score:        ${F1.padStart(6)}% ${F1 >= 70 ? '✅' : '❌'} (target ≥70%)`);
console.log('============================================================');
