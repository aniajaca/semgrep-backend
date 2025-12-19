#!/usr/bin/env node

/**
 * OWASP Benchmark Metrics Calculator
 * Calculates performance metrics by comparing scanner results with ground truth
 * 
 * Usage: node scripts/calculateMetrics.js
 */

const fs = require('fs').promises;
const fullPath = path.isAbsolute(finding.file) 
  ? finding.file 
  : path.join(projectPath, finding.file);

// File paths
const GROUND_TRUTH_FILE = path.join(__dirname, '..', 'BenchmarkJava', 'ground_truth_full.csv');
const SCANNER_RESULTS_FILE = path.join(__dirname, '..', 'BenchmarkJava', 'scanner_results_mapped.csv');
const METRICS_OUTPUT = path.join(__dirname, '..', 'BenchmarkJava', 'validation_metrics.json');
const METRICS_REPORT = path.join(__dirname, '..', 'BenchmarkJava', 'validation_report.txt');

/**
 * Load CSV file
 */
async function loadCSV(filePath) {
  const content = await fs.readFile(filePath, 'utf-8');
  const lines = content.trim().split('\n');
  
  // Skip header (starts with #)
  const dataLines = lines.filter(line => !line.startsWith('#'));
  
  return dataLines.map(line => {
    const [testName, category, isVuln, ...rest] = line.split(',');
    return {
      testName,
      category,
      isVuln: isVuln === 'true',
      raw: line
    };
  });
}

/**
 * Calculate confusion matrix for a category
 */
function calculateConfusionMatrix(groundTruth, scannerResults, category = null) {
  let TP = 0, FP = 0, TN = 0, FN = 0;
  
  const gtMap = new Map(groundTruth.map(t => [t.testName, t]));
  const scanMap = new Map(scannerResults.map(t => [t.testName, t]));
  
  for (const [testName, gt] of gtMap) {
    const scan = scanMap.get(testName);
    
    // Filter by category if specified
    if (category && gt.category !== category) {
      continue;
    }
    
    if (!scan) {
      // Scanner didn't process this test
      if (gt.isVuln) FN++;
      else TN++;
      continue;
    }
    
    // Compare results
    if (gt.isVuln && scan.isVuln) {
      TP++;
    } else if (!gt.isVuln && scan.isVuln) {
      FP++;
    } else if (!gt.isVuln && !scan.isVuln) {
      TN++;
    } else if (gt.isVuln && !scan.isVuln) {
      FN++;
    }
  }
  
  return { TP, FP, TN, FN };
}

/**
 * Calculate performance metrics from confusion matrix
 */
function calculateMetrics(confusionMatrix) {
  const { TP, FP, TN, FN } = confusionMatrix;
  
  // True Positive Rate (Recall/Sensitivity)
  const TPR = TP + FN > 0 ? TP / (TP + FN) : 0;
  
  // False Positive Rate
  const FPR = FP + TN > 0 ? FP / (FP + TN) : 0;
  
  // Precision (Positive Predictive Value)
  const precision = TP + FP > 0 ? TP / (TP + FP) : 0;
  
  // F1-Score (Harmonic mean of Precision and Recall)
  const F1 = precision + TPR > 0 ? 2 * (precision * TPR) / (precision + TPR) : 0;
  
  // Accuracy
  const accuracy = TP + FP + TN + FN > 0 ? (TP + TN) / (TP + FP + TN + FN) : 0;
  
  // Youden Index (Benchmark Score)
  const youdenIndex = TPR - FPR;
  
  // Specificity (True Negative Rate)
  const specificity = TN + FP > 0 ? TN / (TN + FP) : 0;
  
  return {
    TP, FP, TN, FN,
    TPR: TPR * 100, // Convert to percentage
    FPR: FPR * 100,
    precision: precision * 100,
    recall: TPR * 100,
    F1Score: F1 * 100,
    accuracy: accuracy * 100,
    youdenIndex: youdenIndex * 100,
    specificity: specificity * 100
  };
}

/**
 * Get all unique categories
 */
function getCategories(data) {
  return [...new Set(data.map(t => t.category))].sort();
}

/**
 * Main calculation
 */
async function calculateAllMetrics() {
  console.log('================================');
  console.log('OWASP Benchmark Metrics Calculator');
  console.log('================================\n');
  
  // Load data
  console.log('Loading ground truth...');
  const groundTruth = await loadCSV(GROUND_TRUTH_FILE);
  console.log(`✓ Loaded ${groundTruth.length} ground truth test cases\n`);
  
  console.log('Loading scanner results...');
  const scannerResults = await loadCSV(SCANNER_RESULTS_FILE);
  console.log(`✓ Loaded ${scannerResults.length} scanner results\n`);
  
  // Calculate per-category metrics
  console.log('Calculating per-category metrics...\n');
  const categories = getCategories(groundTruth);
  const categoryMetrics = {};
  
  for (const category of categories) {
    const confusionMatrix = calculateConfusionMatrix(groundTruth, scannerResults, category);
    const metrics = calculateMetrics(confusionMatrix);
    
    // Count test cases in this category
    const categoryTests = groundTruth.filter(t => t.category === category);
    const vulnerableCount = categoryTests.filter(t => t.isVuln).length;
    const safeCount = categoryTests.length - vulnerableCount;
    
    categoryMetrics[category] = {
      testCases: categoryTests.length,
      vulnerableCount,
      safeCount,
      ...metrics
    };
    
    console.log(`${category.padEnd(15)} - F1: ${metrics.F1Score.toFixed(1)}%, TPR: ${metrics.TPR.toFixed(1)}%, FPR: ${metrics.FPR.toFixed(1)}%`);
  }
  
  // Calculate aggregate metrics (weighted by category size)
  console.log('\nCalculating aggregate metrics...\n');
  const aggregateConfusion = calculateConfusionMatrix(groundTruth, scannerResults);
  const aggregateMetrics = calculateMetrics(aggregateConfusion);
  
  // Prepare results object
  const results = {
    timestamp: new Date().toISOString(),
    totalTestCases: groundTruth.length,
    scannerResultsCount: scannerResults.length,
    categories: categoryMetrics,
    aggregate: aggregateMetrics,
    summary: {
      categoriesTested: categories.length,
      totalVulnerable: groundTruth.filter(t => t.isVuln).length,
      totalSafe: groundTruth.filter(t => !t.isVuln).length
    }
  };
  
  // Save JSON results
  await fs.writeFile(METRICS_OUTPUT, JSON.stringify(results, null, 2));
  console.log(`✓ Metrics saved: ${METRICS_OUTPUT}\n`);
  
  // Generate text report
  await generateTextReport(results);
  console.log(`✓ Report saved: ${METRICS_REPORT}\n`);
  
  // Display summary
  displaySummary(results);
  
  return results;
}

/**
 * Generate human-readable text report
 */
async function generateTextReport(results) {
  const lines = [];
  
  lines.push('================================');
  lines.push('OWASP BENCHMARK VALIDATION REPORT');
  lines.push('Neperia Security Scanner');
  lines.push('================================\n');
  
  lines.push(`Generated: ${new Date(results.timestamp).toLocaleString()}`);
  lines.push(`Total Test Cases: ${results.totalTestCases}`);
  lines.push(`Scanner Results: ${results.scannerResultsCount}\n`);
  
  lines.push('AGGREGATE PERFORMANCE');
  lines.push('================================');
  const agg = results.aggregate;
  lines.push(`Accuracy:        ${agg.accuracy.toFixed(2)}%`);
  lines.push(`F1-Score:        ${agg.F1Score.toFixed(2)}%`);
  lines.push(`Precision:       ${agg.precision.toFixed(2)}%`);
  lines.push(`Recall (TPR):    ${agg.recall.toFixed(2)}%`);
  lines.push(`False Pos Rate:  ${agg.FPR.toFixed(2)}%`);
  lines.push(`Youden Index:    ${agg.youdenIndex.toFixed(2)}%`);
  lines.push('');
  lines.push('Confusion Matrix:');
  lines.push(`  True Positives:  ${agg.TP}`);
  lines.push(`  False Positives: ${agg.FP}`);
  lines.push(`  True Negatives:  ${agg.TN}`);
  lines.push(`  False Negatives: ${agg.FN}\n`);
  
  lines.push('PER-CATEGORY PERFORMANCE');
  lines.push('================================');
  lines.push('Category        | Tests |  F1   | TPR  | FPR  | Prec | Youden');
  lines.push('----------------|-------|-------|------|------|------|-------');
  
  for (const [category, metrics] of Object.entries(results.categories)) {
    lines.push(
      `${category.padEnd(15)} | ` +
      `${metrics.testCases.toString().padStart(5)} | ` +
      `${metrics.F1Score.toFixed(1).padStart(5)}% | ` +
      `${metrics.TPR.toFixed(1).padStart(4)}% | ` +
      `${metrics.FPR.toFixed(1).padStart(4)}% | ` +
      `${metrics.precision.toFixed(1).padStart(4)}% | ` +
      `${metrics.youdenIndex.toFixed(1).padStart(5)}%`
    );
  }
  
  lines.push('\n');
  lines.push('CATEGORY DETAILS');
  lines.push('================================\n');
  
  for (const [category, metrics] of Object.entries(results.categories)) {
    lines.push(`${category.toUpperCase()}`);
    lines.push(`  Test Cases: ${metrics.testCases} (${metrics.vulnerableCount} vulnerable, ${metrics.safeCount} safe)`);
    lines.push(`  TP: ${metrics.TP}, FP: ${metrics.FP}, TN: ${metrics.TN}, FN: ${metrics.FN}`);
    lines.push(`  F1-Score: ${metrics.F1Score.toFixed(2)}%, Accuracy: ${metrics.accuracy.toFixed(2)}%`);
    lines.push('');
  }
  
  lines.push('INTERPRETATION');
  lines.push('================================');
  lines.push('TPR (True Positive Rate / Recall): % of real vulnerabilities detected');
  lines.push('FPR (False Positive Rate): % of safe code incorrectly flagged');
  lines.push('Precision: % of flagged code that is actually vulnerable');
  lines.push('F1-Score: Harmonic mean of Precision and Recall');
  lines.push('Youden Index: TPR - FPR (benchmark\'s primary metric)');
  lines.push('');
  lines.push('Industry Benchmarks:');
  lines.push('  Commercial SAST Average: TPR 30-40%, FPR 15-60%, Youden ~35%');
  lines.push('  Best-in-Class (Qwiet AI): TPR 100%, FPR 25%, Youden 75%');
  lines.push('  Academic Tools: F1-Score typically 60-75%\n');
  
  await fs.writeFile(METRICS_REPORT, lines.join('\n'));
}

/**
 * Display summary to console
 */
function displaySummary(results) {
  console.log('================================');
  console.log('VALIDATION SUMMARY');
  console.log('================================\n');
  
  const agg = results.aggregate;
  
  console.log('Overall Performance:');
  console.log(`  F1-Score:    ${agg.F1Score.toFixed(2)}%`);
  console.log(`  TPR (Recall):${agg.recall.toFixed(2)}%`);
  console.log(`  FPR:         ${agg.FPR.toFixed(2)}%`);
  console.log(`  Precision:   ${agg.precision.toFixed(2)}%`);
  console.log(`  Youden Idx:  ${agg.youdenIndex.toFixed(2)}%\n`);
  
  // Assessment against targets
  console.log('Target Assessment:');
  assessTarget('Conservative F1 ≥ 65%', agg.F1Score, 65);
  assessTarget('Moderate F1 ≥ 70%', agg.F1Score, 70);
  assessTarget('Ambitious F1 ≥ 75%', agg.F1Score, 75);
  assessTarget('Conservative TPR ≥ 70%', agg.recall, 70);
  assessTarget('Moderate TPR ≥ 75%', agg.recall, 75);
  assessTarget('Ambitious TPR ≥ 80%', agg.recall, 80);
  assessTarget('Conservative FPR ≤ 30%', agg.FPR, 30, true);
  assessTarget('Moderate FPR ≤ 25%', agg.FPR, 25, true);
  assessTarget('Ambitious FPR ≤ 20%', agg.FPR, 20, true);
  console.log('');
  
  // Top/Bottom performing categories
  const sortedByF1 = Object.entries(results.categories)
    .sort((a, b) => b[1].F1Score - a[1].F1Score);
  
  console.log('Top 3 Categories (by F1-Score):');
  sortedByF1.slice(0, 3).forEach(([cat, metrics]) => {
    console.log(`  ${cat.padEnd(15)} - ${metrics.F1Score.toFixed(1)}%`);
  });
  
  console.log('\nBottom 3 Categories (by F1-Score):');
  sortedByF1.slice(-3).forEach(([cat, metrics]) => {
    console.log(`  ${cat.padEnd(15)} - ${metrics.F1Score.toFixed(1)}%`);
  });
  
  console.log('\n================================');
  console.log('Review detailed report: validation_report.txt');
  console.log('================================\n');
}

/**
 * Assess if target is met
 */
function assessTarget(label, value, target, lowerIsBetter = false) {
  const met = lowerIsBetter ? value <= target : value >= target;
  const symbol = met ? '✓' : '✗';
  const status = met ? 'MET' : 'NOT MET';
  console.log(`  ${symbol} ${label.padEnd(25)} - ${value.toFixed(1)}% [${status}]`);
}

/**
 * Main execution
 */
async function main() {
  try {
    await calculateAllMetrics();
    
    console.log('Next Steps:');
    console.log('1. Review validation_report.txt for detailed analysis');
    console.log('2. Generate visualizations (ROC curves, confusion matrices)');
    console.log('3. Document results in thesis section 5.X');
    console.log('4. Prepare defense presentation materials\n');
    
    process.exit(0);
  } catch (error) {
    console.error('\n✗ ERROR:', error.message);
    console.error(error.stack);
    process.exit(1);
  }
}

// Run if called directly
if (require.main === module) {
  main();
}

module.exports = { calculateAllMetrics, calculateMetrics, calculateConfusionMatrix };