// Quick smoke test - run with: node test-aggregation.js
const { calculateFARS, calculateAllFARS, calculatePRS, percentile } = require('./src/lib/aggregation');

let passed = 0;
let failed = 0;

function assert(label, actual, expected, tolerance = 0.1) {
  if (Math.abs(actual - expected) <= tolerance) {
    console.log(`  ✅ ${label}: ${actual} (expected ${expected})`);
    passed++;
  } else {
    console.log(`  ❌ ${label}: ${actual} (expected ${expected})`);
    failed++;
  }
}

// ═══ TEST 1: FARS worked example from Literature Review §6.3 ═══
console.log('\n── FARS: Thesis worked example ──');
console.log('   payment_processor.py with CRS [95, 78, 82, 52]');
console.log('   Expected: (95×1.0 + 78×0.7 + 82×1.0 + 52×0.4) / (1.0+0.7+1.0+0.4) = 81.1');

const farsResult = calculateFARS([
  { crs: 95, file: 'payment_processor.py', ruleId: 'sqli-1' },
  { crs: 78, file: 'payment_processor.py', ruleId: 'xss-1' },
  { crs: 82, file: 'payment_processor.py', ruleId: 'sqli-2' },
  { crs: 52, file: 'payment_processor.py', ruleId: 'info-1' }
]);

assert('FARS score', farsResult.farsScore, 81.1, 0.5);
assert('maxBand', farsResult.maxBand === 'P0' ? 1 : 0, 1);
assert('findingCount', farsResult.findingCount, 4);

// ═══ TEST 2: FARS weight verification ═══
console.log('\n── FARS: Weight boundaries ──');

// All P0 findings - FARS should equal mean
const allP0 = calculateFARS([
  { crs: 90, file: 'a.js', ruleId: 'r1' },
  { crs: 85, file: 'a.js', ruleId: 'r2' }
]);
assert('All P0 → mean', allP0.farsScore, 87.5, 0.1);

// Single finding - FARS = that CRS
const single = calculateFARS([{ crs: 42, file: 'b.js', ruleId: 'r1' }]);
assert('Single finding', single.farsScore, 42.0, 0.1);

// Empty
const empty = calculateFARS([]);
assert('Empty', empty.farsScore, 0, 0);

// ═══ TEST 3: High CRS should dominate (anti-dilution) ═══
console.log('\n── FARS: Anti-dilution property ──');
const dilutionTest = calculateFARS([
  { crs: 95, file: 'c.js', ruleId: 'r1' },  // weight 1.0
  { crs: 20, file: 'c.js', ruleId: 'r2' },  // weight 0.2
  { crs: 15, file: 'c.js', ruleId: 'r3' },  // weight 0.2
  { crs: 10, file: 'c.js', ruleId: 'r4' }   // weight 0.2
]);
// Simple mean = 35. FARS should be much higher because 95 has weight 1.0
console.log(`   Simple mean: 35, FARS: ${dilutionTest.farsScore} (should be >> 35)`);
assert('Anti-dilution', dilutionTest.farsScore > 55 ? 1 : 0, 1);

// ═══ TEST 4: calculateAllFARS groups by file ═══
console.log('\n── FARS: Per-file grouping ──');
const allFars = calculateAllFARS([
  { crs: 90, file: 'routes/users.js', ruleId: 'r1' },
  { crs: 85, file: 'routes/users.js', ruleId: 'r2' },
  { crs: 40, file: 'utils/helper.js', ruleId: 'r3' },
  { crs: 30, file: 'utils/helper.js', ruleId: 'r4' }
]);
assert('File count', allFars.length, 2);
assert('First file (highest)', allFars[0].farsScore > allFars[1].farsScore ? 1 : 0, 1);
console.log(`   routes/users.js FARS: ${allFars[0].farsScore}`);
console.log(`   utils/helper.js FARS: ${allFars[1].farsScore}`);

// ═══ TEST 5: PRS = P90 ═══
console.log('\n── PRS: P90 percentile ──');

// Portfolio from thesis: payment-service=88, user-mgmt=70, reporting=58, admin=38
const prsResult = calculatePRS([
  { farsScore: 88, filename: 'payment-service', maxBand: 'P0', findingCount: 5, severityDistribution: { P0: 3, P1: 1, P2: 1, P3: 0 } },
  { farsScore: 70, filename: 'user-mgmt', maxBand: 'P1', findingCount: 3, severityDistribution: { P0: 0, P1: 2, P2: 1, P3: 0 } },
  { farsScore: 58, filename: 'reporting-api', maxBand: 'P2', findingCount: 2, severityDistribution: { P0: 0, P1: 0, P2: 2, P3: 0 } },
  { farsScore: 38, filename: 'internal-admin', maxBand: 'P3', findingCount: 1, severityDistribution: { P0: 0, P1: 0, P2: 0, P3: 1 } }
]);
// P90 of [38, 58, 70, 88]: index = 0.9 × 3 = 2.7 → 70×0.3 + 88×0.7 = 82.6
assert('PRS score', prsResult.overallScore, 82.6, 1.0);
assert('PRS band', prsResult.band === 'P0' ? 1 : 0, 1);
console.log(`   PRS: ${prsResult.overallScore}, Band: ${prsResult.band}`);

// ═══ TEST 6: Percentile edge cases ═══
console.log('\n── Percentile edge cases ──');
assert('P90 of [100]', percentile([100], 90), 100);
assert('P90 of [0, 100]', percentile([0, 100], 90), 90, 0.1);
assert('P50 of [10, 20, 30, 40]', percentile([10, 20, 30, 40], 50), 25, 0.1);

// ═══ SUMMARY ═══
console.log(`\n${'═'.repeat(50)}`);
console.log(`Results: ${passed} passed, ${failed} failed`);
if (failed === 0) {
  console.log('🎉 All tests pass — FARS/PRS matches thesis formulas exactly');
} else {
  console.log('⚠️  Some tests failed — check implementation');
}
console.log(`${'═'.repeat(50)}\n`);