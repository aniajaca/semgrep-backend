console.log('Testing imports...');

try {
  require('./src/taxonomy');
  console.log('✓ taxonomy');
} catch(e) {
  console.log('✗ taxonomy:', e.message);
}

try {
  require('./src/lib/normalize');
  console.log('✓ normalize');
} catch(e) {
  console.log('✗ normalize:', e.message);
}

try {
  require('./src/enhancedRiskCalculator');
  console.log('✓ enhancedRiskCalculator');
} catch(e) {
  console.log('✗ enhancedRiskCalculator:', e.message);
}

try {
  require('./src/server');
  console.log('✓ server');
} catch(e) {
  console.log('✗ server:', e.message);
}

console.log('\nDone!');
