#!/bin/bash

# Cleanup script to remove redundant files

echo "🧹 Cleaning up redundant files..."

# Remove redundant calculators
if [ -f "src/lib/sophisticatedRiskCalculator.js" ]; then
  rm src/lib/sophisticatedRiskCalculator.js
  echo "✅ Deleted sophisticatedRiskCalculator.js"
fi

if [ -f "src/lib/productionRiskCalculator.js" ]; then
  rm src/lib/productionRiskCalculator.js
  echo "✅ Deleted productionRiskCalculator.js"
fi

if [ -f "src/sophisticatedRiskCalculator.js" ]; then
  rm src/sophisticatedRiskCalculator.js
  echo "✅ Deleted sophisticatedRiskCalculator.js (from src/)"
fi

if [ -f "src/productionRiskCalculator.js" ]; then
  rm src/productionRiskCalculator.js
  echo "✅ Deleted productionRiskCalculator.js (from src/)"
fi

# Remove unused API endpoints file
if [ -f "src/api/riskProfileEndpoints.js" ]; then
  rm src/api/riskProfileEndpoints.js
  echo "✅ Deleted riskProfileEndpoints.js"
fi

if [ -f "src/riskProfileEndpoints.js" ]; then
  rm src/riskProfileEndpoints.js
  echo "✅ Deleted riskProfileEndpoints.js"
fi

# Remove empty api directory if exists
if [ -d "src/api" ] && [ -z "$(ls -A src/api)" ]; then
  rmdir src/api
  echo "✅ Removed empty api directory"
fi

echo "✨ Cleanup complete!"