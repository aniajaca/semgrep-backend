#!/bin/bash
set -e

echo "════════════════════════════════════════════════════"
echo "  Neperia Scanner Re-Validation (REALISTIC)"
echo "════════════════════════════════════════════════════"
echo ""

mkdir -p validation/{repos,results,samples,reports}

echo "Step 1: Setting up repositories..."
if [ ! -d "validation/repos/express" ]; then
    git clone --depth=1 https://github.com/expressjs/express.git validation/repos/express
fi
if [ ! -d "validation/repos/lodash" ]; then
    git clone --depth=1 https://github.com/lodash/lodash.git validation/repos/lodash
fi
echo "✓ Repositories ready"
echo ""

echo "Step 2: Scanning repositories..."
echo ""

# Semgrep-backend
echo "[1/3] Scanning semgrep-backend/src..."
node cli-scan.js --target=./src --filter=OFF --output=validation/results/semgrep-backend_nofilter.json 2>&1 | grep -E "✅|findings"
node cli-scan.js --target=./src --filter=ON --output=validation/results/semgrep-backend_filtered.json 2>&1 | grep -E "✅|findings|filtered"

# Express
echo "[2/3] Scanning express..."
node cli-scan.js --target=validation/repos/express --filter=OFF --output=validation/results/express_nofilter.json 2>&1 | grep -E "✅|findings"
node cli-scan.js --target=validation/repos/express --filter=ON --output=validation/results/express_filtered.json 2>&1 | grep -E "✅|findings|filtered"

# Lodash  
echo "[3/3] Scanning lodash..."
node cli-scan.js --target=validation/repos/lodash --filter=OFF --output=validation/results/lodash_nofilter.json 2>&1 | grep -E "✅|findings"
node cli-scan.js --target=validation/repos/lodash --filter=ON --output=validation/results/lodash_filtered.json 2>&1 | grep -E "✅|findings|filtered"

echo ""
echo "✓ All scans complete!"
echo ""

# Generate samples
echo "Step 3: Generating samples..."
for repo in semgrep-backend express lodash; do
    if [ -f "validation/results/${repo}_nofilter.json" ]; then
        echo "  Processing $repo..."
        node validation/scripts/diff-findings.js \
            --baseline="validation/results/${repo}_nofilter.json" \
            --filtered="validation/results/${repo}_filtered.json" \
            --output="validation/samples/${repo}_removed.json" 2>&1 | tail -1
        
        node validation/scripts/sample-findings.js \
            --removed="validation/samples/${repo}_removed.json" \
            --retained="validation/results/${repo}_filtered.json" \
            --sample-size=50 \
            --output="validation/samples/${repo}_sample.csv" 2>&1 | tail -1
    fi
done

echo ""
echo "════════════════════════════════════════════════════"
echo "  COMPLETE!"
echo "════════════════════════════════════════════════════"
echo ""
echo "Results:"
for repo in semgrep-backend express lodash; do
    if [ -f "validation/results/${repo}_filtered.json" ]; then
        BEFORE=$(jq '.summary.beforeFilter' "validation/results/${repo}_filtered.json")
        AFTER=$(jq '.summary.total' "validation/results/${repo}_filtered.json")
        RATE=$(jq -r '.summary.filterRate' "validation/results/${repo}_filtered.json")
        echo "  $repo: $BEFORE → $AFTER findings ($RATE filtered)"
    fi
done
echo ""
echo "Next: Label CSV files in validation/samples/"
