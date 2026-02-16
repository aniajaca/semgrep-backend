#!/bin/bash
# execute-validation.sh - Main validation execution script
# Run this to execute the entire validation plan

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  Neperia Scanner Re-Validation Execution${NC}"
echo -e "${BLUE}  Version: 2.1 (Streamlined)${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════${NC}\n"

# Create directory structure
echo -e "${YELLOW}Setting up validation directories...${NC}"
mkdir -p validation/{repos,results,samples,reports,seeded_vulnerabilities/src/{api,lib,services},scripts}

# Track progress
PHASE_1_DONE=false
PHASE_2_DONE=false

echo -e "\n${GREEN}✓${NC} Directory structure created"

# ============================================================================
# PHASE 1: REAL REPOSITORY VALIDATION
# ============================================================================

echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}PHASE 1: Real Repository Validation${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"

# Step 1.1: Clone repositories
echo -e "${YELLOW}Step 1.1: Cloning repositories...${NC}"

if [ ! -d "validation/repos/next.js" ]; then
    echo "  Cloning next.js..."
    git clone --depth=1 https://github.com/vercel/next.js.git validation/repos/next.js 2>&1 | grep -v "^remote:"
fi

if [ ! -d "validation/repos/juice-shop" ]; then
    echo "  Cloning juice-shop..."
    git clone --depth=1 https://github.com/juice-shop/juice-shop.git validation/repos/juice-shop 2>&1 | grep -v "^remote:"
fi

if [ ! -d "validation/repos/semgrep-backend" ]; then
    echo "  Using current semgrep-backend (your project)..."
    # Assumes you're running this from semgrep-backend directory
    ln -sf "$(pwd)" validation/repos/semgrep-backend 2>/dev/null || echo "  (already linked)"
fi

echo -e "${GREEN}✓${NC} Repositories ready\n"

# Step 1.2 & 1.3: Scan repositories
echo -e "${YELLOW}Step 1.2-1.3: Scanning repositories (this will take ~2 hours)...${NC}"
echo -e "${BLUE}This is the longest phase. Good time for a coffee break!${NC}\n"

REPOS=("next.js" "juice-shop" "semgrep-backend")

for repo in "${REPOS[@]}"; do
    echo -e "${YELLOW}Scanning $repo...${NC}"
    
    # Check if already scanned
    if [ -f "validation/results/${repo}_nofilter.json" ] && [ -f "validation/results/${repo}_filtered.json" ]; then
        echo -e "  ${GREEN}✓${NC} Already scanned, skipping..."
        continue
    fi
    
    # Scan WITHOUT filter
    echo "  [1/2] Without filter..."
    npm run scan -- \
        --target="validation/repos/$repo" \
        --filter=OFF \
        --output="validation/results/${repo}_nofilter.json" \
        2>&1 | tail -5
    
    # Scan WITH filter
    echo "  [2/2] With filter..."
    npm run scan -- \
        --target="validation/repos/$repo" \
        --filter=ON \
        --output="validation/results/${repo}_filtered.json" \
        2>&1 | tail -5
    
    echo -e "  ${GREEN}✓${NC} $repo complete\n"
done

echo -e "${GREEN}✓${NC} All repository scans complete\n"

# Step 1.4: Generate diff and samples
echo -e "${YELLOW}Step 1.4: Generating samples for manual review...${NC}"

for repo in "${REPOS[@]}"; do
    if [ ! -f "validation/samples/${repo}_removed.json" ]; then
        echo "  Computing diff for $repo..."
        node validation/scripts/diff-findings.js \
            --baseline="validation/results/${repo}_nofilter.json" \
            --filtered="validation/results/${repo}_filtered.json" \
            --output="validation/samples/${repo}_removed.json"
        
        echo "  Sampling findings for $repo..."
        node validation/scripts/sample-findings.js \
            --removed="validation/samples/${repo}_removed.json" \
            --retained="validation/results/${repo}_filtered.json" \
            --sample-size=50 \
            --output="validation/samples/${repo}_sample.csv"
    fi
done

echo -e "\n${GREEN}✓${NC} Sample CSVs generated in validation/samples/"
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  PHASE 1 SCANNING COMPLETE${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}\n"

echo -e "${YELLOW}NEXT STEP: Manual Labeling${NC}"
echo -e "Open these CSV files and fill the 'label' column:"
echo -e "  1. validation/samples/next.js_sample.csv"
echo -e "  2. validation/samples/juice-shop_sample.csv"
echo -e "  3. validation/samples/semgrep-backend_sample.csv"
echo -e ""
echo -e "Labels:"
echo -e "  NON_ACTIONABLE - test/example/dev files"
echo -e "  ACTIONABLE     - production code"
echo -e "  UNCERTAIN      - can't determine"
echo -e ""
echo -e "Save each as: {repo}_sample_labeled.csv"
echo -e ""
echo -e "${YELLOW}After labeling, run:${NC}"
echo -e "  ./execute-validation.sh --phase2"
echo -e ""

# Check if we should continue to Phase 2
if [[ "$1" == "--phase2" ]]; then
    echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}Continuing to Phase 2...${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
    
    # Check if labeled files exist
    LABELED_FILES=$(ls validation/samples/*_labeled.csv 2>/dev/null | wc -l)
    if [ "$LABELED_FILES" -lt 3 ]; then
        echo -e "${RED}ERROR: Missing labeled CSV files!${NC}"
        echo -e "Expected 3 files (*_labeled.csv), found $LABELED_FILES"
        exit 1
    fi
    
    # Calculate metrics
    echo -e "${YELLOW}Calculating metrics from labeled samples...${NC}"
    node validation/scripts/calculate-metrics.js \
        --labeled-samples=validation/samples/*_labeled.csv \
        --results=validation/results \
        --output=validation/reports/metrics_summary.json
    
    echo -e "${GREEN}✓${NC} Metrics calculated\n"
    
    # Display results
    echo -e "${BLUE}Results Summary:${NC}"
    node -e "
    const results = require('./validation/reports/metrics_summary.json');
    console.log('');
    console.log('Aggregate Metrics:');
    console.log('  Removal Precision:     ' + results.aggregate.removalPrecision + '%');
    console.log('  Actionable Loss Rate:  ' + results.aggregate.actionableLossRate + '%');
    console.log('  Critical Loss:         ' + results.aggregate.criticalActionableLoss);
    console.log('  Output Reduction:      ' + results.aggregate.outputReduction + '%');
    console.log('');
    console.log('Status: ' + (
        parseFloat(results.aggregate.removalPrecision) >= 90 &&
        parseFloat(results.aggregate.actionableLossRate) <= 5 &&
        results.aggregate.criticalActionableLoss === 0
        ? '✅ PASS' : '❌ NEEDS ATTENTION'
    ));
    "
    
    echo -e "\n${YELLOW}Proceeding to Phase 2: Seeded Vulnerability Safety Check...${NC}"
    
    # Phase 2 will be triggered separately
    echo -e "\n${BLUE}Phase 1 metrics complete. Run Phase 2 with:${NC}"
    echo -e "  ./execute-validation.sh --phase2-seeded"
fi

exit 0
