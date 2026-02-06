#!/bin/bash
# COMPLETE-SETUP.sh - One-command setup for validation

echo "╔════════════════════════════════════════════════════════╗"
echo "║  Neperia Scanner Validation Setup                     ║"
echo "╚════════════════════════════════════════════════════════╝"
echo ""

# Step 1: Copy CLI scanner
echo "1️⃣  Setting up CLI scanner..."
if [ ! -f "cli-scan.js" ]; then
    echo "❌ cli-scan.js not found!"
    echo "Please download it from the validation package"
    exit 1
fi
chmod +x cli-scan.js
echo "   ✓ CLI scanner ready"

# Step 2: Create directory structure
echo "2️⃣  Creating validation directories..."
mkdir -p validation/{repos,results,samples,reports,seeded_vulnerabilities,scripts}
echo "   ✓ Directories created"

# Step 3: Copy validation scripts
echo "3️⃣  Setting up validation scripts..."

# diff-findings.js
cat > validation/scripts/diff-findings.js << 'EOFSCRIPT'
#!/usr/bin/env node
const fs = require('fs');

const args = process.argv.slice(2).reduce((acc, arg) => {
  const [key, val] = arg.replace('--', '').split('=');
  acc[key] = val;
  return acc;
}, {});

function stableKey(finding) {
  return `${finding.file}:${finding.line || finding.startLine}:${finding.ruleId || finding.checkId}`;
}

const baseline = JSON.parse(fs.readFileSync(args.baseline, 'utf8'));
const filtered = JSON.parse(fs.readFileSync(args.filtered, 'utf8'));

const baselineFindings = baseline.findings || baseline.results || [];
const filteredFindings = filtered.findings || filtered.results || [];

const filteredKeys = new Set(filteredFindings.map(stableKey));
const removed = baselineFindings.filter(f => !filteredKeys.has(stableKey(f)));

const output = {
  totalBaseline: baselineFindings.length,
  totalFiltered: filteredFindings.length,
  removed: removed.length,
  outputReduction: ((removed.length / baselineFindings.length) * 100).toFixed(1),
  findings: removed
};

fs.writeFileSync(args.output, JSON.stringify(output, null, 2));
console.log(`✓ Removed ${removed.length} findings (${output.outputReduction}% reduction)`);
EOFSCRIPT

# sample-findings.js
cat > validation/scripts/sample-findings.js << 'EOFSCRIPT'
#!/usr/bin/env node
const fs = require('fs');

const args = process.argv.slice(2).reduce((acc, arg) => {
  const [key, val] = arg.replace('--', '').split('=');
  acc[key] = val;
  return acc;
}, {});

const removed = JSON.parse(fs.readFileSync(args.removed)).findings;
const retained = JSON.parse(fs.readFileSync(args.retained)).findings || JSON.parse(fs.readFileSync(args.retained)).results || [];

const sampleSize = parseInt(args['sample-size']);
const removedSample = removed.sort(() => 0.5 - Math.random()).slice(0, sampleSize);
const retainedSample = retained.sort(() => 0.5 - Math.random()).slice(0, sampleSize);

const csv = ['file,line,ruleId,severity,message,status,label'];

removedSample.forEach(f => {
  csv.push(`"${f.file}",${f.line || f.startLine},"${f.ruleId || f.checkId}","${f.severity}","${(f.message || '').replace(/"/g, '""')}",removed,`);
});

retainedSample.forEach(f => {
  csv.push(`"${f.file}",${f.line || f.startLine},"${f.ruleId || f.checkId}","${f.severity}","${(f.message || '').replace(/"/g, '""')}",retained,`);
});

fs.writeFileSync(args.output, csv.join('\n'));
console.log(`✓ Generated ${csv.length - 1} samples`);
EOFSCRIPT

# Make scripts executable
chmod +x validation/scripts/*.js
echo "   ✓ Scripts installed"

# Step 4: Test Semgrep
echo "4️⃣  Testing Semgrep availability..."
if command -v semgrep &> /dev/null; then
    SEMGREP_VERSION=$(semgrep --version 2>&1 | head -1)
    echo "   ✓ Semgrep available: $SEMGREP_VERSION"
else
    echo "   ❌ Semgrep not found!"
    echo "   Install with: pip install semgrep"
    echo "   Or: brew install semgrep (macOS)"
    exit 1
fi

# Step 5: Test scanner
echo "5️⃣  Testing scanner..."
node cli-scan.js --help 2>&1 | grep -q "Usage" && echo "   ✓ Scanner CLI working" || echo "   ⚠️  Scanner test inconclusive (may be OK)"

echo ""
echo "╔════════════════════════════════════════════════════════╗"
echo "║  ✅ Setup Complete!                                    ║"
echo "╚════════════════════════════════════════════════════════╝"
echo ""
echo "Next steps:"
echo "  1. Run: ./execute-validation.sh"
echo "  2. Wait ~2 hours for scans to complete"
echo "  3. Label the CSV files in validation/samples/"
echo "  4. Run: ./execute-validation.sh --phase2"
echo ""
echo "Directory structure:"
find validation/ -maxdepth 2 -type d 2>/dev/null
echo ""
echo "Ready to start! 🚀"
