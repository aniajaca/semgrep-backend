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
