#!/usr/bin/env python3
"""
Calculate metrics for OWASP Benchmark scan
"""
import json
import sys
from pathlib import Path

if len(sys.argv) < 3:
    print("Usage: python3 calculate_metrics.py <scan_results.json> <ground_truth.json>")
    sys.exit(1)

SCAN_RESULTS = sys.argv[1]
GROUND_TRUTH = sys.argv[2]

def load_ground_truth():
    with open(GROUND_TRUTH, 'r') as f:
        data = json.load(f)
    
    ground_truth = {}
    for test_case in data['testCases']:
        test_name = f"BenchmarkTest{test_case['testNumber']:05d}"
        ground_truth[test_name] = test_case['isVulnerable']
    
    return ground_truth

def load_scanner_results():
    with open(SCAN_RESULTS, 'r') as f:
        data = json.load(f)
    
    return data.get('findings', [])

def extract_test_name(filepath):
    return Path(filepath).stem

print("="*60)
print("🎯 OWASP BENCHMARK METRICS - CONSTANT BRANCH FIX")
print("="*60)

ground_truth = load_ground_truth()
findings = load_scanner_results()

print(f"✓ Loaded {len(ground_truth)} test cases")
print(f"✓ Loaded {len(findings)} findings")

# Group findings by test case
test_findings = {}
for finding in findings:
    test_name = extract_test_name(finding.get('file', ''))
    if test_name.startswith('BenchmarkTest'):
        if test_name not in test_findings:
            test_findings[test_name] = []
        test_findings[test_name].append(finding)

print(f"✓ Grouped into {len(test_findings)} test cases")
print("Calculating metrics...")

# Calculate confusion matrix
TP = 0  # Scanner found vuln, ground truth says vuln
FP = 0  # Scanner found vuln, ground truth says safe
FN = 0  # Scanner missed vuln, ground truth says vuln
TN = 0  # Scanner found nothing, ground truth says safe

for test_name, is_vulnerable in ground_truth.items():
    scanner_found = test_name in test_findings
    
    if is_vulnerable and scanner_found:
        TP += 1
    elif not is_vulnerable and scanner_found:
        FP += 1
    elif is_vulnerable and not scanner_found:
        FN += 1
    elif not is_vulnerable and not scanner_found:
        TN += 1

# Calculate metrics
total = TP + FP + FN + TN
FPR = (FP / (FP + TN) * 100) if (FP + TN) > 0 else 0
FNR = (FN / (FN + TP) * 100) if (FN + TP) > 0 else 0
precision = (TP / (TP + FP) * 100) if (TP + FP) > 0 else 0
recall = (TP / (TP + FN) * 100) if (TP + FN) > 0 else 0
f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0

print("="*60)
print("CONFUSION MATRIX:")
print("="*60)
print(f"  TP: {TP:4d}   FP: {FP:4d}")
print(f"  FN: {FN:4d}   TN: {TN:4d}")

print("="*60)
print("📊 METRICS:")
print("="*60)
print(f"  FPR: {FPR:6.2f}%  {'✅ PASS' if FPR <= 15 else '❌ FAIL'}  (Target: ≤15%)")
print(f"  FNR: {FNR:6.2f}%  {'✅ PASS' if FNR <= 15 else '❌ FAIL'}  (Target: ≤15%)")
print(f"  Precision: {precision:6.2f}%")
print(f"  Recall: {recall:6.2f}%")
print(f"  F1: {f1:6.2f}%  {'✅ PASS' if f1 >= 70 else '❌ FAIL'}  (Target: ≥70%)")
print("="*60)
