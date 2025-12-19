#!/usr/bin/env python3
"""
Analyze which Semgrep rules cause the most False Positives
"""

import json
from collections import defaultdict
from pathlib import Path

GROUND_TRUTH = "expectedresults-1.2.json"
SCAN_RESULTS = "/tmp/owasp-final.json"

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
print("🔍 FALSE POSITIVE ANALYSIS BY RULE")
print("="*60)

ground_truth = load_ground_truth()
findings = load_scanner_results()

print(f"\n✓ Loaded {len(ground_truth)} test cases")
print(f"✓ Loaded {len(findings)} findings\n")

# Group findings by rule and test case
rule_stats = defaultdict(lambda: {'TP': 0, 'FP': 0, 'findings': []})
cwe_stats = defaultdict(lambda: {'TP': 0, 'FP': 0})

for finding in findings:
    test_name = extract_test_name(finding.get('file', ''))
    rule_id = finding.get('ruleId', 'unknown')
    cwe = finding.get('cwe', ['unknown'])[0] if finding.get('cwe') else 'unknown'
    
    if not test_name.startswith('BenchmarkTest'):
        continue
    
    actually_vuln = ground_truth.get(test_name, False)
    
    if actually_vuln:
        rule_stats[rule_id]['TP'] += 1
        cwe_stats[cwe]['TP'] += 1
    else:
        rule_stats[rule_id]['FP'] += 1
        cwe_stats[cwe]['FP'] += 1
        rule_stats[rule_id]['findings'].append(finding)

# Sort by FP count
sorted_rules = sorted(rule_stats.items(), key=lambda x: x[1]['FP'], reverse=True)

print("="*60)
print("TOP 20 RULES BY FALSE POSITIVE COUNT:")
print("="*60)
print(f"{'Rank':<6}{'FP':<8}{'TP':<8}{'Precision':<12}{'Rule ID':<50}")
print("-"*60)

for i, (rule_id, stats) in enumerate(sorted_rules[:20], 1):
    total = stats['TP'] + stats['FP']
    precision = (stats['TP'] / total * 100) if total > 0 else 0
    print(f"{i:<6}{stats['FP']:<8}{stats['TP']:<8}{precision:>6.1f}%    {rule_id[:45]}")

print("\n" + "="*60)
print("TOP 10 CWEs BY FALSE POSITIVE COUNT:")
print("="*60)

sorted_cwes = sorted(cwe_stats.items(), key=lambda x: x[1]['FP'], reverse=True)
for cwe, stats in sorted_cwes[:10]:
    total = stats['TP'] + stats['FP']
    precision = (stats['TP'] / total * 100) if total > 0 else 0
    print(f"CWE-{cwe}: {stats['FP']} FP, {stats['TP']} TP ({precision:.1f}% precision)")

# Save top FP examples
print("\n" + "="*60)
print("Saving example FPs from top 5 rules...")
print("="*60)

examples = {}
for rule_id, stats in sorted_rules[:5]:
    examples[rule_id] = {
        'fp_count': stats['FP'],
        'tp_count': stats['TP'],
        'examples': stats['findings'][:3]  # First 3 FP examples
    }

with open('fp_rule_analysis.json', 'w') as f:
    json.dump(examples, f, indent=2)

print("✓ Saved to: fp_rule_analysis.json")
print("\n" + "="*60)
