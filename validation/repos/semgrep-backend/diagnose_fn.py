#!/usr/bin/env python3
import json
import sys
from pathlib import Path

def load_json(filepath):
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading {filepath}: {e}")
        sys.exit(1)

def extract_testcase_id(filepath):
    filename = Path(filepath).stem
    if filename.startswith('BenchmarkTest'):
        return filename
    return None

print("=" * 60)
print("FN DIAGNOSTIC: Finding TPs Killed by Filter")
print("=" * 60)

# Load ground truth
print("\n[1/4] Loading OWASP Benchmark ground truth...")
ground_truth = load_json('expectedresults-1.2.json')

truth_map = {}
for test_case in ground_truth.get('testCases', []):
    test_number = test_case.get('testNumber')
    is_vulnerable = test_case.get('isVulnerable', False)
    testcase_id = f"BenchmarkTest{test_number:05d}"
    truth_map[testcase_id] = is_vulnerable

print(f"   ✓ Loaded {len(truth_map)} test cases")

# Load raw scan
print("\n[2/4] Loading RAW scan results...")
raw_results = load_json('/tmp/owasp-raw.json')

raw_testcases = set()
for finding in raw_results.get('findings', []):
    testcase_id = extract_testcase_id(finding.get('file', ''))
    if testcase_id:
        raw_testcases.add(testcase_id)

print(f"   ✓ Raw scan found {len(raw_testcases)} unique test cases")

# Load filtered scan
print("\n[3/4] Loading FILTERED scan results...")
filtered_results = load_json('/tmp/owasp-final.json')

filtered_testcases = set()
for finding in filtered_results.get('findings', []):
    testcase_id = extract_testcase_id(finding.get('file', ''))
    if testcase_id:
        filtered_testcases.add(testcase_id)

print(f"   ✓ Filtered output has {len(filtered_testcases)} unique test cases")

# Find FN cases
print("\n[4/4] Analyzing False Negatives...")

fn_cases = []
fn_killed_by_filter = {}
fn_missed_by_scanner = []

for testcase_id, is_vulnerable in truth_map.items():
    if not is_vulnerable:
        continue
    
    if testcase_id not in filtered_testcases:
        fn_cases.append(testcase_id)
        
        if testcase_id in raw_testcases:
            fn_killed_by_filter[testcase_id] = {'reason': 'filtered-out'}
        else:
            fn_missed_by_scanner.append(testcase_id)

print(f"\n   📊 FN Analysis:")
print(f"   Total FN cases: {len(fn_cases)}")
print(f"   - Killed by filter: {len(fn_killed_by_filter)}")
print(f"   - Missed by scanner: {len(fn_missed_by_scanner)}")

if len(fn_killed_by_filter) > 0:
    print(f"\n   🚨 CRITICAL: Filter removed {len(fn_killed_by_filter)} TPs!")

# Save report
output = {
    'summary': {
        'total_fn': len(fn_cases),
        'fn_killed_by_filter': len(fn_killed_by_filter),
        'fn_missed_by_scanner': len(fn_missed_by_scanner)
    },
    'testcases_killed_by_filter': list(fn_killed_by_filter.keys())[:20]
}

with open('fn_cases_due_to_filter.json', 'w') as f:
    json.dump(output, f, indent=2)

print(f"\n   ✓ Saved report to: fn_cases_due_to_filter.json")
print("\n" + "=" * 60)
print(f"Filter killed {len(fn_killed_by_filter)} true positives")
print(f"Scanner missed {len(fn_missed_by_scanner)} vulnerabilities")

if len(fn_killed_by_filter) > 100:
    print("\n🚨 CRITICAL: Filter is too aggressive!")
