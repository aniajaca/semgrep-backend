#!/usr/bin/env python3
import json

with open('fp_rule_analysis.json', 'r') as f:
    data = json.load(f)

print("=== TOP 5 FP EXAMPLES ===\n")

for rule_id, info in list(data.items())[:5]:
    print(f"\n{'='*60}")
    print(f"RULE: {rule_id}")
    print(f"FP Count: {info['fp_count']}")
    print(f"{'='*60}")
    
    for i, example in enumerate(info['examples'][:2], 1):
        print(f"\n--- Example {i} ---")
        print(f"File: {example['file'].split('/')[-1]}")
        print(f"Line: {example.get('startLine', 'N/A')}")
        print(f"CWE: {example.get('cwe', ['N/A'])[0]}")
