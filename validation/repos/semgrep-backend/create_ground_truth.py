#!/usr/bin/env python3
import csv
import json

print("Converting expectedresults-1.2.csv to JSON...")

test_cases = []

with open('BenchmarkJava/expectedresults-1.2.csv', 'r') as f:
    reader = csv.DictReader(f)
    for row in reader:
        test_name = row['# test name'].strip()
        test_number = test_name.replace('BenchmarkTest', '')
        is_vuln = row[' real vulnerability'].strip().lower() == 'true'
        
        test_cases.append({
            'testNumber': int(test_number),
            'isVulnerable': is_vuln
        })

output = {'testCases': test_cases}

with open('expectedresults-1.2.json', 'w') as f:
    json.dump(output, f, indent=2)

print(f"✓ Created expectedresults-1.2.json with {len(test_cases)} test cases")
print(f"✓ Vulnerable: {sum(1 for t in test_cases if t['isVulnerable'])}")
