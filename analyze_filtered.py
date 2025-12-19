import json

# Load ground truth
with open('expectedresults-1.2.json') as f:
    ground_truth_data = json.load(f)

ground_truth = {}
for tc in ground_truth_data['testCases']:
    test_name = f"BenchmarkTest{tc['testNumber']:05d}"
    ground_truth[test_name] = tc['isVulnerable']

# Load our results
with open('/tmp/owasp-constant-branch.json') as f:
    our_results = json.load(f)

# Get test cases we found
our_findings = set()
for finding in our_results['findings']:
    test_name = finding['file'].split('/')[-1].replace('.java', '')
    if test_name.startswith('BenchmarkTest'):
        our_findings.add(test_name)

print("Checking if we filtered any VULNERABLE test cases...\n")

filtered_vulnerable = []
for test_name, is_vuln in ground_truth.items():
    if is_vuln and test_name not in our_findings:
        filtered_vulnerable.append(test_name)

print(f"We filtered {len(filtered_vulnerable)} VULNERABLE test cases (FN)!")
print("\nFirst 20:")
for test in filtered_vulnerable[:20]:
    print(f"  {test}")

print(f"\nTotal FN: {len(filtered_vulnerable)}")
print(f"These are real vulnerabilities we should NOT have filtered!")
