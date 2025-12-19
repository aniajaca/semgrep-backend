import json

# Load ground truth
with open('expectedresults-1.2.json') as f:
    ground_truth_data = json.load(f)

ground_truth = {}
for tc in ground_truth_data['testCases']:
    test_name = f"BenchmarkTest{tc['testNumber']:05d}"
    ground_truth[test_name] = tc['isVulnerable']

# Load BASELINE (before constant branch)
with open('/tmp/owasp-final.json') as f:
    baseline = json.load(f)

baseline_findings = set()
for finding in baseline['findings']:
    test_name = finding['file'].split('/')[-1].replace('.java', '')
    if test_name.startswith('BenchmarkTest'):
        baseline_findings.add(test_name)

# Load NEW (with constant branch)
with open('/tmp/owasp-constant-branch.json') as f:
    new_results = json.load(f)

new_findings = set()
for finding in new_results['findings']:
    test_name = finding['file'].split('/')[-1].replace('.java', '')
    if test_name.startswith('BenchmarkTest'):
        new_findings.add(test_name)

# Find vulnerable tests
vulnerable_tests = {name for name, is_vuln in ground_truth.items() if is_vuln}

baseline_fn = vulnerable_tests - baseline_findings
new_fn = vulnerable_tests - new_findings

# What changed?
newly_filtered_vulnerable = new_fn - baseline_fn

print(f"Baseline FN: {len(baseline_fn)}")
print(f"New FN: {len(new_fn)}")
print(f"Newly filtered vulnerable: {len(newly_filtered_vulnerable)}")

if newly_filtered_vulnerable:
    print(f"\n❌ These {len(newly_filtered_vulnerable)} vulnerable tests were NEW FN:")
    for test in sorted(newly_filtered_vulnerable)[:20]:
        print(f"  {test}")
