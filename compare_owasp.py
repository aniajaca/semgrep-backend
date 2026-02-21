#!/usr/bin/env python3
"""
compare_owasp.py
Compares OWASP Benchmark results: baseline (known) vs filtered scan.
Uses ground truth CSV + filtered scan JSON.

Usage:
  python3 compare_owasp.py ~/BenchmarkJava/expectedresults-1.2.csv /tmp/owasp-with-filter.json
"""
import csv
import json
import sys

# Known baseline results (filter OFF)
BASELINE = {
    "TP": 1279, "FP": 608, "TN": 717, "FN": 136,
    "TPR": 90.39, "FPR": 45.89, "Precision": 67.78, "F1": 77.47,
    "total_detected": 1887
}

def main():
    if len(sys.argv) < 3:
        print("Usage: python3 compare_owasp.py <expectedresults-1.2.csv> <owasp-with-filter.json>")
        sys.exit(1)

    gt_path = sys.argv[1]
    filtered_path = sys.argv[2]

    # Load ground truth
    ground_truth = {}
    with open(gt_path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            # CSV has columns like: # test name, category, real vulnerability, CWE
            test_name = row.get("# test name", row.get("test name", "")).strip()
            is_vuln_raw = row.get("real vulnerability", row.get("vuln", "")).strip().lower()
            is_vuln = is_vuln_raw in ("true", "1", "yes")
            if test_name:
                ground_truth[test_name] = is_vuln

    print(f"Ground truth loaded: {len(ground_truth)} test cases")
    total_real_vulns = sum(1 for v in ground_truth.values() if v)
    total_real_safe = sum(1 for v in ground_truth.values() if not v)
    print(f"  Real vulnerabilities: {total_real_vulns}")
    print(f"  Real safe: {total_real_safe}")

    # Load filtered scan results
    with open(filtered_path) as f:
        scan_data = json.load(f)

    findings = scan_data.get("findings", scan_data.get("results", []))
    print(f"Filtered scan findings: {len(findings)}")

    # Extract detected test names (deduplicate)
    detected_tests = set()
    for finding in findings:
        filepath = finding.get("file", finding.get("path", ""))
        filename = filepath.split("/")[-1].replace(".java", "")
        detected_tests.add(filename)

    print(f"Unique test files with findings: {len(detected_tests)}")

    # Compute confusion matrix
    TP = 0  # truly vulnerable AND detected
    FP = 0  # truly safe AND detected
    TN = 0  # truly safe AND not detected
    FN = 0  # truly vulnerable AND not detected

    for test_name, is_vuln in ground_truth.items():
        detected = test_name in detected_tests
        if is_vuln and detected:
            TP += 1
        elif is_vuln and not detected:
            FN += 1
        elif not is_vuln and detected:
            FP += 1
        elif not is_vuln and not detected:
            TN += 1

    total = TP + FP + TN + FN
    TPR = (TP / (TP + FN) * 100) if (TP + FN) > 0 else 0
    FPR = (FP / (FP + TN) * 100) if (FP + TN) > 0 else 0
    Precision = (TP / (TP + FP) * 100) if (TP + FP) > 0 else 0
    F1 = (2 * Precision * TPR / (Precision + TPR)) if (Precision + TPR) > 0 else 0

    print()
    print("=" * 70)
    print("OWASP BENCHMARK COMPARISON: BASELINE vs FILTERED")
    print("=" * 70)
    print()
    print(f"{'Metric':<20} {'Baseline (filter OFF)':<25} {'Filtered (filter ON)':<25} {'Delta'}")
    print("-" * 70)
    print(f"{'TP':<20} {BASELINE['TP']:<25} {TP:<25} {TP - BASELINE['TP']:+d}")
    print(f"{'FP':<20} {BASELINE['FP']:<25} {FP:<25} {FP - BASELINE['FP']:+d}")
    print(f"{'TN':<20} {BASELINE['TN']:<25} {TN:<25} {TN - BASELINE['TN']:+d}")
    print(f"{'FN':<20} {BASELINE['FN']:<25} {FN:<25} {FN - BASELINE['FN']:+d}")
    print(f"{'Total detected':<20} {BASELINE['total_detected']:<25} {TP + FP:<25} {(TP + FP) - BASELINE['total_detected']:+d}")
    print()
    print(f"{'TPR':<20} {BASELINE['TPR']:<24.2f}% {TPR:<24.2f}% {TPR - BASELINE['TPR']:+.2f}%")
    print(f"{'FPR':<20} {BASELINE['FPR']:<24.2f}% {FPR:<24.2f}% {FPR - BASELINE['FPR']:+.2f}%")
    print(f"{'Precision':<20} {BASELINE['Precision']:<24.2f}% {Precision:<24.2f}% {Precision - BASELINE['Precision']:+.2f}%")
    print(f"{'F1':<20} {BASELINE['F1']:<24.2f}% {F1:<24.2f}% {F1 - BASELINE['F1']:+.2f}%")

    # Classify the 21 removed findings
    removed_vulns = BASELINE['TP'] - TP  # TPs that became FNs
    removed_safe = BASELINE['FP'] - FP   # FPs that became TNs (good!)

    print()
    print("=" * 70)
    print(f"FILTER IMPACT ANALYSIS ({BASELINE['total_detected'] - (TP + FP)} findings removed)")
    print("=" * 70)
    print(f"  FPs correctly removed (now TN):  {removed_safe}")
    print(f"  TPs incorrectly removed (now FN): {removed_vulns}")
    print()
    if removed_vulns == 0:
        print("  EXCELLENT: Filter removed ONLY false positives!")
    elif removed_vulns <= 3:
        print(f"  ACCEPTABLE: Filter removed {removed_safe} FPs at cost of {removed_vulns} TPs")
    else:
        print(f"  WARNING: Filter removed {removed_vulns} true positives — investigate!")

    # Interpretation for thesis
    print()
    print("=" * 70)
    print("THESIS INTERPRETATION")
    print("=" * 70)
    delta_fpr = FPR - BASELINE['FPR']
    delta_tpr = TPR - BASELINE['TPR']
    if abs(delta_fpr) < 2 and abs(delta_tpr) < 2:
        print("  Minimal change (<2% on both TPR and FPR).")
        print("  The contextual filter had negligible effect on synthetic benchmark code.")
        print("  This confirms the filter targets real-world deployment signals absent")
        print("  from synthetic test suites.")
    elif delta_fpr < -2 and abs(delta_tpr) < 2:
        print(f"  FPR improved by {abs(delta_fpr):.1f}% with minimal TPR impact ({delta_tpr:+.2f}%).")
        print("  The filter's protection detection identified safe patterns even in")
        print("  synthetic code.")
    else:
        print(f"  TPR change: {delta_tpr:+.2f}%, FPR change: {delta_fpr:+.2f}%")
        print("  Investigate which findings were removed.")

    # Save results
    results = {
        "baseline": BASELINE,
        "filtered": {
            "TP": TP, "FP": FP, "TN": TN, "FN": FN,
            "TPR": round(TPR, 2), "FPR": round(FPR, 2),
            "Precision": round(Precision, 2), "F1": round(F1, 2),
            "total_detected": TP + FP
        },
        "delta": {
            "findings_removed": BASELINE['total_detected'] - (TP + FP),
            "FPs_removed": removed_safe,
            "TPs_removed": removed_vulns,
            "TPR_delta": round(TPR - BASELINE['TPR'], 2),
            "FPR_delta": round(FPR - BASELINE['FPR'], 2),
            "F1_delta": round(F1 - BASELINE['F1'], 2)
        }
    }

    outfile = "/tmp/owasp_filter_comparison.json"
    with open(outfile, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n  Results saved to: {outfile}")

if __name__ == "__main__":
    main()