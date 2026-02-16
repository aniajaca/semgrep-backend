#!/usr/bin/env python3
"""
Calculate metrics for NEW scan with contextual filtering
Compares against OWASP Benchmark ground truth
"""

import json
import csv
from collections import defaultdict
from pathlib import Path

# File paths
GROUND_TRUTH = "/Users/aniajaca/Library/Mobile Documents/com~apple~CloudDocs/Neperia/semgrep-backend/BenchmarkJava/expectedresults-1.2.csv"
NEW_SCAN_RESULTS = "/tmp/owasp-final.json"

def load_ground_truth():
    """Load OWASP Benchmark ground truth"""
    ground_truth = {}
    
    with open(GROUND_TRUTH, 'r') as f:
        for line in f:
            line = line.strip()
            # Skip header and empty lines
            if line.startswith('#') or not line:
                continue
            
            # Parse CSV: test name, category, real vulnerability, cwe
            parts = line.split(',')
            if len(parts) >= 3:
                test_name = parts[0].strip()
                category = parts[1].strip()
                is_vuln = parts[2].strip().lower() == 'true'
                
                ground_truth[test_name] = {
                    'category': category,
                    'isVulnerable': is_vuln
                }
    
    print(f"✓ Loaded {len(ground_truth)} test cases from ground truth")
    return ground_truth

def extract_test_name(filepath):
    """Extract test case name from file path"""
    # Example: .../BenchmarkTest00001.java -> BenchmarkTest00001
    filename = Path(filepath).stem
    return filename

def load_scanner_results():
    """Load NEW scanner results (after contextual filtering)"""
    with open(NEW_SCAN_RESULTS, 'r') as f:
        data = json.load(f)
    
    findings = data.get('findings', [])
    print(f"✓ Loaded {len(findings)} findings from NEW scan")
    
    # Group findings by test case
    findings_by_test = defaultdict(list)
    for finding in findings:
        filepath = finding.get('file', '')
        test_name = extract_test_name(filepath)
        if test_name.startswith('BenchmarkTest'):
            findings_by_test[test_name].append(finding)
    
    print(f"✓ Findings grouped into {len(findings_by_test)} test cases")
    return findings_by_test

def calculate_metrics(ground_truth, scanner_results):
    """Calculate TP, FP, TN, FN and metrics"""
    
    TP = 0  # Scanner found + Actually vulnerable
    FP = 0  # Scanner found + NOT vulnerable
    TN = 0  # Scanner didn't find + NOT vulnerable
    FN = 0  # Scanner didn't find + Actually vulnerable
    
    # Also track by category
    by_category = defaultdict(lambda: {'TP': 0, 'FP': 0, 'TN': 0, 'FN': 0})
    
    for test_name, gt in ground_truth.items():
        scanner_found = test_name in scanner_results
        actually_vuln = gt['isVulnerable']
        category = gt['category']
        
        if scanner_found and actually_vuln:
            TP += 1
            by_category[category]['TP'] += 1
        elif scanner_found and not actually_vuln:
            FP += 1
            by_category[category]['FP'] += 1
        elif not scanner_found and not actually_vuln:
            TN += 1
            by_category[category]['TN'] += 1
        elif not scanner_found and actually_vuln:
            FN += 1
            by_category[category]['FN'] += 1
    
    return {
        'TP': TP,
        'FP': FP,
        'TN': TN,
        'FN': FN
    }, by_category

def compute_rates(confusion_matrix):
    """Compute rates from confusion matrix"""
    TP = confusion_matrix['TP']
    FP = confusion_matrix['FP']
    TN = confusion_matrix['TN']
    FN = confusion_matrix['FN']
    
    # False Positive Rate
    FPR = (FP / (FP + TN) * 100) if (FP + TN) > 0 else 0
    
    # False Negative Rate
    FNR = (FN / (TP + FN) * 100) if (TP + FN) > 0 else 0
    
    # Precision
    precision = (TP / (TP + FP) * 100) if (TP + FP) > 0 else 0
    
    # Recall (TPR)
    recall = (TP / (TP + FN) * 100) if (TP + FN) > 0 else 0
    
    # F1 Score
    F1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0
    
    # Accuracy
    accuracy = ((TP + TN) / (TP + FP + TN + FN) * 100) if (TP + FP + TN + FN) > 0 else 0
    
    return {
        'FPR': FPR,
        'FNR': FNR,
        'Precision': precision,
        'Recall': recall,
        'F1': F1,
        'Accuracy': accuracy
    }

def print_results(confusion_matrix, rates):
    """Print results in a nice format"""
    
    print("\n" + "="*60)
    print("🎯 NEW SCAN RESULTS (WITH CONTEXTUAL FILTER)")
    print("="*60)
    
    print("\nConfusion Matrix:")
    print(f"  True Positives (TP):   {confusion_matrix['TP']:4d}")
    print(f"  False Positives (FP):  {confusion_matrix['FP']:4d}")
    print(f"  True Negatives (TN):   {confusion_matrix['TN']:4d}")
    print(f"  False Negatives (FN):  {confusion_matrix['FN']:4d}")
    
    print("\n" + "-"*60)
    print("📊 METRICS:")
    print("-"*60)
    
    # Check against targets
    fpr_status = "✅ PASS" if rates['FPR'] <= 15 else "❌ FAIL"
    fnr_status = "✅ PASS" if rates['FNR'] <= 15 else "❌ FAIL"
    f1_status = "✅ PASS" if rates['F1'] >= 70 else "❌ FAIL"
    
    print(f"  False Positive Rate:  {rates['FPR']:6.2f}%  {fpr_status}  (Target: ≤15%)")
    print(f"  False Negative Rate:  {rates['FNR']:6.2f}%  {fnr_status}  (Target: ≤15%)")
    print(f"  Precision:            {rates['Precision']:6.2f}%")
    print(f"  Recall (TPR):         {rates['Recall']:6.2f}%")
    print(f"  F1 Score:             {rates['F1']:6.2f}%  {f1_status}  (Target: ≥70%)")
    print(f"  Accuracy:             {rates['Accuracy']:6.2f}%")
    
    print("\n" + "="*60)
    print("📈 COMPARISON TO OLD RESULTS (WITHOUT FILTER):")
    print("="*60)
    
    old_fpr = 45.89
    old_f1 = 77.47
    
    fpr_improvement = old_fpr - rates['FPR']
    f1_change = rates['F1'] - old_f1
    
    print(f"  OLD FPR:  {old_fpr:.2f}%")
    print(f"  NEW FPR:  {rates['FPR']:.2f}%")
    print(f"  IMPROVEMENT: {fpr_improvement:+.2f} percentage points")
    print()
    print(f"  OLD F1:   {old_f1:.2f}%")
    print(f"  NEW F1:   {rates['F1']:.2f}%")
    print(f"  CHANGE: {f1_change:+.2f} percentage points")
    
    print("\n" + "="*60)

def main():
    print("="*60)
    print("OWASP Benchmark Metrics Calculator")
    print("NEW Scan with Contextual Filtering")
    print("="*60 + "\n")
    
    # Load data
    ground_truth = load_ground_truth()
    scanner_results = load_scanner_results()
    
    # Calculate metrics
    print("\nCalculating metrics...")
    confusion_matrix, by_category = calculate_metrics(ground_truth, scanner_results)
    rates = compute_rates(confusion_matrix)
    
    # Print results
    print_results(confusion_matrix, rates)
    
    print("\n✓ Done!\n")

if __name__ == "__main__":
    main()
