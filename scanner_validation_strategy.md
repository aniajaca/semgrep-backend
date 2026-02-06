# Neperia Scanner Re-Validation Strategy
## Post-Filter Optimization Validation Plan

**Date**: January 2026  
**Context**: After FPR reduction from 46% → 10% via contextual filter tuning  
**Goal**: Ensure Recall, Accuracy, and F1-Score remain strong while FPR is reduced

---

## 1. EXECUTIVE SUMMARY

### Critical Success Metrics
| Metric | Baseline (Dec 2025) | Target (Jan 2026) | Acceptance Criteria |
|--------|---------------------|-------------------|---------------------|
| **FPR** | 45.89% | ≤12% | ✅ Must achieve |
| **Recall (TPR)** | 90.39% | ≥85% | ⚠️ Max 5% degradation |
| **Accuracy** | 72.85% | ≥70% | ⚠️ Maintain within 3% |
| **F1-Score** | 77.47% | ≥75% | ⚠️ Maintain within 3% |
| **Precision** | 67.78% | ≥80% | ✅ Should improve |
| **Youden Index** | 44.50% | ≥75% | ✅ Target improvement |

**Risk Assessment**: Aggressive filtering to reduce FPR risks increasing False Negatives (degrading Recall). Must validate that real vulnerabilities are not being filtered out.

---

## 2. VALIDATION METHODOLOGY

### Phase 1: OWASP Benchmark Full Re-Run (PRIMARY VALIDATION)

**Objective**: Reproduce exact baseline conditions with updated filter

#### 2.1 Test Execution
```bash
# Run scanner on OWASP Benchmark v1.2 (2740 test cases)
npm run validate:owasp-benchmark -- \
  --benchmark-mode=true \
  --filterTestFiles=true \
  --filterExampleCode=true \
  --filterInjectionWithoutInput=true \
  --detectSanitization=true \
  --aggressiveMode=false \
  --verbose=true

# Expected output: Performance metrics matching target thresholds
```

#### 2.2 Metrics Collection
Generate comprehensive report capturing:
- **Confusion Matrix**: TP, FP, TN, FN counts
- **Aggregate Metrics**: Accuracy, F1, Precision, Recall, FPR, Youden
- **Per-Category Performance**: All 11 vulnerability types
- **Statistical Significance**: Compare with baseline using McNemar's test

#### 2.3 Category-Specific Analysis
For each of 11 categories, validate:

| Category | Baseline F1 | Baseline TPR | Baseline FPR | Target F1 | Priority |
|----------|-------------|--------------|--------------|-----------|----------|
| **CRYPTO** | 95.9% | 100.0% | 9.5% | ≥95% | ⭐ MAINTAIN |
| **WEAKRAND** | 96.5% | 100.0% | 5.8% | ≥95% | ⭐ MAINTAIN |
| **HASH** | 78.4% | 70.5% | 11.2% | ≥75% | ⚠️ MONITOR |
| **SQLI** | 73.2% | 93.8% | 73.3% | ≥75% | 🔥 CRITICAL |
| **XSS** | 72.7% | 82.1% | 51.7% | ≥75% | 🔥 CRITICAL |
| **PATHTRAVER** | 67.2% | 91.7% | 80.0% | ≥70% | 🔥 CRITICAL |
| **CMDI** | 66.3% | 92.9% | 88.0% | ≥70% | 🔥 CRITICAL |
| **XPATHI** | 65.1% | 93.3% | 70.0% | ≥70% | 🔥 CRITICAL |
| **LDAPI** | 64.2% | 96.3% | 87.5% | ≥70% | 🔥 CRITICAL |

**Critical Categories**: SQLI, XSS, PathTraversal, CMDI, XPATHI, LDAPI (high FPR in baseline)

---

### Phase 2: Regression Testing (SAFETY NET)

**Objective**: Ensure no regressions in previously passing tests

#### 2.1 Unit Test Suite
```bash
# Run full test suite with coverage reporting
npm test -- --coverage --verbose

# Acceptance: ≥70% coverage maintained (baseline: 72.05%)
# Acceptance: ≥550 passing tests (baseline: 550)
# Acceptance: Zero new failing tests
```

#### 2.2 Integration Tests
Focus on filter pipeline:
```bash
# Test contextual filter with known-good samples
npm run test:integration -- --grep "contextual.*filter"

# Test risk scoring with filtered findings
npm run test:integration -- --grep "risk.*calculator"

# Validate end-to-end flow: SAST → Filter → Risk → Report
npm run test:integration -- --grep "end.*to.*end"
```

#### 2.3 Golden File Validation
Compare outputs against known-good test cases:
```bash
# Run scanner on validation corpus (50 curated files)
npm run validate:golden-files

# Acceptance: Zero deviations from expected findings
# Acceptance: All context inference flags match expected values
# Acceptance: All risk scores within ±5% of expected
```

---

### Phase 3: Context Inference Accuracy Validation

**Objective**: Verify automated context detection maintains 95% accuracy

#### 3.1 Context Factor Validation
Test 200 sample files with ground truth labels:

| Context Factor | Samples | Expected Accuracy | Validation Method |
|----------------|---------|-------------------|-------------------|
| **internetFacing** | 50 | ≥95% | Manual review of API routes/endpoints |
| **noAuth** | 50 | ≥95% | Check auth middleware detection |
| **handlesPII** | 50 | ≥95% | Verify PII pattern matching |
| **production** | 50 | ≥95% | Validate env detection (NODE_ENV, configs) |

```bash
# Run context inference validation
npm run validate:context-inference -- \
  --sample-size=200 \
  --ground-truth-file=./validation/context_ground_truth.json
```

#### 3.2 Filter Decision Audit
Manually review 100 filtered findings:
```bash
# Extract filtered findings with reasons
npm run audit:filtered-findings -- \
  --limit=100 \
  --output=./validation/filtered_audit.json
```

**Manual Review Checklist**:
- [ ] All filtered findings are truly false positives (0% FN in filtered set)
- [ ] Filter reasons are accurate and explainable
- [ ] No high-severity vulnerabilities incorrectly filtered
- [ ] Protection detection (sanitization) is accurate

---

### Phase 4: Real-World Validation (GROUND TRUTH)

**Objective**: Test on real codebases with known vulnerabilities

#### 4.1 Known Vulnerable Projects
Test on curated real-world projects:

| Project | Known Vulns | Expected Detections | Purpose |
|---------|-------------|---------------------|---------|
| **DVWA** | 12 SQLi, 8 XSS | ≥18/20 (90% recall) | Web app validation |
| **WebGoat** | 15+ various | ≥13/15 (87% recall) | Educational baseline |
| **Juice Shop** | 20+ various | ≥17/20 (85% recall) | Modern app testing |

```bash
# Clone and scan each project
./scripts/validate-real-world.sh --projects=DVWA,WebGoat,JuiceShop
```

#### 4.2 Self-Scan Analysis
Re-scan Neperia scanner codebase:
```bash
# Scan own codebase with new filter
npm run scan:self -- --output=./validation/self_scan_jan2026.json

# Compare with previous self-scan (pre-filter tuning)
npm run compare-scans -- \
  --baseline=./validation/self_scan_dec2025.json \
  --current=./validation/self_scan_jan2026.json
```

**Acceptance Criteria**:
- FPR reduced by ≥70% (from manual review baseline)
- No new security issues introduced
- All test/example code findings appropriately filtered

---

## 3. STATISTICAL VALIDATION

### 3.1 McNemar's Test (Baseline vs. Current)
Test if changes are statistically significant:

```python
from scipy.stats import mcnemar

# Confusion matrices: baseline vs. current
baseline_cm = [[TP_base, FP_base], [FN_base, TN_base]]
current_cm = [[TP_curr, FP_curr], [FN_curr, TN_curr]]

# Compute McNemar statistic
result = mcnemar(baseline_cm, current_cm)
print(f"p-value: {result.pvalue}")
# Acceptance: p < 0.05 (statistically significant improvement)
```

### 3.2 Performance Degradation Analysis
Calculate metric changes:

```python
metrics = {
    'Recall': (90.39, current_recall),
    'Accuracy': (72.85, current_accuracy),
    'F1': (77.47, current_f1),
    'FPR': (45.89, current_fpr)
}

for metric, (baseline, current) in metrics.items():
    change_pct = ((current - baseline) / baseline) * 100
    print(f"{metric}: {baseline:.2f}% → {current:.2f}% ({change_pct:+.2f}%)")
    
    # Flag if degradation exceeds threshold
    if metric in ['Recall', 'Accuracy', 'F1'] and change_pct < -5:
        print(f"⚠️ WARNING: {metric} degraded by {change_pct:.2f}%")
```

---

## 4. REPORTING & DOCUMENTATION

### 4.1 Validation Report Structure
```markdown
# Scanner Validation Report - January 2026

## Executive Summary
- **Validation Date**: [DATE]
- **Scanner Version**: [VERSION]
- **OWASP Benchmark Version**: 1.2 (2740 test cases)

## Key Findings
| Metric | Baseline (Dec 2025) | Current (Jan 2026) | Change | Status |
|--------|---------------------|---------------------|---------|--------|
| FPR | 45.89% | XX.XX% | -XX.XX% | ✅/❌ |
| Recall | 90.39% | XX.XX% | ±XX.XX% | ✅/❌ |
| Accuracy | 72.85% | XX.XX% | ±XX.XX% | ✅/❌ |
| F1-Score | 77.47% | XX.XX% | ±XX.XX% | ✅/❌ |

## Per-Category Analysis
[Detailed breakdown for all 11 categories]

## Context Inference Accuracy
- internetFacing: XX% (target: ≥95%)
- noAuth: XX% (target: ≥95%)
- handlesPII: XX% (target: ≥95%)
- production: XX% (target: ≥95%)

## Real-World Validation
- DVWA: XX/20 detected (baseline: 18/20)
- WebGoat: XX/15 detected (baseline: 13/15)

## Statistical Significance
- McNemar's test p-value: X.XXXX
- Conclusion: [SIGNIFICANT/NOT SIGNIFICANT]

## Recommendations
[Action items if any metrics are out of bounds]
```

### 4.2 Comparison Visualization
Generate charts:
- Confusion matrix comparison (baseline vs. current)
- Per-category F1-Score comparison (radar chart)
- Precision-Recall curve (before/after)
- FPR vs. TPR trade-off curve

---

## 5. ACCEPTANCE CRITERIA & GO/NO-GO DECISION

### ✅ PASS Criteria (All must be met)
1. **FPR ≤ 12%** (primary goal achieved)
2. **Recall ≥ 85%** (max 5% degradation from 90.39%)
3. **Accuracy ≥ 70%** (within 3% of 72.85%)
4. **F1-Score ≥ 75%** (within 3% of 77.47%)
5. **Context Inference ≥ 95%** accuracy across all factors
6. **Zero Critical Regressions** (no new failing tests)
7. **Real-World Recall ≥ 85%** on DVWA/WebGoat/JuiceShop

### ⚠️ CONDITIONAL PASS (Requires Mitigation)
- If Recall drops 5-10%: Document affected categories, create remediation plan
- If Accuracy drops 3-5%: Investigate filter rules, consider tuning
- If any category F1 drops >10%: Flag for immediate investigation

### ❌ FAIL Criteria (Rollback Required)
1. **Recall < 80%** (excessive FN rate)
2. **Any critical category (SQLI, XSS) Recall < 80%**
3. **Context Inference < 90%** (filter decisions unreliable)
4. **Real-World Recall < 75%** (fails practical validation)

---

## 6. EXECUTION CHECKLIST

### Pre-Validation Setup
- [ ] Backup current scanner configuration
- [ ] Document all filter rule changes since December
- [ ] Prepare OWASP Benchmark v1.2 environment
- [ ] Set up validation corpus (DVWA, WebGoat, JuiceShop)
- [ ] Create ground truth dataset for context inference

### Validation Execution (Estimated: 4-6 hours)
- [ ] Run OWASP Benchmark full suite (~2 hours)
- [ ] Run unit test suite with coverage (~30 minutes)
- [ ] Run integration tests (~30 minutes)
- [ ] Execute golden file validation (~1 hour)
- [ ] Validate context inference accuracy (~1 hour)
- [ ] Scan real-world projects (~1 hour)
- [ ] Perform statistical analysis (~30 minutes)

### Post-Validation Analysis (Estimated: 2-3 hours)
- [ ] Generate validation report
- [ ] Create comparison visualizations
- [ ] Document any degradations or anomalies
- [ ] Calculate statistical significance
- [ ] Make GO/NO-GO recommendation

### Documentation & Thesis Integration
- [ ] Update Architecture Document (Section 7.2: Validation Results)
- [ ] Prepare validation methodology for thesis Chapter 4
- [ ] Document filter tuning decisions (ADR-XX)
- [ ] Create appendix with full OWASP Benchmark results

---

## 7. RISK MITIGATION STRATEGIES

### If Recall Degrades Significantly (>5%)
**Root Cause Analysis**:
1. Identify which categories lost detections
2. Review filtered findings in those categories
3. Check if filter rules are too aggressive

**Mitigation Options**:
1. **Selective Rollback**: Revert specific filter rules for affected categories
2. **Confidence Threshold Tuning**: Lower confidence threshold for critical categories
3. **Protection Detection Refinement**: Improve sanitization detection to reduce FP without FN

### If Context Inference Accuracy Drops (<95%)
**Root Cause Analysis**:
1. Review false positive/negative context inferences
2. Check if project structure changed (new patterns)
3. Validate AST parsing for edge cases

**Mitigation Options**:
1. **Pattern Library Update**: Add missing patterns to context detection
2. **Fallback Strategies**: Implement conservative defaults when uncertain
3. **Manual Override Mechanism**: Allow users to provide context hints

### If Real-World Validation Fails
**Root Cause Analysis**:
1. Compare OWASP Benchmark findings vs. real-world findings
2. Check if real-world apps use newer frameworks/libraries
3. Validate that known vulnerabilities are in scope

**Mitigation Options**:
1. **Ruleset Expansion**: Add rules for missing vulnerability patterns
2. **Framework Support**: Enhance support for specific frameworks
3. **Hybrid Approach**: Combine static analysis with dynamic testing (DAST)

---

## 8. THESIS INTEGRATION GUIDANCE

### Chapter 4: Validation & Evaluation
Include sections:

1. **4.1 Validation Methodology**
   - Explain OWASP Benchmark as ground truth
   - Describe metrics selection rationale
   - Document statistical methods (McNemar's test)

2. **4.2 Baseline Performance Analysis**
   - Present December 2025 results
   - Discuss FPR challenge (45.89%)
   - Justify filter optimization approach

3. **4.3 Filter Optimization Results**
   - Show FPR reduction: 45.89% → ~10%
   - Demonstrate Recall preservation: 90.39% → ≥85%
   - Analyze Precision improvement: 67.78% → ≥80%

4. **4.4 Context Inference Validation**
   - Present 95% accuracy results
   - Show per-factor breakdown
   - Discuss edge cases and limitations

5. **4.5 Real-World Applicability**
   - DVWA/WebGoat/JuiceShop results
   - Self-scan findings
   - Comparison with commercial SAST tools

6. **4.6 Statistical Significance**
   - McNemar's test results
   - Confidence intervals
   - Limitations and threats to validity

### Key Figures for Thesis
1. Confusion matrix comparison (before/after)
2. Precision-Recall curve
3. Per-category performance radar chart
4. Context inference accuracy breakdown
5. Youden Index improvement visualization

---

## 9. TIMELINE & RESOURCE ALLOCATION

### Recommended Timeline
- **Week 1 (Jan 8-14)**: Execute full validation suite
- **Week 2 (Jan 15-21)**: Analyze results, create report
- **Week 3 (Jan 22-28)**: Implement mitigation if needed, re-validate
- **Week 4 (Jan 29-Feb 4)**: Finalize documentation for thesis

### Resource Requirements
- **Compute**: OWASP Benchmark scan (~2 CPU hours)
- **Storage**: ~500MB for validation artifacts
- **Manual Effort**: ~10-15 hours total (execution + analysis)

---

## 10. SUCCESS INDICATORS FOR THESIS DEFENSE

### Demonstrates Academic Rigor
✅ Systematic validation methodology  
✅ Statistical significance testing  
✅ Multiple validation approaches (benchmark + real-world)  
✅ Transparent reporting of limitations  

### Validates Core Thesis Claims
✅ Context-aware filtering reduces FPR by >70%  
✅ Recall degradation minimal (<5%)  
✅ Context inference accuracy ≥95%  
✅ Practical applicability on real codebases  

### Competitive Performance
✅ FPR competitive with best-in-class (Qwiet AI: 25%)  
✅ Recall superior to commercial average (30-40%)  
✅ Youden Index improvement significant  

---

## APPENDIX A: Validation Scripts

### A.1 OWASP Benchmark Runner
```bash
#!/bin/bash
# validate-owasp-benchmark.sh

BENCHMARK_PATH="./benchmarks/owasp-benchmark-1.2"
OUTPUT_DIR="./validation/results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

echo "Starting OWASP Benchmark validation..."
npm run scan -- \
  --target="$BENCHMARK_PATH" \
  --benchmark-mode=true \
  --output="$OUTPUT_DIR/benchmark_${TIMESTAMP}.json" \
  --verbose

echo "Generating performance report..."
node ./scripts/generate-benchmark-report.js \
  --input="$OUTPUT_DIR/benchmark_${TIMESTAMP}.json" \
  --output="$OUTPUT_DIR/benchmark_report_${TIMESTAMP}.html"

echo "Validation complete. Report: $OUTPUT_DIR/benchmark_report_${TIMESTAMP}.html"
```

### A.2 Metrics Comparison Script
```javascript
// compare-metrics.js
const baseline = require('./validation/baseline_dec2025.json');
const current = require('./validation/current_jan2026.json');

function compareMetrics(base, curr) {
  const metrics = ['accuracy', 'f1Score', 'precision', 'recall', 'fpr'];
  
  console.log('Metric Comparison:');
  console.log('==================');
  
  metrics.forEach(metric => {
    const baseVal = base[metric];
    const currVal = curr[metric];
    const change = ((currVal - baseVal) / baseVal) * 100;
    const status = Math.abs(change) < 5 ? '✅' : '⚠️';
    
    console.log(`${metric}: ${baseVal.toFixed(2)}% → ${currVal.toFixed(2)}% (${change:+.2f}%) ${status}`);
  });
}

compareMetrics(baseline, current);
```

---

## APPENDIX B: Manual Review Template

### Filtered Findings Audit Template
```markdown
# Filtered Finding Review

**Finding ID**: [AUTO-GENERATED]
**File**: [PATH]
**Line**: [NUMBER]
**Vulnerability Type**: [TYPE]
**Filter Reason**: [REASON]
**Filter Confidence**: [0.00-1.00]

## Ground Truth Assessment
- [ ] True Positive (incorrectly filtered - FALSE NEGATIVE)
- [ ] True Negative (correctly filtered - TRUE NEGATIVE)

## Context Validation
- [ ] internetFacing detection accurate
- [ ] noAuth detection accurate
- [ ] handlesPII detection accurate
- [ ] production detection accurate

## Filter Decision
- [ ] CORRECT: Finding is indeed a false positive
- [ ] INCORRECT: Finding is a real vulnerability (CRITICAL)
- [ ] UNCERTAIN: Requires deeper analysis

## Notes
[Additional observations]
```

---

**END OF VALIDATION STRATEGY**

*This document should be executed immediately to ensure scanner quality before thesis finalization.*
