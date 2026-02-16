# Experiment 4: Risk Scoring Validation - RESULTS

**Date:** December 31, 2024
**Vulnerability Type:** Path Traversal (CWE-22)
**Hypothesis:** Identical vulnerabilities receive different risk scores based on deployment context

## Test Files

All three files contain the same vulnerability pattern: `path.join()` with unsanitized user input.

### File 1: production_api_download.js
- **Context:** internet_facing=TRUE, production=TRUE, handles_pii=TRUE
- **Scenario:** Public file download API endpoint
- **Findings:** 3 Path Traversal vulnerabilities detected by Semgrep

### File 2: internal_admin_logs.js
- **Context:** internet_facing=FALSE, production=TRUE, handles_pii=FALSE  
- **Scenario:** Internal admin log viewer (requires authentication)
- **Findings:** 2 Path Traversal vulnerabilities detected by Semgrep

### File 3: dev_file_reader.js
- **Context:** internet_facing=FALSE, production=FALSE, handles_pii=FALSE
- **Scenario:** Development testing endpoint
- **Findings:** 4 Path Traversal vulnerabilities detected by Semgrep

## Results

| File | Raw Score | Multiplier | Final Score | Priority | Match Expected? |
|------|-----------|------------|-------------|----------|-----------------|
| File 1 | 60 | 2.73x | **100** | P0 (Critical) | ✅ |
| File 2 | 60 | 1.30x | **78** | P1 (High) | ✅ |
| File 3 | 53 | 1.00x | **53** | P2 (Medium) | ✅ |

**Score Spread:** 47 points (100 - 53)

## Validation Criteria

✅ **Same vulnerability type:** All files detected as Path Traversal (CWE-22)  
✅ **Production API scored ≥90:** Actual = 100  
✅ **Internal admin scored 60-80:** Actual = 78  
✅ **Dev script scored ≤60:** Actual = 53  
✅ **Correct ordering:** 100 > 78 > 53

**Result:** ALL CRITERIA MET (5/5)

## Key Findings

1. **Environmental Multipliers Work:** The system correctly applied different multipliers based on deployment context:
   - 2.73x for internet-facing production with PII
   - 1.30x for internal production without PII
   - 1.00x for non-production development code

2. **Operationally Meaningful Scores:** The final scores align with real-world prioritization:
   - Score 100 (P0): Fix immediately - public API exposing user files
   - Score 78 (P1): Fix this sprint - internal tool with auth
   - Score 53 (P2): Fix this quarter - dev code not in production

3. **Context-Aware Beats Static Scoring:** Traditional CVSS would assign all three the same severity (Medium/6.5). Context-aware scoring differentiates them appropriately.

## Conclusion

✅ **Hypothesis Validated:** The risk scoring system successfully adjusts vulnerability severity based on deployment context, providing operationally meaningful prioritization that static CVSS scores cannot achieve.

**Thesis Contribution:** Demonstrates that automated context inference enables deployment-aware vulnerability prioritization, addressing a fundamental gap in traditional SAST tools.
