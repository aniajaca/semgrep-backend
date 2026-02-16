# Experiment 3 — Contextual Filter Effectiveness

## Repository
next.js

## Objective
Demonstrate measurable noise reduction through contextual filtering of static analysis findings.

## Methodology
1. Run Semgrep with default ruleset (`--config auto`)
2. Apply contextual filter with production configuration

## Results

### Quantitative Metrics
| Metric | Value |
|--------|-------|
| Raw findings | 767 |
| Filtered out | 77 |
| Downgraded | 101 |
| Final output | 690 |
| **Reduction rate** | **10.0%** |

### Filter Breakdown
- downgrade: two-context-signals: 78
- example code: 62
- downgrade: moderate-confidence-protection-detected: 23
- test file: 9
- high-confidence-protection-detected: 5
- 3-context-signals-detected: 1

## Interpretation

The contextual filter reduced noise by 10.0%, removing 77 findings that are not production-relevant.

---
*Generated: 2025-12-20T16:43:20.438Z*
