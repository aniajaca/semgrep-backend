# Experiment 3 — Contextual Filter Effectiveness

## Repository
semgrep-backend

## Objective
Demonstrate measurable noise reduction through contextual filtering of static analysis findings.

## Methodology
1. Run Semgrep with default ruleset (`--config auto`)
2. Apply contextual filter with production configuration

## Results

### Quantitative Metrics
| Metric | Value |
|--------|-------|
| Raw findings | 64 |
| Filtered out | 2 |
| Downgraded | 3 |
| Final output | 62 |
| **Reduction rate** | **3.1%** |

### Filter Breakdown
- downgrade: moderate-confidence-protection-detected: 3
- high-confidence-protection-detected: 1
- test file: 1

## Interpretation

The contextual filter reduced noise by 3.1%, removing 2 findings that are not production-relevant.

---
*Generated: 2025-12-20T16:51:23.547Z*
