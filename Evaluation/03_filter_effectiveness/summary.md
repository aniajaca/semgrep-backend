# Experiment 3 — Contextual Filter Effectiveness (Noise Reduction)

## Objective
Demonstrate measurable noise reduction through contextual filtering of static analysis findings, and show that the filter can both remove non-actionable findings and downgrade findings where protective context is detected.

## Methodology
1. Run Semgrep (`--config auto`) to produce raw findings.
2. Apply the contextual filter in production configuration.
3. Outcomes:
   - Removed: excluded from final output (non-actionable noise such as tests/examples)
   - Downgraded: kept but deprioritized due to protective context

## Results (two representative repositories)

### next.js (framework repository with extensive tests/examples)
- Raw findings: 767
- Removed: 77 (10.0%)
- Downgraded: 101
- Final output: 690
- Dominant reasons: example code, test files, and context-signal downgrades.

### semgrep-backend (internal tooling repository)
- Raw findings: 64
- Removed: 2 (3.1%)
- Downgraded: 3
- Final output: 62
- Dominant reasons: test file removal and protection-detected downgrades.

## Interpretation
Across two different repository types, contextual filtering produced measurable noise reduction and consistent downgrading behavior. This supports the claim that the context-aware pipeline improves usability by reducing non-actionable output while preserving potentially relevant findings for prioritization.
