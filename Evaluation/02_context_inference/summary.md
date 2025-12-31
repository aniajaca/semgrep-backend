Experiment 2 — Context Inference Validation (Repo-Level)

Purpose
Validate the correctness of repo-level context inference signals (internet_facing, handles_pii, prod_signals, test_only) using a small labeled set of real repositories.

Method
Predicted labels produced by RepoContextCollector.collectRepoContext() are compared against a ground-truth CSV. Accuracy is computed per attribute and overall.

Results
Overall accuracy reached 95.0% (19/20 correct). internet_facing, prod_signals, and test_only achieved 100% accuracy. The only remaining error is a handles_pii false positive on an internal tooling repository (semgrep-backend), consistent with a keyword-based heuristic.

Interpretation
The results support using context inference as an automated heuristic layer to inform filtering and prioritization, while documenting known ambiguity for handles_pii in non-application repositories.
