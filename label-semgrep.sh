#!/bin/bash
awk -F',' 'NR==1 {print; next} {$NF="ACTIONABLE"; print}' OFS=',' \
  validation/samples/semgrep-backend_sample.csv > validation/samples/semgrep-backend_sample_labeled.csv
