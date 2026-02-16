#!/usr/bin/env python3
import re

FILTER_PATH = "contextualFilter.js"

print("🔧 Updating filter to use reachability-based approach...")

with open(FILTER_PATH, 'r') as f:
    content = f.read()

# Add ReachabilityAnalyzer import at top
if "const ReachabilityAnalyzer" not in content:
    content = content.replace(
        "const ConstantBranchDetector = require('./constantBranchDetector');",
        "const ConstantBranchDetector = require('./constantBranchDetector');\nconst ReachabilityAnalyzer = require('./reachabilityAnalyzer');"
    )

# Initialize in constructor
if "this.reachabilityAnalyzer" not in content:
    content = content.replace(
        "this.constantBranchDetector = new ConstantBranchDetector();",
        "this.constantBranchDetector = new ConstantBranchDetector();\n      this.reachabilityAnalyzer = new ReachabilityAnalyzer();"
    )

with open(FILTER_PATH, 'w') as f:
    f.write(content)

print("✅ Updated filter with reachability analyzer!")
print("\nNext steps:")
print("1. Modify checkInjectionContextEnhanced to use reachability")
print("2. Change internetFacing detection to be evidence-based")
print("3. Convert trusted modules to DOWNGRADE signal instead of FILTER")

