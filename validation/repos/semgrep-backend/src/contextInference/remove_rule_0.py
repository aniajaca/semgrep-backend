#!/usr/bin/env python3

with open('contextualFilter.js', 'r') as f:
    lines = f.readlines()

# Find and remove Rule 0 section (lines ~505-530)
new_lines = []
skip = False
for i, line in enumerate(lines):
    # Start skipping at Rule 0 comment
    if 'Rule 0: Trusted Internal Modules' in line:
        skip = True
        new_lines.append('    // Rule 0: REMOVED - Using reachability-based approach instead\n')
        continue
    
    # Stop skipping after the closing brace of the if statement
    if skip and line.strip() == '}':
        skip = False
        continue
    
    if not skip:
        new_lines.append(line)

with open('contextualFilter.js', 'w') as f:
    f.writelines(new_lines)

print("✅ Removed Rule 0 (trusted module hard filter)")
