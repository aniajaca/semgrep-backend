#!/usr/bin/env python3

with open('contextualFilter.js', 'r') as f:
    content = f.read()

# Add reachability rules BEFORE protection priority
old_priority = '''      // ========================================
      // DECISION LOGIC: Protection-First Approach
      // ========================================
      const activeCategoryCount = signals.categories.length;
      const hasProtection = signals.categories.includes('has-protection');
      const protectionConfidence = signals.scores['has-protection'] || 0;
      
      // Calculate average confidence
      const avgConfidence = Object.keys(signals.scores).length > 0
        ? Object.values(signals.scores).reduce((a, b) => a + b, 0) / Object.keys(signals.scores).length
        : 0;
      
      // PRIORITY 1: Protection detected (most important signal)'''

new_priority = '''      // ========================================
      // DECISION LOGIC: Reachability-First Approach
      // ========================================
      const activeCategoryCount = signals.categories.length;
      const hasProtection = signals.categories.includes('has-protection');
      const protectionConfidence = signals.scores['has-protection'] || 0;
      const notReachable = signals.categories.includes('not-reachable');
      const hasNoUserInput = signals.categories.includes('no-user-input');
      
      // Calculate average confidence
      const avgConfidence = Object.keys(signals.scores).length > 0
        ? Object.values(signals.scores).reduce((a, b) => a + b, 0) / Object.keys(signals.scores).length
        : 0;
      
      // PRIORITY 0: Reachability + No Input (STRONGEST signal for FP)
      // If code is not reachable from entrypoints AND has no user input, it's very likely noise
      if (notReachable && hasNoUserInput) {
        return {
          action: 'FILTER',
          reason: 'not-reachable-and-no-user-input',
          categories: signals.categories,
          details: signals.details.join('; '),
          confidence: 0.90,
          message: 'HIGH CONFIDENCE FP: Code unreachable from entrypoints with no user input'
        };
      }
      
      // Reachable but has user input → DOWNGRADE (lower priority)
      if (notReachable && !hasNoUserInput) {
        return {
          action: 'DOWNGRADE',
          reason: 'not-reachable-but-input-present',
          categories: signals.categories,
          details: signals.details.join('; '),
          confidence: 0.70,
          severityAdjustment: -1,
          message: 'MODERATE FP: Code unreachable but contains input patterns'
        };
      }
      
      // PRIORITY 1: Protection detected (second most important signal)'''

content = content.replace(old_priority, new_priority)

with open('contextualFilter.js', 'w') as f:
    f.write(content)

print("✅ Step 3: Added reachability-based decision rules")
print("\nDecision logic:")
print("  1. NOT REACHABLE + NO INPUT → FILTER (90% confidence)")
print("  2. NOT REACHABLE + HAS INPUT → DOWNGRADE (70% confidence)")
print("  3. Fall through to protection/context logic")
