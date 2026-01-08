#!/usr/bin/env python3

with open('contextualFilter.js', 'r') as f:
    content = f.read()

# 1. Add reachability computation in filterFindings()
old_filtering_start = '''    const filtered = [];
    const startTime = Date.now();
    
    if (this.config.verbose) {'''

new_filtering_start = '''    const filtered = [];
    const startTime = Date.now();
    
    // Compute reachability ONCE per scan (cached for all findings)
    let reachability = null;
    try {
      reachability = await this.reachabilityAnalyzer.analyzeProject(projectPath);
      if (this.config.verbose) {
        console.log(`[REACHABILITY] Total: ${reachability.totalFiles}, Reachable: ${reachability.reachableCount}, Entrypoints: ${reachability.entrypointCount}`);
      }
    } catch (err) {
      if (this.config.verbose) {
        console.log(`[REACHABILITY WARN] ${err.message}`);
      }
    }
    
    if (this.config.verbose) {'''

content = content.replace(old_filtering_start, new_filtering_start)

# 2. Pass reachability to shouldFilter
old_should_filter_call = '''      const decision = await this.shouldFilter(finding, projectPath, contextInference);'''
new_should_filter_call = '''      const decision = await this.shouldFilter(finding, projectPath, contextInference, reachability);'''

content = content.replace(old_should_filter_call, new_should_filter_call)

# 3. Update shouldFilter signature
old_signature = '''  async shouldFilter(finding, projectPath, contextInference) {'''
new_signature = '''  async shouldFilter(finding, projectPath, contextInference, reachability = null) {'''

content = content.replace(old_signature, new_signature)

# 4. Pass reachability to checkInjectionContextEnhanced
old_injection_call = '''      const injectionCheck = await this.checkInjectionContextEnhanced(
        finding,
        projectPath,
        contextInference
      );'''

new_injection_call = '''      const injectionCheck = await this.checkInjectionContextEnhanced(
        finding,
        projectPath,
        contextInference,
        reachability
      );'''

content = content.replace(old_injection_call, new_injection_call)

# 5. Update checkInjectionContextEnhanced signature
old_injection_sig = '''  async checkInjectionContextEnhanced(finding, projectPath, contextInference) {'''
new_injection_sig = '''  async checkInjectionContextEnhanced(finding, projectPath, contextInference, reachability = null) {'''

content = content.replace(old_injection_sig, new_injection_sig)

with open('contextualFilter.js', 'w') as f:
    f.write(content)

print("✅ Step 1: Integrated reachability computation and passing")
