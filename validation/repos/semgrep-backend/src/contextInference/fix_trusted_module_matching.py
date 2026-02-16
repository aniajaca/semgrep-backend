#!/usr/bin/env python3

with open('contextualFilter.js', 'r') as f:
    content = f.read()

# Fix the pattern matching to use path.basename()
old_code = '''  isTrustedInternalModule(filepath) {
    const lower = filepath.toLowerCase();
    
    // Exclude public-facing code (these ARE vulnerable if not validated)
    if (lower.includes('server.js') || 
        lower.includes('controller') || 
        lower.includes('handler') ||
        lower.includes('servlet') ||
        lower.includes('endpoint')) {
      return { isTrusted: false };
    }
    
    // Trusted internal utility patterns
    const trustedPatterns = [
      { pattern: 'manager.js', reason: 'Profile/resource manager - operates on validated IDs' },
      { pattern: 'collector.js', reason: 'Data collector - operates on validated paths' },
      { pattern: 'detector.js', reason: 'Pattern detector - internal analysis only' },
      { pattern: '/lib/inputvalidation', reason: 'Validation library itself' },
      { pattern: '/lib/normalize', reason: 'Normalization utilities' }
    ];
    
    for (const { pattern, reason } of trustedPatterns) {
      if (lower.includes(pattern)) {
        return {
          isTrusted: true,
          pattern: pattern,
          details: reason
        };
      }
    }
    
    return { isTrusted: false };
  }'''

new_code = '''  isTrustedInternalModule(filepath) {
    const lower = filepath.toLowerCase();
    const basename = path.basename(lower);
    
    // Exclude public-facing code (these ARE vulnerable if not validated)
    if (basename === 'server.js' || 
        lower.includes('controller') || 
        lower.includes('handler') ||
        lower.includes('servlet') ||
        lower.includes('endpoint')) {
      return { isTrusted: false };
    }
    
    // Trusted internal utility patterns - check BASENAME
    if (basename.includes('manager.js') ||
        basename.includes('collector.js') ||
        basename.includes('detector.js') ||
        lower.includes('/lib/inputvalidation') ||
        lower.includes('/lib/normalize')) {
      
      let reason = '';
      if (basename.includes('manager.js')) reason = 'Profile/resource manager - operates on validated IDs';
      else if (basename.includes('collector.js')) reason = 'Data collector - operates on validated paths';
      else if (basename.includes('detector.js')) reason = 'Pattern detector - internal analysis only';
      else if (lower.includes('/lib/inputvalidation')) reason = 'Validation library itself';
      else if (lower.includes('/lib/normalize')) reason = 'Normalization utilities';
      
      return {
        isTrusted: true,
        pattern: basename,
        details: reason
      };
    }
    
    return { isTrusted: false };
  }'''

content = content.replace(old_code, new_code)

with open('contextualFilter.js', 'w') as f:
    f.write(content)

print("✅ Fixed pattern matching to use basename!")
print("   Now matches: profileManager.js, repoContextCollector.js, etc.")
