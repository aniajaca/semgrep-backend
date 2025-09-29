// ==============================================================================
// src/contextInference/utils/canonicalizer.js
// ==============================================================================

/**
 * Canonicalize context keys to match calculator expectations
 */
function canonicalizeContext(context) {
  const canonical = {};
  
  // Define canonical mappings
  const mappings = {
    'internet-facing': 'internetFacing',
    'internet_facing': 'internetFacing',
    'internetfacing': 'internetFacing',
    'internetFacing': 'internetFacing',
    
    'handles-pi': 'handlesPI',
    'handles_pi': 'handlesPI',
    'handlesPersonalData': 'handlesPI',
    'handlespersonaldata': 'handlesPI',
    'handlesPI': 'handlesPI',
    
    'production': 'production',
    'prod': 'production',
    
    'no-auth': 'noAuth',
    'no_auth': 'noAuth',
    'noauth': 'noAuth',
    'noAuth': 'noAuth',
    'authorizationMissing': 'noAuth',
    
    'user-base-large': 'userBaseLarge',
    'user_base_large': 'userBaseLarge',
    'userBaseLarge': 'userBaseLarge',
    'largeUserBase': 'userBaseLarge',
    
    'regulated': 'regulated',
    'compliance': 'regulated',
    
    'kev-listed': 'kevListed',
    'kev_listed': 'kevListed',
    'kevListed': 'kevListed',
    
    'public-exploit': 'publicExploit',
    'public_exploit': 'publicExploit',
    'publicExploit': 'publicExploit',
    'exploitAvailable': 'publicExploit',
    
    'epss': 'epss',
    'epss-score': 'epss',
    'epss_score': 'epss',
    
    'legacy-code': 'legacyCode',
    'legacy_code': 'legacyCode',
    'legacyCode': 'legacyCode',
    'legacySystem': 'legacyCode',
    
    'public-api': 'publicAPI',
    'public_api': 'publicAPI',
    'publicAPI': 'publicAPI',
    
    'user-input': 'userInput',
    'user_input': 'userInput',
    'userInput': 'userInput'
  };
  
  // Apply mappings
  for (const [key, value] of Object.entries(context)) {
    const canonicalKey = mappings[key] || key;
    canonical[canonicalKey] = value;
  }
  
  return canonical;
}

module.exports = { canonicalizeContext };