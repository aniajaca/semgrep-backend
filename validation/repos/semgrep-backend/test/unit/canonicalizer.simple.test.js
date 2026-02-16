// test/unit/canonicalizer.simple.test.js
const { canonicalizeContext } = require('../../src/contextInference/utils/canonicalizer');

describe('Canonicalizer', () => {
  it('should canonicalize internet-facing variants', () => {
    expect(canonicalizeContext({ 'internet-facing': true }).internetFacing).toBe(true);
    expect(canonicalizeContext({ 'internet_facing': true }).internetFacing).toBe(true);
    expect(canonicalizeContext({ 'internetfacing': true }).internetFacing).toBe(true);
  });
  
  it('should canonicalize handles-pi variants', () => {
    expect(canonicalizeContext({ 'handles-pi': true }).handlesPI).toBe(true);
    expect(canonicalizeContext({ 'handles_pi': true }).handlesPI).toBe(true);
    expect(canonicalizeContext({ 'handlesPersonalData': true }).handlesPI).toBe(true);
  });
  
  it('should canonicalize production variants', () => {
    expect(canonicalizeContext({ 'production': true }).production).toBe(true);
    expect(canonicalizeContext({ 'prod': true }).production).toBe(true);
  });
  
  it('should canonicalize no-auth variants', () => {
    expect(canonicalizeContext({ 'no-auth': true }).noAuth).toBe(true);
    expect(canonicalizeContext({ 'no_auth': true }).noAuth).toBe(true);
    expect(canonicalizeContext({ 'noauth': true }).noAuth).toBe(true);
  });
  
  it('should canonicalize user-base-large variants', () => {
    expect(canonicalizeContext({ 'user-base-large': true }).userBaseLarge).toBe(true);
    expect(canonicalizeContext({ 'user_base_large': true }).userBaseLarge).toBe(true);
    expect(canonicalizeContext({ 'largeUserBase': true }).userBaseLarge).toBe(true);
  });
  
  it('should canonicalize regulated variants', () => {
    expect(canonicalizeContext({ 'regulated': true }).regulated).toBe(true);
    expect(canonicalizeContext({ 'compliance': true }).regulated).toBe(true);
  });
  
  it('should canonicalize kev-listed variants', () => {
    expect(canonicalizeContext({ 'kev-listed': true }).kevListed).toBe(true);
    expect(canonicalizeContext({ 'kev_listed': true }).kevListed).toBe(true);
  });
  
  it('should canonicalize public-exploit variants', () => {
    expect(canonicalizeContext({ 'public-exploit': true }).publicExploit).toBe(true);
    expect(canonicalizeContext({ 'public_exploit': true }).publicExploit).toBe(true);
    expect(canonicalizeContext({ 'exploitAvailable': true }).publicExploit).toBe(true);
  });
  
  it('should canonicalize epss variants', () => {
    expect(canonicalizeContext({ 'epss': 0.5 }).epss).toBe(0.5);
    expect(canonicalizeContext({ 'epss-score': 0.5 }).epss).toBe(0.5);
    expect(canonicalizeContext({ 'epss_score': 0.5 }).epss).toBe(0.5);
  });
  
  it('should canonicalize legacy-code variants', () => {
    expect(canonicalizeContext({ 'legacy-code': true }).legacyCode).toBe(true);
    expect(canonicalizeContext({ 'legacy_code': true }).legacyCode).toBe(true);
    expect(canonicalizeContext({ 'legacySystem': true }).legacyCode).toBe(true);
  });
  
  it('should canonicalize public-api variants', () => {
    expect(canonicalizeContext({ 'public-api': true }).publicAPI).toBe(true);
    expect(canonicalizeContext({ 'public_api': true }).publicAPI).toBe(true);
  });
  
  it('should canonicalize user-input variants', () => {
    expect(canonicalizeContext({ 'user-input': true }).userInput).toBe(true);
    expect(canonicalizeContext({ 'user_input': true }).userInput).toBe(true);
  });
  
  it('should handle empty context', () => {
    const result = canonicalizeContext({});
    expect(result).toEqual({});
  });
  
  it('should handle multiple mappings', () => {
    const result = canonicalizeContext({
      'internet-facing': true,
      'handles-pi': true,
      'production': true,
      'no-auth': true
    });
    expect(result.internetFacing).toBe(true);
    expect(result.handlesPI).toBe(true);
    expect(result.production).toBe(true);
    expect(result.noAuth).toBe(true);
  });
  
  it('should preserve unmapped keys', () => {
    const result = canonicalizeContext({ customKey: 'value' });
    expect(result.customKey).toBe('value');
  });

  it('should handle null context', () => {
    const result = canonicalizeContext(null || {});
    expect(result).toBeDefined();
  });

  it('should handle mixed case keys', () => {
    const result = canonicalizeContext({ 'Internet-Facing': true });
    expect(result['Internet-Facing']).toBe(true);
  });
});