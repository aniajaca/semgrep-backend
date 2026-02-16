/**
 * Constant Branch Detector - DISABLED
 * Causing too many false negatives
 */

class ConstantBranchDetector {
  constructor() {}

  detectConstantBranch(code, filepath = '') {
    // DISABLED: Was causing 258 false negatives
    return {
      hasPattern: false,
      constantValue: null,
      confidence: 0,
      details: []
    };
  }
}

module.exports = ConstantBranchDetector;
