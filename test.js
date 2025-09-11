parseCode(code, language = 'javascript') {
  try {
    const ast = Parser.parse(code, {
      sourceType: 'unambiguous',  // Change to 'unambiguous'
      plugins: [
        'jsx',
        'typescript', 
        'decorators-legacy',
        'dynamicImport',
        'classProperties',
        'asyncGenerators',
        'objectRestSpread',  // Add this
        'optionalChaining',  // Add this
        'nullishCoalescingOperator'  // Add this
      ],
      errorRecovery: true,
      allowReturnOutsideFunction: true,  // Add this
      allowImportExportEverywhere: true  // Add this
    });
    return ast;
  } catch (error) {
    console.error('Parse error:', error.message);
    // Return a partial result instead of null
    this.addFinding({
      type: 'PARSE_ERROR',
      severity: 'info',
      line: 0,
      message: `Code parsing failed: ${error.message}`,
      code: code.substring(0, 100)
    });
    return null;
  }
}