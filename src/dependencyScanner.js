// At the top, add the import
const DependencyScanner = require('./dependencyScanner');

// Add this endpoint
app.post('/scan-dependencies', async (req, res) => {
  console.log('=== DEPENDENCY SCAN REQUEST ===');
  
  try {
    const { packageJson, packageLock } = req.body;
    
    if (!packageJson) {
      return res.status(400).json({
        status: 'error',
        message: 'package.json content required'
      });
    }
    
    const scanner = new DependencyScanner();
    const findings = await scanner.scan(packageJson, packageLock);
    
    const riskScore = calculateRiskScore(findings);
    
    res.json({
      status: 'success',
      findings: findings,
      stats: {
        total: findings.length,
        critical: findings.filter(f => f.severity === 'critical').length,
        high: findings.filter(f => f.severity === 'high').length,
        medium: findings.filter(f => f.severity === 'medium').length,
        low: findings.filter(f => f.severity === 'low').length
      },
      riskScore: riskScore,
      riskLevel: riskScore > 70 ? 'Critical' :
                 riskScore > 40 ? 'High' :
                 riskScore > 20 ? 'Medium' :
                 riskScore > 0 ? 'Low' : 'Minimal',
      timestamp: new Date().toISOString()
    });
    
  } catch (error) {
    console.error('Dependency scan error:', error);
    res.status(500).json({
      status: 'error',
      message: 'Dependency scan failed',
      error: error.message
    });
  }
});