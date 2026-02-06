const express = require('express');
const router = express.Router();
const dast = require('../dast');
const validator = require('../dast/validator');

/**
 * POST /v1/scan-dast
 * Execute DAST scan on target URL
 */
router.post('/scan-dast', async (req, res) => {
  try {
    const { targetUrl, cookies } = req.body;

    if (!targetUrl) {
      return res.status(400).json({
        error: 'Missing required parameter: targetUrl',
        status: 'error'
      });
    }

    try {
      validator.validateTarget(targetUrl);
    } catch (error) {
      return res.status(400).json({
        error: `Invalid target: ${error.message}`,
        status: 'error',
        hint: 'Tier-1 DAST only supports localhost targets'
      });
    }

    console.log(`DAST scan request: ${targetUrl}`);

    const result = await dast.quickScan(targetUrl, { cookies: cookies || {} });

    res.json({
      status: result.status,
      scanId: result.scanId,
      findings: result.findings,
      metadata: result.metadata,
      summary: {
        totalFindings: result.findings.length,
        criticalFindings: result.findings.filter(f => f.severity === 'CRITICAL').length,
        highFindings: result.findings.filter(f => f.severity === 'HIGH').length
      }
    });

  } catch (error) {
    console.error('DAST API Error:', error);
    res.status(500).json({
      error: 'Internal server error during DAST scan',
      message: error.message,
      status: 'error'
    });
  }
});

module.exports = router;
