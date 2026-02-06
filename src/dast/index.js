const crawler = require('./crawler');
const validator = require('./validator');
const normalizer = require('./normalizer');
const sqlInjectionProbe = require('./probes/sqlInjection');

class DASTOrchestrator {
  constructor() {
    this.timeout = 90000;
    this.defaultProbes = ['sql_injection'];
  }

  async quickScan(targetUrl, options = {}) {
    console.log(`\nQuick DAST scan: ${targetUrl}\n`);
    const scanId = this.generateScanId();
    const startTime = Date.now();
    const cookies = options.cookies || {};

    try {
      validator.validateTarget(targetUrl);
      const crawlResults = await crawler.quickScan(targetUrl, { cookies });

      if (crawlResults.forms.length === 0) {
        return this.buildResponse(scanId, startTime, {
          status: 'success',
          findings: [],
          metadata: { message: 'No forms found', mode: 'quick' }
        });
      }

      // PASS COOKIES TO PROBE
      const dastFindings = await sqlInjectionProbe.test(crawlResults.forms, { 
        timeout: 15000,
        cookies: cookies 
      });
      
      const normalizedFindings = normalizer.normalizeMany(dastFindings);

      return this.buildResponse(scanId, startTime, {
        status: 'success',
        findings: normalizedFindings,
        metadata: {
          pagesVisited: 1,
          formsFound: crawlResults.forms.length,
          findingsCount: normalizedFindings.length,
          authenticated: crawlResults.metadata.authenticated,
          mode: 'quick'
        }
      });
    } catch (error) {
      return this.buildResponse(scanId, startTime, {
        status: 'error',
        error: error.message,
        findings: [],
        metadata: { mode: 'quick' }
      });
    }
  }

  buildResponse(scanId, startTime, data) {
    const duration = Date.now() - startTime;
    return {
      scanId,
      status: data.status,
      timedOut: data.timedOut || false,
      findings: data.findings || [],
      metadata: {
        scanId,
        durationMs: duration,
        timestamp: new Date().toISOString(),
        ...data.metadata
      },
      ...(data.error && { error: data.error })
    };
  }

  generateScanId() {
    return `dast-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }
}

module.exports = new DASTOrchestrator();
