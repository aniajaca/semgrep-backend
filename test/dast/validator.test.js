// src/dast/index.js
// Main DAST orchestrator - coordinates crawler, probes, and normalization

const crawler = require('./crawler');
const validator = require('./validator');
const normalizer = require('./normalizer');
const sqlInjectionProbe = require('./probes/sqlInjection');

class DASTOrchestrator {
  constructor() {
    this.timeout = 90000; // 90s hard limit (system-wide budget)
    this.defaultProbes = ['sql_injection'];
  }

  /**
   * Execute DAST scan
   * @param {Object} options - Scan configuration
   * @returns {Promise<Object>} Scan results
   */
  async scan(options) {
    const {
      targetUrl,
      probeTypes = this.defaultProbes,
      crawlDepth = 2,
      maxPages = 10,
      timeout = this.timeout
    } = options;

    const startTime = Date.now();
    const scanId = this.generateScanId();

    console.log(`\n${'='.repeat(60)}`);
    console.log(`DAST Scan Started: ${scanId}`);
    console.log(`Target: ${targetUrl}`);
    console.log(`Probes: ${probeTypes.join(', ')}`);
    console.log(`${'='.repeat(60)}\n`);

    try {
      // 1. VALIDATE TARGET (0.1s)
      console.log('Step 1/5: Validating target...');
      validator.validateTarget(targetUrl);
      console.log('✓ Target validation passed\n');

      // 2. CRAWL (30s budget)
      console.log('Step 2/5: Crawling application...');
      const crawlTimeout = Math.min(30000, timeout * 0.33);
      const crawlStartTime = Date.now();
      
      const crawlResults = await crawler.crawl(targetUrl, {
        maxPages,
        maxDepth: crawlDepth,
        timeout: crawlTimeout
      });

      const crawlDuration = Date.now() - crawlStartTime;
      console.log(`✓ Crawl complete (${crawlDuration}ms)\n`);

      if (crawlResults.forms.length === 0) {
        console.log('⚠️  No forms found - nothing to test');
        return this.buildResponse(scanId, startTime, {
          status: 'success',
          findings: [],
          metadata: {
            ...crawlResults.metadata,
            formsFound: 0,
            message: 'No testable parameters found'
          }
        });
      }

      // 3. PROBE (40s budget)
      console.log('Step 3/5: Running vulnerability probes...');
      const probeTimeout = Math.min(40000, timeout - (Date.now() - startTime) - 20000);
      const dastFindings = await this.runProbes(crawlResults.forms, probeTypes, probeTimeout);
      console.log(`✓ Probes complete: ${dastFindings.length} findings\n`);

      // 4. NORMALIZE (5s budget)
      console.log('Step 4/5: Normalizing findings...');
      const normalizedFindings = normalizer.normalizeMany(dastFindings);
      console.log(`✓ Normalized ${normalizedFindings.length} findings\n`);

      // 5. CHECK TIMEOUT
      const elapsed = Date.now() - startTime;
      console.log('Step 5/5: Finalizing...');
      
      if (elapsed > timeout) {
        console.warn(`⚠️  Scan exceeded ${timeout}ms budget (${elapsed}ms)`);
        return this.buildResponse(scanId, startTime, {
          status: 'partial',
          timedOut: true,
          findings: normalizedFindings,
          metadata: {
            ...crawlResults.metadata,
            findingsCount: normalizedFindings.length,
            message: 'Scan exceeded time budget, returning partial results'
          }
        });
      }

      console.log(`✓ Scan complete (${elapsed}ms)\n`);
      console.log(`${'='.repeat(60)}`);
      console.log(`DAST Scan Complete: ${normalizedFindings.length} findings`);
      console.log(`${'='.repeat(60)}\n`);

      return this.buildResponse(scanId, startTime, {
        status: 'success',
        findings: normalizedFindings,
        metadata: {
          ...crawlResults.metadata,
          findingsCount: normalizedFindings.length
        }
      });

    } catch (error) {
      const elapsed = Date.now() - startTime;
      console.error(`\n❌ DAST Scan Failed: ${error.message}`);
      console.error(`${'='.repeat(60)}\n`);

      return this.buildResponse(scanId, startTime, {
        status: 'error',
        error: error.message,
        findings: [],
        metadata: {
          message: `Scan failed: ${error.message}`
        }
      });
    }
  }

  /**
   * Run vulnerability probes on discovered forms
   */
  async runProbes(forms, probeTypes, timeout) {
    const allFindings = [];
    const startTime = Date.now();
    const timePerProbe = Math.floor(timeout / probeTypes.length);

    for (const probeType of probeTypes) {
      const remainingTime = timeout - (Date.now() - startTime);
      if (remainingTime < 5000) {
        console.warn(`⚠️  Insufficient time for ${probeType} probe, skipping`);
        continue;
      }

      const probeTimeout = Math.min(timePerProbe, remainingTime);

      try {
        let findings = [];

        switch (probeType) {
          case 'sql_injection':
            findings = await sqlInjectionProbe.test(forms, { timeout: probeTimeout });
            break;
          
          // Future probes go here
          // case 'xss':
          //   findings = await xssProbe.test(forms, { timeout: probeTimeout });
          //   break;

          default:
            console.warn(`⚠️  Unknown probe type: ${probeType}`);
        }

        allFindings.push(...findings);

      } catch (error) {
        console.error(`Error running ${probeType} probe:`, error.message);
        // Continue with other probes
      }
    }

    return allFindings;
  }

  /**
   * Build standardized response object
   */
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

  /**
   * Generate unique scan ID
   */
  generateScanId() {
    return `dast-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Quick scan - single page, minimal probes (for testing)
   */
  async quickScan(targetUrl) {
    console.log(`\nQuick DAST scan: ${targetUrl}\n`);

    const scanId = this.generateScanId();
    const startTime = Date.now();

    try {
      validator.validateTarget(targetUrl);

      // Crawl single page only
      const crawlResults = await crawler.quickScan(targetUrl);

      if (crawlResults.forms.length === 0) {
        return this.buildResponse(scanId, startTime, {
          status: 'success',
          findings: [],
          metadata: { message: 'No forms found', mode: 'quick' }
        });
      }

      // Test only SQL injection (fast)
      const dastFindings = await sqlInjectionProbe.test(
        crawlResults.forms, 
        { timeout: 15000 }
      );

      const normalizedFindings = normalizer.normalizeMany(dastFindings);

      return this.buildResponse(scanId, startTime, {
        status: 'success',
        findings: normalizedFindings,
        metadata: {
          pagesVisited: 1,
          formsFound: crawlResults.forms.length,
          findingsCount: normalizedFindings.length,
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
}

module.exports = new DASTOrchestrator();