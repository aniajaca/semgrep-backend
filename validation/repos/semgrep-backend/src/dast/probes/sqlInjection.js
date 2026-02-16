// src/dast/probes/sqlInjection.js
// SQL Injection probe with baseline/diff verification for reduced false positives

const axios = require('axios');
const payloads = require('../payloads/sqli-payloads.json');

// SQL error signatures for detection
const SQL_ERROR_SIGNATURES = [
  { pattern: /sql syntax/i, weight: 0.9, dbms: 'generic' },
  { pattern: /mysql_fetch/i, weight: 0.95, dbms: 'mysql' },
  { pattern: /mysqli::/i, weight: 0.95, dbms: 'mysql' },
  { pattern: /pg_query/i, weight: 0.95, dbms: 'postgresql' },
  { pattern: /sqlite3/i, weight: 0.95, dbms: 'sqlite' },
  { pattern: /ora-\d{5}/i, weight: 0.95, dbms: 'oracle' },
  { pattern: /sqlstate\[/i, weight: 0.9, dbms: 'generic' },
  { pattern: /syntax error/i, weight: 0.7, dbms: 'generic' },
  { pattern: /unterminated quoted string/i, weight: 0.85, dbms: 'generic' },
  { pattern: /unclosed quotation mark/i, weight: 0.85, dbms: 'mssql' },
  { pattern: /quoted string not properly terminated/i, weight: 0.85, dbms: 'oracle' },
  { pattern: /driver.*sql/i, weight: 0.75, dbms: 'generic' }
];

class SQLInjectionProbe {
  constructor() {
    this.timeout = 20000; // Default 20s timeout (configurable)
    this.maxPayloadsPerParam = 3; // Test top 3 payloads per parameter
    this.timingThreshold = 4000; // 4s for timing attack detection
    this.timingVerifications = 3; // Verify timing 3 times
  }

  /**
   * Test forms for SQL injection vulnerabilities
   * @param {Array} forms - Array of form objects from crawler
   * @param {Object} options - { timeout: number }
   * @returns {Promise<Array>} Array of DASTFinding objects
   */
  async test(forms, options = {}) {
    const timeout = options.timeout || this.timeout;
    const startTime = Date.now();
    const findings = [];

    console.log(`SQLi probe testing ${forms.length} forms...`);

    for (const form of forms) {
      // Check timeout budget
      if (Date.now() - startTime > timeout) {
        console.warn('⚠️  SQLi probe timeout, returning partial results');
        break;
      }

      // Test each input parameter
      for (const input of form.inputs) {
        // Skip non-injectable parameters
        if (this.shouldSkipParameter(input)) {
          continue;
        }

        try {
          // 1. Error-based detection
          const errorFinding = await this.testErrorBased(form, input);
          if (errorFinding) {
            findings.push(errorFinding);
            continue; // One finding per parameter sufficient
          }

          // 2. Timing-based detection (if time permits)
          const remainingTime = timeout - (Date.now() - startTime);
          if (remainingTime > 15000) { // Need 15s for timing tests
            const timingFinding = await this.testTimingBased(form, input);
            if (timingFinding) {
              findings.push(timingFinding);
            }
          }
        } catch (error) {
          console.error(`Error testing ${form.action}[${input.name}]:`, error.message);
          // Continue with other parameters
        }
      }
    }

    console.log(`✓ SQLi probe complete: ${findings.length} findings`);
    return findings;
  }

  /**
   * Check if parameter should be skipped
   */
  shouldSkipParameter(input) {
    const skipTypes = ['submit', 'button', 'image', 'reset'];
    if (skipTypes.includes(input.type)) {
      return true;
    }

    // Skip hidden inputs with static values (CSRF tokens, etc)
    if (input.type === 'hidden' && input.value && input.value.length > 20) {
      return true;
    }

    return false;
  }

  /**
   * Test for error-based SQL injection with baseline/diff verification
   */
  async testErrorBased(form, input) {
    console.log(`  Testing ${input.name} for error-based SQLi...`);

    // 1. BASELINE: Request with normal value
    const baseline = await this.makeRequest(form, {
      [input.name]: 'test123'
    });

    if (baseline.error) {
      console.log(`    Baseline failed: ${baseline.error}`);
      return null; // Can't establish baseline
    }

    // 2. TEST: Inject payloads and look for NEW SQL errors
    for (const payload of payloads.error_based.slice(0, this.maxPayloadsPerParam)) {
      const result = await this.makeRequest(form, {
        [input.name]: payload
      });

      if (result.error) continue; // Network error, skip

      // Compare: Did NEW SQL errors appear?
      const newErrors = this.detectNewErrors(baseline.body, result.body);

      if (newErrors.length > 0) {
        console.log(`    ✓ SQLi detected! Error: ${newErrors[0].signature}`);
        return {
          type: 'SQL_INJECTION',
          targetUrl: form.action,
          vulnerableParameter: input.name,
          testPayload: payload,
          detectionMethod: 'error_based',
          confidence: newErrors[0].confidence,
          evidence: this.truncateEvidence(newErrors[0].evidence),
          httpMethod: form.method,
          statusCode: result.status,
          dbms: newErrors[0].dbms,
          verified: true
        };
      }
    }

    return null; // No SQLi detected
  }

  /**
   * Test for timing-based SQL injection (blind SQLi)
   */
  async testTimingBased(form, input) {
    console.log(`  Testing ${input.name} for timing-based SQLi...`);

    // Measure baseline response time
    const baselineStart = Date.now();
    await this.makeRequest(form, { [input.name]: 'test123' });
    const baselineTime = Date.now() - baselineStart;

    // Test with timing payload
    const timingPayload = payloads.timing_based[0]; // SLEEP(5)
    const deltas = [];

    // Measure 3 times for consistency
    for (let i = 0; i < this.timingVerifications; i++) {
      const start = Date.now();
      await this.makeRequest(form, { [input.name]: timingPayload });
      const delta = Date.now() - start;
      deltas.push(delta);
    }

    // All 3 requests took >4s consistently?
    const minDelta = Math.min(...deltas);
    const avgDelta = deltas.reduce((a, b) => a + b, 0) / deltas.length;

    if (minDelta > this.timingThreshold && avgDelta > this.timingThreshold + 500) {
      console.log(`    ✓ Timing-based SQLi detected! Delays: ${deltas.join('ms, ')}ms`);
      return {
        type: 'SQL_INJECTION',
        targetUrl: form.action,
        vulnerableParameter: input.name,
        testPayload: timingPayload,
        detectionMethod: 'timing_based',
        confidence: 0.70, // Lower confidence (network could be slow)
        evidence: `Response times: ${deltas.join('ms, ')}ms (baseline: ${baselineTime}ms)`,
        httpMethod: form.method,
        responseTime: Math.round(avgDelta),
        verified: true
      };
    }

    return null; // No timing anomaly detected
  }

  /**
   * Make HTTP request to form endpoint
   */
  async makeRequest(form, data) {
    try {
      const config = {
        method: form.method.toLowerCase(),
        url: form.action,
        timeout: 8000, // 8s per request
        validateStatus: () => true, // Accept any status code
        maxRedirects: 0 // Don't follow redirects
      };

      // Add data as query params (GET) or body (POST)
      if (form.method.toUpperCase() === 'GET') {
        config.params = data;
      } else {
        config.data = new URLSearchParams(data).toString();
        config.headers = {
          'Content-Type': 'application/x-www-form-urlencoded'
        };
      }

      const response = await axios(config);

      return {
        status: response.status,
        body: typeof response.data === 'string' 
          ? response.data.substring(0, 50000) // Limit to 50KB
          : JSON.stringify(response.data).substring(0, 50000),
        headers: response.headers
      };
    } catch (error) {
      return {
        status: 0,
        body: '',
        error: error.message
      };
    }
  }

  /**
   * Detect NEW SQL errors that appear in payload response but not baseline
   */
  detectNewErrors(baselineBody, payloadBody) {
    const newErrors = [];

    for (const sig of SQL_ERROR_SIGNATURES) {
      const inBaseline = sig.pattern.test(baselineBody);
      const inPayload = sig.pattern.test(payloadBody);

      // NEW error appears in payload response
      if (!inBaseline && inPayload) {
        const match = payloadBody.match(sig.pattern);
        newErrors.push({
          signature: sig.pattern.source,
          confidence: sig.weight,
          dbms: sig.dbms,
          evidence: this.extractContext(payloadBody, match.index, 200)
        });
      }
    }

    // Return highest confidence match
    return newErrors.sort((a, b) => b.confidence - a.confidence);
  }

  /**
   * Extract context around error for evidence
   */
  extractContext(text, position, length) {
    const start = Math.max(0, position - length / 2);
    const end = Math.min(text.length, position + length / 2);
    let context = text.substring(start, end);

    // Add ellipsis if truncated
    if (start > 0) context = '...' + context;
    if (end < text.length) context = context + '...';

    return context;
  }

  /**
   * Truncate evidence to reasonable size
   */
  truncateEvidence(evidence) {
    if (evidence.length > 500) {
      return evidence.substring(0, 500) + '... [truncated]';
    }
    return evidence;
  }
}

module.exports = new SQLInjectionProbe();