// Enhanced SQLi probe with content-based detection
const axios = require('axios');
const payloads = require('../payloads/sqli-payloads.json');

const SQL_ERROR_SIGNATURES = [
  { pattern: /sql syntax/i, weight: 0.9, dbms: 'generic' },
  { pattern: /mysql_fetch/i, weight: 0.95, dbms: 'mysql' },
  { pattern: /mysqli::/i, weight: 0.95, dbms: 'mysql' },
  { pattern: /pg_query/i, weight: 0.95, dbms: 'postgresql' },
];

class SQLInjectionProbe {
  constructor() {
    this.timeout = 20000;
    this.maxPayloadsPerParam = 3;
  }

  async test(forms, options = {}) {
    const timeout = options.timeout || this.timeout;
    const startTime = Date.now();
    const findings = [];

    console.log(`SQLi probe testing ${forms.length} forms...`);

    for (const form of forms) {
      if (Date.now() - startTime > timeout) {
        console.warn('⚠️  SQLi probe timeout');
        break;
      }

      for (const input of form.inputs) {
        if (this.shouldSkipParameter(input)) continue;

        try {
          // Test for content-based SQLi (DVWA style)
          const contentFinding = await this.testContentBased(form, input);
          if (contentFinding) {
            findings.push(contentFinding);
            continue;
          }

          // Fallback to error-based
          const errorFinding = await this.testErrorBased(form, input);
          if (errorFinding) {
            findings.push(errorFinding);
          }
        } catch (error) {
          console.error(`Error testing ${form.action}[${input.name}]:`, error.message);
        }
      }
    }

    console.log(`✓ SQLi probe complete: ${findings.length} findings`);
    return findings;
  }

  async testContentBased(form, input) {
    console.log(`  Testing ${input.name} for content-based SQLi...`);

    // Baseline request
    const baseline = await this.makeRequest(form, { [input.name]: '1' });
    if (baseline.error) return null;

    // SQLi payload that returns multiple rows
    const payload = "1' OR '1'='1";
    const result = await this.makeRequest(form, { [input.name]: payload });
    if (result.error) return null;

    // Check if response is significantly longer (more data returned)
    const baselineLength = baseline.body.length;
    const resultLength = result.body.length;
    const lengthIncrease = (resultLength - baselineLength) / baselineLength;

    // If response is >50% longer, likely returning more rows
    if (lengthIncrease > 0.5) {
      console.log(`    ✓ Content-based SQLi detected! Response ${(lengthIncrease * 100).toFixed(0)}% longer`);
      return {
        type: 'SQL_INJECTION',
        targetUrl: form.action,
        vulnerableParameter: input.name,
        testPayload: payload,
        detectionMethod: 'content_based',
        confidence: 0.80,
        evidence: `Baseline response: ${baselineLength} bytes, SQLi response: ${resultLength} bytes (+${(lengthIncrease * 100).toFixed(0)}%)`,
        httpMethod: form.method,
        statusCode: result.status,
        verified: true
      };
    }

    return null;
  }

  async testErrorBased(form, input) {
    console.log(`  Testing ${input.name} for error-based SQLi...`);

    const baseline = await this.makeRequest(form, { [input.name]: 'test123' });
    if (baseline.error) return null;

    for (const payload of payloads.error_based.slice(0, this.maxPayloadsPerParam)) {
      const result = await this.makeRequest(form, { [input.name]: payload });
      if (result.error) continue;

      const newErrors = this.detectNewErrors(baseline.body, result.body);
      if (newErrors.length > 0) {
        console.log(`    ✓ Error-based SQLi detected!`);
        return {
          type: 'SQL_INJECTION',
          targetUrl: form.action,
          vulnerableParameter: input.name,
          testPayload: payload,
          detectionMethod: 'error_based',
          confidence: newErrors[0].confidence,
          evidence: newErrors[0].evidence,
          httpMethod: form.method,
          statusCode: result.status,
          dbms: newErrors[0].dbms,
          verified: true
        };
      }
    }

    return null;
  }

  async makeRequest(form, data) {
    try {
      const config = {
        method: form.method.toLowerCase(),
        url: form.action,
        timeout: 8000,
        validateStatus: () => true,
        maxRedirects: 0
      };

      if (form.method.toUpperCase() === 'GET') {
        config.params = data;
      } else {
        config.data = new URLSearchParams(data).toString();
        config.headers = { 'Content-Type': 'application/x-www-form-urlencoded' };
      }

      const response = await axios(config);
      return {
        status: response.status,
        body: typeof response.data === 'string' 
          ? response.data.substring(0, 50000)
          : JSON.stringify(response.data).substring(0, 50000)
      };
    } catch (error) {
      return { status: 0, body: '', error: error.message };
    }
  }

  detectNewErrors(baselineBody, payloadBody) {
    const newErrors = [];
    for (const sig of SQL_ERROR_SIGNATURES) {
      const inBaseline = sig.pattern.test(baselineBody);
      const inPayload = sig.pattern.test(payloadBody);
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
    return newErrors.sort((a, b) => b.confidence - a.confidence);
  }

  extractContext(text, position, length) {
    const start = Math.max(0, position - length / 2);
    const end = Math.min(text.length, position + length / 2);
    let context = text.substring(start, end);
    if (start > 0) context = '...' + context;
    if (end < text.length) context = context + '...';
    return context;
  }

  shouldSkipParameter(input) {
    const skipTypes = ['submit', 'button', 'image', 'reset'];
    return skipTypes.includes(input.type);
  }
}

module.exports = new SQLInjectionProbe();
