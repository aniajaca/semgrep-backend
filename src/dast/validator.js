// src/dast/validator.js
// Enforces localhost-only targets for DAST Tier 1 (egress policy compliance)

class DASTValidator {
  constructor() {
    // Allowed target patterns (localhost and Docker networks only)
    this.allowedTargets = [
      'http://localhost',
      'http://127.0.0.1',
      'http://host.docker.internal',
      // Docker bridge networks (172.16.0.0 - 172.31.255.255)
      /^http:\/\/172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}/
    ];
  }

  /**
   * Validate that target URL is allowed per egress policy
   * @param {string} targetUrl - URL to validate
   * @returns {boolean} true if valid
   * @throws {Error} if target is not allowed
   */
  validateTarget(targetUrl) {
    if (!targetUrl) {
      throw new Error('Target URL is required');
    }

    let parsed;
    try {
      parsed = new URL(targetUrl);
    } catch (e) {
      throw new Error(`Invalid URL format: ${e.message}`);
    }

    // Check protocol (only http allowed in Tier 1)
    if (parsed.protocol !== 'http:') {
      throw new Error(
        'HTTPS not supported in Tier 1. Use http:// for local test applications. ' +
        'Tier 2 will support HTTPS with certificate validation.'
      );
    }

    // Check against allow-list
    const allowed = this.allowedTargets.some(pattern => {
      if (typeof pattern === 'string') {
        return parsed.href.startsWith(pattern);
      }
      // Regex pattern
      return pattern.test(parsed.href);
    });

    if (!allowed) {
      throw new Error(
        'DAST Tier 1 only scans localhost/Docker targets (privacy-by-design constraint). ' +
        'Allowed: localhost, 127.0.0.1, host.docker.internal, Docker bridge networks (172.16-31.x.x). ' +
        'For external target scanning, use Tier 2 (enterprise) with explicit customer allow-lists.'
      );
    }

    return true;
  }

  /**
   * Check if a URL is within allowed scope
   * @param {string} url - URL to check
   * @param {string} baseUrl - Base URL for scope checking
   * @returns {boolean}
   */
  isInScope(url, baseUrl) {
    try {
      const parsed = new URL(url);
      const base = new URL(baseUrl);
      
      // Must be same origin
      return parsed.origin === base.origin;
    } catch (e) {
      return false;
    }
  }

  /**
   * Sanitize URL for logging (remove sensitive query params)
   * @param {string} url
   * @returns {string}
   */
  sanitizeForLogging(url) {
    try {
      const parsed = new URL(url);
      // Remove query params that might contain sensitive data
      const sensitive = ['password', 'token', 'key', 'secret', 'api_key', 'auth'];
      sensitive.forEach(param => {
        if (parsed.searchParams.has(param)) {
          parsed.searchParams.set(param, '***REDACTED***');
        }
      });
      return parsed.href;
    } catch (e) {
      return url;
    }
  }
}

module.exports = new DASTValidator();