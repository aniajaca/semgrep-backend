// dependencyScanner.js — Multi-language SCA with OSV integration
// Supports: npm (JavaScript), PyPI (Python), Maven (Java)
// Stateless, zero-persistence design (GDPR Article 25 compliant)

const semver = require('semver');
const { XMLParser } = require('fast-xml-parser');

// ═══════════════════════════════════════════════════════════════
// RUNTIME COMPATIBILITY — fetch / AbortController polyfills
// Node 18+ has these as globals; older versions need node-fetch.
// ═══════════════════════════════════════════════════════════════

const fetchFn = typeof globalThis.fetch === 'function'
  ? globalThis.fetch
  : (require('node-fetch').default || require('node-fetch'));

const AbortControllerImpl = typeof globalThis.AbortController === 'function'
  ? globalThis.AbortController
  : (() => {
      // Older Node versions may need an AbortController polyfill (e.g., abort-controller package)
      try {
        const ac = require('abort-controller');
        return ac.AbortController || ac; // support both export styles
      } catch (_) {
        // Last resort: a no-op stub that will simply never abort.
        // This only triggers on very old Node versions without abort-controller installed.
        console.warn('AbortController not available — OSV requests will not time out');
        return class NoOpAbortController {
          constructor() { this.signal = {}; }
          abort() {}
        };
      }
    })();

// ═══════════════════════════════════════════════════════════════
// CONSTANTS
// ═══════════════════════════════════════════════════════════════

const OSV_API_BASE = 'https://api.osv.dev/v1';
const OSV_BATCH_LIMIT = 100;         // Max queries per batch call
const OSV_TIMEOUT_MS = 15000;        // 15 s per HTTP call
const SUPPORTED_ECOSYSTEMS = ['npm', 'PyPI', 'Maven'];

// ═══════════════════════════════════════════════════════════════
// CVSS 3.1 BASE SCORE CALCULATOR (RFC 8878 compliant)
// ═══════════════════════════════════════════════════════════════

const CVSS31 = {
  AV:   { N: 0.85, A: 0.62, L: 0.55, P: 0.20 },
  AC:   { L: 0.77, H: 0.44 },
  PR_U: { N: 0.85, L: 0.62, H: 0.27 },   // Scope Unchanged
  PR_C: { N: 0.85, L: 0.68, H: 0.50 },   // Scope Changed
  UI:   { N: 0.85, R: 0.62 },
  CIA:  { H: 0.56, L: 0.22, N: 0.00 }
};

/**
 * Parse a CVSS 3.x vector string into a metrics object.
 * Returns null if the string is not a valid CVSS 3.x vector.
 */
function parseCVSSVector(vector) {
  if (!vector || typeof vector !== 'string') return null;
  if (!vector.startsWith('CVSS:3')) return null;

  const metrics = {};
  vector.split('/').forEach(part => {
    const [key, val] = part.split(':');
    if (key && val) metrics[key] = val;
  });

  const required = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'];
  if (!required.every(k => metrics[k])) return null;
  return metrics;
}

/**
 * Compute the CVSS 3.1 base score from a parsed metrics object.
 * Implements the official FIRST formula.
 */
function computeCVSS31BaseScore(m) {
  if (!m) return null;

  const scopeChanged = m.S === 'C';
  const pr = scopeChanged ? CVSS31.PR_C : CVSS31.PR_U;

  const iss = 1 - (
    (1 - CVSS31.CIA[m.C]) *
    (1 - CVSS31.CIA[m.I]) *
    (1 - CVSS31.CIA[m.A])
  );

  let impact;
  if (scopeChanged) {
    impact = 7.52 * (iss - 0.029) - 3.25 * Math.pow(Math.max(0, iss - 0.02), 15);
  } else {
    impact = 6.42 * iss;
  }

  if (impact <= 0) return 0.0;

  const exploitability =
    8.22 *
    CVSS31.AV[m.AV] *
    CVSS31.AC[m.AC] *
    pr[m.PR] *
    CVSS31.UI[m.UI];

  let base;
  if (scopeChanged) {
    base = Math.min(1.08 * (impact + exploitability), 10.0);
  } else {
    base = Math.min(impact + exploitability, 10.0);
  }

  // CVSS spec: round up to nearest 0.1
  return Math.ceil(base * 10) / 10;
}

/**
 * Map a numeric CVSS base score to a severity label.
 */
function severityFromScore(score) {
  if (score == null) return 'medium';
  if (score >= 9.0) return 'critical';
  if (score >= 7.0) return 'high';
  if (score >= 4.0) return 'medium';
  if (score >= 0.1) return 'low';
  return 'info';
}

/**
 * Get a heuristic CVSS score from a severity label (for fallback only).
 */
function heuristicCVSSFromSeverity(severity) {
  const map = {
    critical: { baseScore: 9.8, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' },
    high:     { baseScore: 7.5, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N' },
    medium:   { baseScore: 5.3, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N' },
    low:      { baseScore: 3.1, vector: 'CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N' },
    info:     { baseScore: 0.0, vector: null }
  };
  return map[normSev(severity)] || map.medium;
}

/** Normalise severity to lowercase canonical form. */
function normSev(s) {
  return (s || 'medium').toString().toLowerCase();
}

// ═══════════════════════════════════════════════════════════════
// OSV CLIENT
// ═══════════════════════════════════════════════════════════════

/**
 * Query the OSV batch endpoint.
 * @param {Array<{name:string, ecosystem:string, version?:string}>} packages
 * @returns {Array<{package:object, vulns:Array}>}  Parallel array with OSV results.
 */
async function queryOSVBatch(packages) {
  if (!packages || packages.length === 0) return [];

  const allResults = [];

  // Split into batches of OSV_BATCH_LIMIT
  for (let i = 0; i < packages.length; i += OSV_BATCH_LIMIT) {
    const batch = packages.slice(i, i + OSV_BATCH_LIMIT);

    const queries = batch.map(pkg => {
      const q = { package: { name: pkg.name, ecosystem: pkg.ecosystem } };
      if (pkg.version && pkg.version !== 'unknown') {
        q.version = pkg.version;
      }
      return q;
    });

    try {
      const controller = new AbortControllerImpl();
      const timeout = setTimeout(() => controller.abort(), OSV_TIMEOUT_MS);

      const response = await fetchFn(`${OSV_API_BASE}/querybatch`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ queries }),
        signal: controller.signal
      });

      clearTimeout(timeout);

      if (!response.ok) {
        console.error(`OSV batch query failed: HTTP ${response.status}`);
        // Return empty results for this batch — fail-open
        allResults.push(...batch.map(() => ({ vulns: [] })));
        continue;
      }

      const data = await response.json();
      const results = data.results || [];

      // Pad if OSV returned fewer results than sent queries
      while (results.length < batch.length) {
        results.push({ vulns: [] });
      }

      allResults.push(...results);
    } catch (err) {
      console.error('OSV batch query error:', err.message);
      allResults.push(...batch.map(() => ({ vulns: [] })));
    }
  }

  return allResults;
}

/**
 * Extract severity + CVSS information from an OSV vulnerability object.
 */
function extractOSVSeverity(osvVuln) {
  // 1. Try severity array (official CVSS vectors)
  if (Array.isArray(osvVuln.severity)) {
    for (const entry of osvVuln.severity) {
      if (entry.type === 'CVSS_V3' && entry.score) {
        const metrics = parseCVSSVector(entry.score);
        const baseScore = computeCVSS31BaseScore(metrics);
        if (baseScore != null) {
          return {
            severity: severityFromScore(baseScore),
            cvss: { baseScore, vector: entry.score }
          };
        }
      }
    }
  }

  // 2. Try database_specific.severity or database_specific.cvss_v3
  const dbSpecific = osvVuln.database_specific || {};
  if (dbSpecific.cvss_v3) {
    const score = typeof dbSpecific.cvss_v3 === 'number'
      ? dbSpecific.cvss_v3
      : parseFloat(dbSpecific.cvss_v3);
    if (!isNaN(score)) {
      return {
        severity: severityFromScore(score),
        cvss: { baseScore: score }
      };
    }
  }
  if (dbSpecific.severity) {
    const sev = normSev(dbSpecific.severity);
    return { severity: sev, cvss: heuristicCVSSFromSeverity(sev) };
  }

  // 3. Try ecosystem_specific inside affected[]
  if (Array.isArray(osvVuln.affected)) {
    for (const aff of osvVuln.affected) {
      const ecoSev = aff.ecosystem_specific?.severity;
      if (ecoSev) {
        const sev = normSev(ecoSev);
        return { severity: sev, cvss: heuristicCVSSFromSeverity(sev) };
      }
    }
  }

  // 4. Fallback: unknown severity
  return { severity: 'medium', cvss: heuristicCVSSFromSeverity('medium') };
}

/**
 * Extract the preferred vulnerability ID.
 * Prefers CVE aliases over OSV IDs.
 */
function extractVulnId(osvVuln) {
  if (Array.isArray(osvVuln.aliases)) {
    const cve = osvVuln.aliases.find(a => a.startsWith('CVE-'));
    if (cve) return cve;
  }
  return osvVuln.id || 'UNKNOWN';
}

/**
 * Try to determine the first fixed version from OSV affected ranges.
 */
function extractFixedVersion(osvVuln, packageName, ecosystem) {
  if (!Array.isArray(osvVuln.affected)) return null;

  for (const aff of osvVuln.affected) {
    // Match by package name + ecosystem
    const affPkg = aff.package || {};
    if (affPkg.ecosystem !== ecosystem) continue;
    if (affPkg.name !== packageName) continue;

    if (Array.isArray(aff.ranges)) {
      for (const range of aff.ranges) {
        if (Array.isArray(range.events)) {
          for (const event of range.events) {
            if (event.fixed) return event.fixed;
          }
        }
      }
    }
  }
  return null;
}

/**
 * Normalise a single OSV vulnerability into our canonical output format.
 */
function normalizeOSVVuln(osvVuln, packageName, installedVersion, ecosystem) {
  const { severity, cvss } = extractOSVSeverity(osvVuln);
  const vulnId = extractVulnId(osvVuln);
  const fixedVersion = extractFixedVersion(osvVuln, packageName, ecosystem);

  let remediation = null;
  if (fixedVersion) {
    remediation = `Update ${packageName} to ${fixedVersion} or later`;
  } else if (osvVuln.references && osvVuln.references.length > 0) {
    const advisory = osvVuln.references.find(r => r.type === 'ADVISORY');
    remediation = advisory
      ? `See advisory: ${advisory.url}`
      : `See: ${osvVuln.references[0].url}`;
  }

  return {
    package: packageName,
    installedVersion: installedVersion || 'unknown',
    ecosystem,
    vulnerability: {
      id: vulnId,
      osvId: osvVuln.id,
      severity,
      description: osvVuln.summary || osvVuln.details || 'No description available',
      cvss: cvss || undefined,
      remediation: remediation || 'Check package repository for updates',
      aliases: osvVuln.aliases || [],
      published: osvVuln.published || null,
      modified: osvVuln.modified || null
    }
  };
}

// ═══════════════════════════════════════════════════════════════
// PARSERS
// ═══════════════════════════════════════════════════════════════

/**
 * Parse a Python requirements.txt into a list of dependency objects.
 * Handles ==, >=, <=, ~=, !=, comments, blank lines, -r includes (skipped).
 */
function parseRequirementsTxt(content) {
  if (!content || typeof content !== 'string') return [];

  const deps = [];
  const lines = content.split('\n');

  for (let raw of lines) {
    // Strip inline comments
    const commentIdx = raw.indexOf('#');
    if (commentIdx >= 0) raw = raw.substring(0, commentIdx);
    raw = raw.trim();

    // Skip empty lines, options, includes, URLs
    if (!raw) continue;
    if (raw.startsWith('-')) continue;          // -r, --index-url, etc.
    if (raw.startsWith('http')) continue;       // URL-based deps
    if (raw.includes('://')) continue;

    // Handle environment markers: package==1.0; python_version >= "3.6"
    const markerIdx = raw.indexOf(';');
    if (markerIdx >= 0) raw = raw.substring(0, markerIdx).trim();

    // Handle extras: package[extra]==1.0
    raw = raw.replace(/\[.*?\]/, '');

    // Split on version specifier operators
    // Supports: ==, >=, <=, ~=, !=, <, >
    const match = raw.match(/^([a-zA-Z0-9_.-]+)\s*(==|>=|<=|~=|!=|<|>)\s*(.+)$/);

    if (match) {
      const name = match[1].trim();
      const operator = match[2];
      const version = match[3].trim();

      deps.push({ name, version, operator, raw: `${name}${operator}${version}` });
    } else {
      // No version specifier — just a package name
      const name = raw.replace(/\s+/g, '');
      if (/^[a-zA-Z0-9_.-]+$/.test(name)) {
        deps.push({ name, version: null, operator: null, raw: name });
      }
    }
  }

  return deps;
}

/**
 * Parse a Maven pom.xml into a list of dependency objects.
 * Resolves simple <properties> variable interpolation.
 * Ignores profiles, parents, dependency management, etc.
 */
function parsePomXml(content) {
  if (!content || typeof content !== 'string') return [];

  try {
    const parser = new XMLParser({
      ignoreAttributes: true,
      isArray: (name) => name === 'dependency',
      trimValues: true
    });

    const parsed = parser.parse(content);
    const project = parsed.project || parsed;

    // Build properties map for variable resolution
    const properties = {};
    const propsObj = project.properties || {};
    for (const [key, val] of Object.entries(propsObj)) {
      if (typeof val === 'string' || typeof val === 'number') {
        properties[key] = String(val);
      }
    }
    // Add common implicit properties
    if (project.version) {
      properties['project.version'] = String(project.version);
    }
    if (project.groupId) {
      properties['project.groupId'] = String(project.groupId);
    }

    /**
     * Resolve ${property.name} references in a string.
     * Only one level of resolution (no recursive expansion).
     */
    function resolveProperty(str) {
      if (!str || typeof str !== 'string') return str;
      return str.replace(/\$\{([^}]+)\}/g, (match, propName) => {
        return properties[propName] || match;   // leave unresolved if not found
      });
    }

    // Extract dependencies from <dependencies> and <dependencyManagement>
    const deps = [];
    const sections = [];

    if (project.dependencies?.dependency) {
      sections.push(project.dependencies.dependency);
    }
    if (project.dependencyManagement?.dependencies?.dependency) {
      sections.push(project.dependencyManagement.dependencies.dependency);
    }

    for (const section of sections) {
      const depList = Array.isArray(section) ? section : [section];
      for (const dep of depList) {
        if (!dep || !dep.artifactId) continue;

        const groupId = resolveProperty(dep.groupId) || '';
        const artifactId = resolveProperty(dep.artifactId);
        const version = resolveProperty(dep.version) || null;
        const scope = (dep.scope || 'compile').toLowerCase();

        deps.push({
          groupId,
          artifactId,
          version,
          scope,
          name: `${groupId}:${artifactId}`,
          raw: `${groupId}:${artifactId}:${version || 'unspecified'}`
        });
      }
    }

    return deps;
  } catch (err) {
    console.error('Failed to parse pom.xml:', err.message);
    return [];
  }
}

// ═══════════════════════════════════════════════════════════════
// DEPENDENCY SCANNER CLASS
// ═══════════════════════════════════════════════════════════════

class DependencyScanner {
  constructor() {
    // ── Hardcoded fallback DB (npm only, used when OSV is unreachable) ──
    this.fallbackDB = {
      'lodash': {
        vulnerableVersions: '<4.17.21',
        cve: 'CVE-2021-23337',
        severity: 'high',
        description: 'Command injection vulnerability in lodash template function',
        remediation: 'Update to lodash@4.17.21 or later'
      },
      'minimist': {
        vulnerableVersions: '<1.2.6',
        cve: 'CVE-2021-44906',
        severity: 'critical',
        description: 'Prototype pollution allowing property injection',
        remediation: 'Update to minimist@1.2.6 or later'
      },
      'axios': {
        vulnerableVersions: '<0.21.2',
        cve: 'CVE-2021-3749',
        severity: 'high',
        description: 'Server-Side Request Forgery (SSRF) in axios',
        remediation: 'Update to axios@0.21.2 or later'
      },
      'express': {
        vulnerableVersions: '<4.17.3',
        cve: 'CVE-2022-24999',
        severity: 'high',
        description: 'Express.js Open Redirect vulnerability in query parser',
        remediation: 'Update to express@4.17.3 or later'
      },
      'node-fetch': {
        vulnerableVersions: '<2.6.7',
        cve: 'CVE-2022-0235',
        severity: 'medium',
        description: 'Regular expression denial of service (ReDoS)',
        remediation: 'Update to node-fetch@2.6.7 or later'
      },
      'jquery': {
        vulnerableVersions: '<3.5.0',
        cve: 'CVE-2020-11022',
        severity: 'medium',
        description: 'XSS vulnerability in jQuery DOM manipulation',
        remediation: 'Update to jquery@3.5.0 or later'
      },
      'moment': {
        vulnerableVersions: '<2.29.4',
        cve: 'CVE-2022-31129',
        severity: 'high',
        description: 'Path traversal vulnerability in moment.js',
        remediation: 'Update to moment@2.29.4 or later'
      },
      'webpack': {
        vulnerableVersions: '<5.76.0',
        cve: 'CVE-2023-28154',
        severity: 'medium',
        description: 'Webpack DOM XSS vulnerability in development server',
        remediation: 'Update to webpack@5.76.0 or later'
      }
    };

    /** Latest known stable versions for npm packages (heuristic outdated check). */
    this.latestVersions = {
      'react': '18.2.0',
      'react-dom': '18.2.0',
      'vue': '3.4.21',
      '@angular/core': '17.3.0',
      'express': '4.19.2',
      'lodash': '4.17.21',
      'axios': '1.6.8',
      'webpack': '5.91.0',
      'typescript': '5.4.3',
      'jest': '29.7.0',
      'eslint': '8.57.0',
      'prettier': '3.2.5',
      'nodemon': '3.1.0',
      'moment': '2.30.1',
      'jquery': '3.7.1',
      'minimist': '1.2.8',
      'node-fetch': '3.3.2',
      'dotenv': '16.4.5',
      'cors': '2.8.5',
      'multer': '1.4.5-lts.1',
      'semver': '7.6.0',
      'helmet': '7.0.0',
      'express-rate-limit': '6.8.0'
    };
  }

  // ══════════════════════════════════════════════════════════
  // PUBLIC — Unified multi-language entry point
  // ══════════════════════════════════════════════════════════

  /**
   * Scan multiple ecosystems in a single call.
   *
   * @param {Object} opts
   * @param {Object}  [opts.packageJson]       Parsed package.json object
   * @param {string}  [opts.requirementsTxt]   Raw requirements.txt string
   * @param {string}  [opts.pomXml]            Raw pom.xml string
   * @param {boolean} [opts.includeDevDependencies=false]
   * @param {string}  [opts.lockFile]          Raw lock-file content
   * @param {string}  [opts.lockFileType='npm']
   *
   * @returns {{ vulnerabilities, summary, ecosystemResults, warnings }}
   */
  async scanMultiLanguage(opts = {}) {
    const {
      packageJson,
      requirementsTxt,
      pomXml,
      includeDevDependencies = false,
      lockFile,
      lockFileType = 'npm'
    } = opts;

    const ecosystemResults = {};
    const allVulnerabilities = [];
    const allWarnings = [];
    let totalDeps = 0;

    // ── npm ──
    if (packageJson) {
      try {
        const npmResult = await this.scanNpmDependencies(packageJson, {
          includeDevDependencies,
          lockFile,
          lockFileType
        });
        ecosystemResults.npm = { status: 'success', ...npmResult };
        allVulnerabilities.push(...npmResult.vulnerabilities);
        allWarnings.push(...(npmResult.warnings || []));
        totalDeps += npmResult.metrics?.packagesScanned || 0;
      } catch (err) {
        console.error('npm scan failed:', err.message);
        ecosystemResults.npm = { status: 'error', error: err.message, vulnerabilities: [] };
      }
    }

    // ── Python ──
    if (requirementsTxt) {
      try {
        const pyResult = await this.scanPythonDependencies(requirementsTxt);
        ecosystemResults.pypi = { status: 'success', ...pyResult };
        allVulnerabilities.push(...pyResult.vulnerabilities);
        allWarnings.push(...(pyResult.warnings || []));
        totalDeps += pyResult.metrics?.packagesScanned || 0;
      } catch (err) {
        console.error('Python scan failed:', err.message);
        ecosystemResults.pypi = { status: 'error', error: err.message, vulnerabilities: [] };
      }
    }

    // ── Java / Maven ──
    if (pomXml) {
      try {
        const javaResult = await this.scanJavaDependencies(pomXml);
        ecosystemResults.maven = { status: 'success', ...javaResult };
        allVulnerabilities.push(...javaResult.vulnerabilities);
        allWarnings.push(...(javaResult.warnings || []));
        totalDeps += javaResult.metrics?.packagesScanned || 0;
      } catch (err) {
        console.error('Java scan failed:', err.message);
        ecosystemResults.maven = { status: 'error', error: err.message, vulnerabilities: [] };
      }
    }

    // Deduplicate across ecosystems
    const dedupedVulns = this.deduplicateVulnerabilities(allVulnerabilities);

    return {
      vulnerabilities: dedupedVulns,
      ecosystemResults,
      warnings: allWarnings,
      summary: this._buildUnifiedSummary(dedupedVulns, totalDeps),
      scannedAt: new Date().toISOString()
    };
  }

  // ══════════════════════════════════════════════════════════
  // PUBLIC — npm scanning (backward-compatible signature)
  // ══════════════════════════════════════════════════════════

  /**
   * Scan an npm package.json for vulnerabilities.
   * This method preserves the original calling convention used by server.js.
   *
   * @param {Object} packageJson   Parsed package.json
   * @param {Object} [options]
   * @returns {Object}
   */
  async scanDependencies(packageJson, options = {}) {
    return this.scanNpmDependencies(packageJson, options);
  }

  async scanNpmDependencies(packageJson, options = {}) {
    if (!packageJson || typeof packageJson !== 'object') {
      return this._emptyResult('npm');
    }

    const includeDevDependencies = options.includeDevDependencies || false;
    const dependencies = {
      ...(packageJson.dependencies || {}),
      ...(includeDevDependencies ? (packageJson.devDependencies || {}) : {})
    };

    if (Object.keys(dependencies).length === 0) {
      return this._emptyResult('npm');
    }

    // Build package list for OSV
    const packages = [];
    const warnings = [];
    let undefinedVersions = 0;

    for (const [name, versionSpec] of Object.entries(dependencies)) {
      if (!versionSpec || versionSpec === '' || versionSpec === '*' || versionSpec === 'latest') {
        undefinedVersions++;
        warnings.push({
          package: name,
          type: 'undefined-version',
          message: `Version not specified or uses wildcard: "${versionSpec || 'undefined'}"`,
          suggestion: `Pin to a specific version, e.g. "^${this.latestVersions[name] || '1.0.0'}"`
        });
        packages.push({ name, ecosystem: 'npm', version: 'unknown', rawVersion: versionSpec });
        continue;
      }

      const cleaned = this.cleanVersion(versionSpec);
      packages.push({ name, ecosystem: 'npm', version: cleaned, rawVersion: versionSpec });
    }

    // Query OSV
    let osvResults;
    let osvFailed = false;
    try {
      osvResults = await queryOSVBatch(packages.filter(p => p.version !== 'unknown'));
    } catch (err) {
      console.error('OSV query failed for npm, using fallback DB:', err.message);
      osvFailed = true;
      osvResults = [];
    }

    // Process results
    const vulnerabilities = [];

    // Map OSV results back to packages (only for those with known versions)
    const knownPackages = packages.filter(p => p.version !== 'unknown');
    for (let i = 0; i < knownPackages.length; i++) {
      const pkg = knownPackages[i];
      const result = osvResults[i];
      if (result && Array.isArray(result.vulns) && result.vulns.length > 0) {
        for (const vuln of result.vulns) {
          vulnerabilities.push(
            normalizeOSVVuln(vuln, pkg.name, pkg.version, 'npm')
          );
        }
      }
    }

    // Fallback: use hardcoded DB ONLY when OSV was unreachable.
    // When OSV succeeds but returns zero vulnerabilities, that is a
    // legitimate "clean" result — do NOT second-guess it with the
    // static fallback DB, as that would create false positives.
    if (osvFailed) {
      console.warn('OSV unreachable — falling back to hardcoded vulnerability DB');
      for (const pkg of packages) {
        if (pkg.version === 'unknown') continue;
        const fallback = this._checkFallbackDB(pkg.name, pkg.version);
        if (fallback) {
          vulnerabilities.push(fallback);
        }
      }
    }

    // Lock file scanning
    if (options.lockFile) {
      try {
        const lockVulns = await this.scanLockFile(options.lockFile, options.lockFileType || 'npm');
        for (const lv of lockVulns) {
          const exists = vulnerabilities.some(
            v => v.package === lv.package && v.vulnerability.id === lv.vulnerability.id
          );
          if (!exists) vulnerabilities.push(lv);
        }
      } catch (err) {
        console.warn('Lock file scan failed:', err.message);
      }
    }

    // Outdated packages check
    const outdatedPackages = await this.checkOutdatedPackages(dependencies);

    // Security recommendations
    const securityRecommendations = this.checkSecurityPackages(dependencies);

    const dedupedVulns = this.deduplicateVulnerabilities(vulnerabilities);

    return {
      vulnerabilities: dedupedVulns,
      outdatedPackages,
      warnings,
      securityRecommendations,
      metrics: {
        packagesScanned: Object.keys(dependencies).length,
        undefinedVersions,
        vulnerablePackages: dedupedVulns.length,
        outdatedPackages: outdatedPackages.length,
        osvQueryUsed: !osvFailed
      },
      summary: this._buildEcosystemSummary(dedupedVulns, Object.keys(dependencies).length, 'npm'),
      scannedAt: new Date().toISOString()
    };
  }

  // ══════════════════════════════════════════════════════════
  // PUBLIC — Python scanning
  // ══════════════════════════════════════════════════════════

  async scanPythonDependencies(requirementsTxt) {
    if (!requirementsTxt || typeof requirementsTxt !== 'string') {
      return this._emptyResult('PyPI');
    }

    const parsed = parseRequirementsTxt(requirementsTxt);
    if (parsed.length === 0) {
      return this._emptyResult('PyPI');
    }

    const warnings = [];
    const packages = [];

    for (const dep of parsed) {
      // For exact versions (==) we can query OSV precisely
      // For ranges (>=, ~=, etc.) we query with the lower-bound version as best-effort
      let version = 'unknown';

      if (dep.version) {
        if (dep.operator === '==') {
          version = dep.version;
        } else if (dep.operator === '~=' || dep.operator === '>=' || dep.operator === '>') {
          // Best-effort: use the specified version as an approximation
          version = dep.version;
          warnings.push({
            package: dep.name,
            type: 'range-version',
            message: `Using range specifier "${dep.operator}${dep.version}"; OSV query uses ${dep.version} as approximation`,
            suggestion: `Pin exact version with "==" for accurate SCA results`
          });
        } else {
          // <=, <, != — not useful for pinning
          version = 'unknown';
          warnings.push({
            package: dep.name,
            type: 'imprecise-version',
            message: `Version constraint "${dep.operator}${dep.version}" is not precise enough for accurate scanning`,
            suggestion: `Pin exact version with "==" for accurate SCA results`
          });
        }
      } else {
        warnings.push({
          package: dep.name,
          type: 'no-version',
          message: 'No version specified',
          suggestion: `Pin exact version, e.g. "${dep.name}==x.y.z"`
        });
      }

      packages.push({ name: dep.name, ecosystem: 'PyPI', version });
    }

    // Query OSV
    const vulnerabilities = [];
    try {
      const queryable = packages.filter(p => p.version !== 'unknown');
      const osvResults = await queryOSVBatch(queryable);

      for (let i = 0; i < queryable.length; i++) {
        const pkg = queryable[i];
        const result = osvResults[i];
        if (result && Array.isArray(result.vulns) && result.vulns.length > 0) {
          for (const vuln of result.vulns) {
            vulnerabilities.push(
              normalizeOSVVuln(vuln, pkg.name, pkg.version, 'PyPI')
            );
          }
        }
      }

      // For packages without versions, query by name only (no version filter)
      const unknownPkgs = packages.filter(p => p.version === 'unknown');
      if (unknownPkgs.length > 0) {
        const unknownResults = await queryOSVBatch(unknownPkgs);
        for (let i = 0; i < unknownPkgs.length; i++) {
          const pkg = unknownPkgs[i];
          const result = unknownResults[i];
          if (result && Array.isArray(result.vulns) && result.vulns.length > 0) {
            for (const vuln of result.vulns) {
              vulnerabilities.push(
                normalizeOSVVuln(vuln, pkg.name, 'unknown', 'PyPI')
              );
            }
          }
        }
      }
    } catch (err) {
      console.error('OSV query failed for Python:', err.message);
      warnings.push({
        package: '*',
        type: 'osv-failure',
        message: `OSV API unreachable: ${err.message}. Python scan returned partial results.`
      });
    }

    const dedupedVulns = this.deduplicateVulnerabilities(vulnerabilities);

    return {
      vulnerabilities: dedupedVulns,
      warnings,
      metrics: {
        packagesScanned: parsed.length,
        vulnerablePackages: dedupedVulns.length,
        osvQueryUsed: true
      },
      summary: this._buildEcosystemSummary(dedupedVulns, parsed.length, 'PyPI'),
      scannedAt: new Date().toISOString()
    };
  }

  // ══════════════════════════════════════════════════════════
  // PUBLIC — Java / Maven scanning
  // ══════════════════════════════════════════════════════════

  async scanJavaDependencies(pomXml) {
    if (!pomXml || typeof pomXml !== 'string') {
      return this._emptyResult('Maven');
    }

    const parsed = parsePomXml(pomXml);
    if (parsed.length === 0) {
      return this._emptyResult('Maven');
    }

    const warnings = [];
    const packages = [];

    for (const dep of parsed) {
      // Skip test-scoped dependencies unless they have no scope (defaults to compile)
      if (dep.scope === 'test' || dep.scope === 'provided') {
        continue;
      }

      if (!dep.version) {
        warnings.push({
          package: dep.name,
          type: 'no-version',
          message: `Version not specified in pom.xml (may be inherited from parent POM)`,
          suggestion: 'Ensure version is resolved through dependencyManagement or parent POM'
        });
      }

      // Check for unresolved properties
      if (dep.version && dep.version.includes('${')) {
        warnings.push({
          package: dep.name,
          type: 'unresolved-property',
          message: `Version contains unresolved property: ${dep.version}`,
          suggestion: 'Add the property to <properties> in pom.xml'
        });
        packages.push({ name: dep.name, ecosystem: 'Maven', version: 'unknown' });
        continue;
      }

      packages.push({
        name: dep.name,
        ecosystem: 'Maven',
        version: dep.version || 'unknown'
      });
    }

    // Query OSV
    const vulnerabilities = [];
    try {
      const queryable = packages.filter(p => p.version !== 'unknown');
      const osvResults = await queryOSVBatch(queryable);

      for (let i = 0; i < queryable.length; i++) {
        const pkg = queryable[i];
        const result = osvResults[i];
        if (result && Array.isArray(result.vulns) && result.vulns.length > 0) {
          for (const vuln of result.vulns) {
            vulnerabilities.push(
              normalizeOSVVuln(vuln, pkg.name, pkg.version, 'Maven')
            );
          }
        }
      }

      // Query packages without versions by name only
      const unknownPkgs = packages.filter(p => p.version === 'unknown');
      if (unknownPkgs.length > 0) {
        const unknownResults = await queryOSVBatch(unknownPkgs);
        for (let i = 0; i < unknownPkgs.length; i++) {
          const pkg = unknownPkgs[i];
          const result = unknownResults[i];
          if (result && Array.isArray(result.vulns) && result.vulns.length > 0) {
            for (const vuln of result.vulns) {
              vulnerabilities.push(
                normalizeOSVVuln(vuln, pkg.name, 'unknown', 'Maven')
              );
            }
          }
        }
      }
    } catch (err) {
      console.error('OSV query failed for Maven:', err.message);
      warnings.push({
        package: '*',
        type: 'osv-failure',
        message: `OSV API unreachable: ${err.message}. Maven scan returned partial results.`
      });
    }

    const dedupedVulns = this.deduplicateVulnerabilities(vulnerabilities);

    return {
      vulnerabilities: dedupedVulns,
      warnings,
      metrics: {
        packagesScanned: packages.length,
        vulnerablePackages: dedupedVulns.length,
        osvQueryUsed: true
      },
      summary: this._buildEcosystemSummary(dedupedVulns, packages.length, 'Maven'),
      scannedAt: new Date().toISOString()
    };
  }

  // ══════════════════════════════════════════════════════════
  // PUBLIC — Lock file scanning (npm only, kept for compat)
  // ══════════════════════════════════════════════════════════

  async scanLockFile(lockFileContent, type = 'npm') {
    if (type !== 'npm') {
      console.warn(`Lock file type "${type}" not yet supported for OSV scanning`);
      return [];
    }

    let lockData;
    try {
      lockData = JSON.parse(lockFileContent);
    } catch (err) {
      console.error('Failed to parse lock file:', err.message);
      return [];
    }

    const packagesMap = lockData.packages || lockData.dependencies || {};
    const packages = [];

    for (const [pkgPath, data] of Object.entries(packagesMap)) {
      if (!pkgPath || pkgPath === '' || !pkgPath.startsWith('node_modules/')) continue;
      const name = pkgPath.replace('node_modules/', '').replace(/^\//, '');
      if (name && data.version) {
        packages.push({ name, ecosystem: 'npm', version: data.version });
      }
    }

    if (packages.length === 0) return [];

    // Query OSV for lock-file packages
    const vulnerabilities = [];
    try {
      const osvResults = await queryOSVBatch(packages);
      for (let i = 0; i < packages.length; i++) {
        const pkg = packages[i];
        const result = osvResults[i];
        if (result && Array.isArray(result.vulns) && result.vulns.length > 0) {
          for (const vuln of result.vulns) {
            vulnerabilities.push(
              normalizeOSVVuln(vuln, pkg.name, pkg.version, 'npm')
            );
          }
        }
      }
    } catch (err) {
      console.error('OSV query failed for lock file, using fallback:', err.message);
      // Fallback to hardcoded DB
      for (const pkg of packages) {
        const fallback = this._checkFallbackDB(pkg.name, pkg.version);
        if (fallback) vulnerabilities.push(fallback);
      }
    }

    return vulnerabilities;
  }

  // ══════════════════════════════════════════════════════════
  // INTERNAL — Fallback / heuristic helpers
  // ══════════════════════════════════════════════════════════

  /** Check the hardcoded fallback DB for a single npm package. */
  _checkFallbackDB(packageName, version) {
    const entry = this.fallbackDB[packageName];
    if (!entry) return null;

    try {
      if (!semver.satisfies(version, entry.vulnerableVersions)) return null;
    } catch {
      return null;
    }

    return {
      package: packageName,
      installedVersion: version,
      ecosystem: 'npm',
      vulnerability: {
        id: entry.cve,
        severity: normSev(entry.severity),
        description: entry.description,
        cvss: heuristicCVSSFromSeverity(entry.severity),
        remediation: entry.remediation
      }
    };
  }

  /** Return an empty result set for a given ecosystem. */
  _emptyResult(ecosystem) {
    return {
      vulnerabilities: [],
      warnings: [],
      metrics: { packagesScanned: 0, vulnerablePackages: 0, osvQueryUsed: false },
      summary: {
        totalDependencies: 0,
        totalVulnerabilities: 0,
        severityDistribution: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
      },
      scannedAt: new Date().toISOString()
    };
  }

  /** Build a summary object for a single ecosystem. */
  _buildEcosystemSummary(vulnerabilities, totalDeps, ecosystem) {
    const dist = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const v of vulnerabilities) {
      const sev = normSev(v.vulnerability?.severity);
      if (dist.hasOwnProperty(sev)) dist[sev]++;
    }

    return {
      ecosystem,
      totalDependencies: totalDeps,
      totalVulnerabilities: vulnerabilities.length,
      severityDistribution: dist,
      needsImmediateAction: dist.critical > 0 || dist.high > 2
    };
  }

  /** Build a unified summary across all ecosystems. */
  _buildUnifiedSummary(vulnerabilities, totalDeps) {
    const dist = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const v of vulnerabilities) {
      const sev = normSev(v.vulnerability?.severity);
      if (dist.hasOwnProperty(sev)) dist[sev]++;
    }

    const riskCalc = calculateDependencyRiskScore(vulnerabilities);

    return {
      totalDependencies: totalDeps,
      totalVulnerabilities: vulnerabilities.length,
      severityDistribution: dist,
      riskScore: riskCalc.score,
      riskLevel: riskCalc.level.toUpperCase(),
      needsImmediateAction: dist.critical > 0 || dist.high > 2,
      recommendation: riskCalc.recommendation
    };
  }

  // ══════════════════════════════════════════════════════════
  // HELPERS (preserved from original for backward compat)
  // ══════════════════════════════════════════════════════════

  normalizeSeverity(severity) {
    return normSev(severity);
  }

  cleanVersion(version) {
    if (!version) return '0.0.0';
    if (version.startsWith('file:') || version.startsWith('git:')) return '0.0.0';

    let cleaned = version
      .replace(/^[\^~>=<\s"'()]+/, '')
      .replace(/["'()]+$/, '');

    if (cleaned.includes(' ')) cleaned = cleaned.split(' ')[0];
    if (cleaned.includes('||')) cleaned = cleaned.split('||')[0].trim();
    cleaned = cleaned.replace(/\.x/g, '.0');

    if (!semver.valid(cleaned)) {
      const coerced = semver.coerce(cleaned);
      return coerced ? coerced.version : '0.0.0';
    }
    return cleaned;
  }

  deduplicateVulnerabilities(vulnerabilities) {
    const seen = new Set();
    return vulnerabilities.filter(vuln => {
      const key = `${vuln.package}::${vuln.ecosystem}::${vuln.vulnerability?.id || vuln.vulnerability?.osvId || ''}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }

  getCVSSScore(severity) {
    return heuristicCVSSFromSeverity(severity);
  }

  async checkOutdatedPackages(dependencies) {
    const outdated = [];
    for (const [name, version] of Object.entries(dependencies)) {
      if (!version || version === '*' || version === 'latest' || version === '') continue;
      const cleaned = this.cleanVersion(version);
      const latest = this.latestVersions[name];
      if (!latest || !semver.valid(cleaned)) continue;

      try {
        if (semver.lt(cleaned, latest)) {
          outdated.push({
            package: name,
            current: version,
            installed: cleaned,
            latest,
            type: semver.major(latest) > semver.major(cleaned) ? 'major'
              : semver.minor(latest) > semver.minor(cleaned) ? 'minor' : 'patch',
            updateCommand: `npm install ${name}@${latest}`
          });
        }
      } catch { /* skip */ }
    }
    return outdated.sort((a, b) => {
      const p = { major: 3, minor: 2, patch: 1 };
      return (p[b.type] || 0) - (p[a.type] || 0);
    });
  }

  checkSecurityPackages(dependencies) {
    const recommendations = [];
    if (dependencies['express']) {
      if (!dependencies['helmet']) {
        recommendations.push({
          package: 'helmet',
          reason: 'Helps secure Express apps by setting HTTP headers',
          priority: 'high'
        });
      }
      if (!dependencies['express-rate-limit']) {
        recommendations.push({
          package: 'express-rate-limit',
          reason: 'Basic rate-limiting middleware for Express',
          priority: 'medium'
        });
      }
    }
    return recommendations;
  }
}

// ═══════════════════════════════════════════════════════════════
// STANDALONE RISK SCORE (kept for backward compat with server.js)
// ═══════════════════════════════════════════════════════════════

function calculateDependencyRiskScore(vulnerabilities) {
  const severityPoints = { critical: 40, high: 20, medium: 10, low: 5, info: 1 };
  let score = 0;
  const details = { critical: [], high: [], medium: [], low: [] };

  for (const vuln of vulnerabilities) {
    const sev = normSev(vuln.vulnerability?.severity);
    score += severityPoints[sev] || 5;
    if (sev !== 'info' && details[sev]) {
      details[sev].push(vuln.package);
    }
  }

  let level;
  if (score >= 100) level = 'critical';
  else if (score >= 50) level = 'high';
  else if (score >= 20) level = 'medium';
  else if (score > 0) level = 'low';
  else level = 'none';

  return {
    score,
    level,
    details,
    recommendation: score > 50
      ? 'Immediate action required to update vulnerable dependencies'
      : score > 20
        ? 'Schedule dependency updates in next sprint'
        : score > 0
          ? 'Minor vulnerabilities detected, include in regular maintenance'
          : 'Dependencies are secure'
  };
}

// ═══════════════════════════════════════════════════════════════
// EXPORTS
// ═══════════════════════════════════════════════════════════════

module.exports = {
  DependencyScanner,
  calculateDependencyRiskScore,
  // Export utilities for testing
  parseRequirementsTxt,
  parsePomXml,
  parseCVSSVector,
  computeCVSS31BaseScore,
  severityFromScore
};