// dependencyScanner.js - Fixed version with all blockers resolved
const semver = require('semver');

class DependencyScanner {
  constructor() {
    // Expanded vulnerability database with more packages and detailed info
    this.vulnerabilityDB = {
      'lodash': {
        vulnerableVersions: '<4.17.21',
        cve: 'CVE-2021-23337',
        severity: 'high',
        description: 'Command injection vulnerability in lodash template function',
        remediation: 'Update to lodash@4.17.21 or later',
        affectedVersions: '4.17.0 - 4.17.20',
        exploitability: 'Remote code execution possible through template injection'
      },
      'minimist': {
        vulnerableVersions: '<1.2.6',
        cve: 'CVE-2021-44906',
        severity: 'critical',
        description: 'Prototype pollution allowing property injection',
        remediation: 'Update to minimist@1.2.6 or later',
        affectedVersions: '< 1.2.6',
        exploitability: 'Can lead to denial of service or remote code execution'
      },
      'axios': {
        vulnerableVersions: '<0.21.2',
        cve: 'CVE-2021-3749',
        severity: 'high',
        description: 'Server-Side Request Forgery (SSRF) in axios',
        remediation: 'Update to axios@0.21.2 or later',
        affectedVersions: '< 0.21.2',
        exploitability: 'Allows attackers to access internal services'
      },
      'express': {
        vulnerableVersions: '<4.17.3',
        cve: 'CVE-2022-24999',
        severity: 'high',
        description: 'Express.js Open Redirect vulnerability in query parser',
        remediation: 'Update to express@4.17.3 or later',
        affectedVersions: '< 4.17.3',
        exploitability: 'Can lead to phishing attacks through URL manipulation'
      },
      'node-fetch': {
        vulnerableVersions: '<2.6.7',
        cve: 'CVE-2022-0235',
        severity: 'medium',
        description: 'Regular expression denial of service (ReDoS)',
        remediation: 'Update to node-fetch@2.6.7 or later',
        affectedVersions: '< 2.6.7',
        exploitability: 'Can cause application slowdown or crash'
      },
      'jquery': {
        vulnerableVersions: '<3.5.0',
        cve: 'CVE-2020-11022',
        severity: 'medium',
        description: 'XSS vulnerability in jQuery DOM manipulation',
        remediation: 'Update to jquery@3.5.0 or later',
        affectedVersions: '< 3.5.0',
        exploitability: 'Cross-site scripting through untrusted HTML'
      },
      'moment': {
        vulnerableVersions: '<2.29.4',
        cve: 'CVE-2022-31129',
        severity: 'high',
        description: 'Path traversal vulnerability in moment.js',
        remediation: 'Update to moment@2.29.4 or later (Consider migrating to date-fns or dayjs)',
        affectedVersions: '< 2.29.4',
        exploitability: 'Can access files outside intended directory',
        note: 'Moment.js is now in maintenance mode - consider alternatives'
      },
      'webpack': {
        vulnerableVersions: '<5.76.0',
        cve: 'CVE-2023-28154',
        severity: 'medium',
        description: 'Webpack DOM XSS vulnerability in development server',
        remediation: 'Update to webpack@5.76.0 or later',
        affectedVersions: '< 5.76.0',
        exploitability: 'XSS in webpack-dev-server'
      },
      'react': {
        vulnerableVersions: '<16.4.2',
        cve: 'CVE-2018-14732',
        severity: 'medium',
        description: 'XSS vulnerability in React development builds',
        remediation: 'Update to react@16.4.2 or later',
        affectedVersions: '< 16.4.2',
        exploitability: 'Affects development builds only'
      },
      '@angular/core': {
        vulnerableVersions: '<11.0.5',
        cve: 'CVE-2021-21277',
        severity: 'high',
        description: 'XSS vulnerability in Angular sanitization',
        remediation: 'Update to @angular/core@11.0.5 or later',
        affectedVersions: '< 11.0.5',
        exploitability: 'Bypass of HTML sanitization'
      },
      'vue': {
        vulnerableVersions: '<2.6.14',
        cve: 'CVE-2021-3654',
        severity: 'medium',
        description: 'Prototype pollution in Vue.js',
        remediation: 'Update to vue@2.6.14 or later (or Vue 3)',
        affectedVersions: '< 2.6.14',
        exploitability: 'Can modify object prototypes'
      },
      'typescript': {
        vulnerableVersions: '<4.2.0',
        cve: 'CVE-2021-28168',
        severity: 'low',
        description: 'Path traversal in TypeScript compiler',
        remediation: 'Update to typescript@4.2.0 or later',
        affectedVersions: '< 4.2.0',
        exploitability: 'Limited to build-time'
      }
    };

    // Latest stable versions as of 2024
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

  /**
   * Helper to normalize severity strings
   */
  normalizeSeverity(severity) {
    return (severity || 'medium').toString().toLowerCase();
  }

  /**
   * FIX: Accept options parameter and honor includeDevDependencies
   */
  async scanDependencies(packageJson, options = {}) {
    const { includeDevDependencies = true } = options;
    
    const vulnerabilities = [];
    const warnings = [];

    // FIX: Conditionally include devDependencies based on options
    const dependencies = {
      ...packageJson.dependencies,
      ...(includeDevDependencies ? packageJson.devDependencies : {})
    };

    // Track scanning metrics
    let packagesScanned = 0;
    let undefinedVersions = 0;

    for (const [packageName, version] of Object.entries(dependencies)) {
      packagesScanned++;
      
      // Handle undefined, empty, or wildcard versions
      if (!version || version === '' || version === '*' || version === 'latest') {
        undefinedVersions++;
        vulnerabilities.push({
          id: `dep-${packageName}-undefined`,
          package: packageName,
          version: version || 'undefined',
          installedVersion: 'undefined',
          vulnerability: {
            cve: 'VERSION-UNDEFINED',
            severity: 'medium',
            description: `Package version is not specified or uses wildcard. This prevents security scanning and can lead to breaking changes.`,
            vulnerableVersions: 'Cannot determine without specific version',
            remediation: `Specify an exact version for ${packageName} in package.json (e.g., "^${this.latestVersions[packageName] || '1.0.0'}")`,
            affectedVersions: 'All versions when undefined',
            exploitability: 'Unknown vulnerabilities may exist',
            cvss: { baseScore: 5.0, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N' }
          }
        });
        continue;
      }

      // Clean and validate version
      const cleanVersion = this.cleanVersion(version);
      
      // Check if it's a valid semver
      if (!semver.valid(cleanVersion)) {
        warnings.push({
          package: packageName,
          message: `Invalid version format: ${version}`,
          suggestion: `Use a valid semver format like "^1.2.3"`
        });
        continue;
      }

      // Check against vulnerability database
      const vuln = this.vulnerabilityDB[packageName];
      if (vuln) {
        if (this.isVulnerable(cleanVersion, vuln.vulnerableVersions)) {
          vulnerabilities.push({
            id: `dep-${packageName}-${vuln.cve}`,
            package: packageName,
            version: version,
            installedVersion: cleanVersion,
            vulnerability: {
              ...vuln,
              severity: this.normalizeSeverity(vuln.severity),
              cvss: this.getCVSSScore(vuln.severity),
              patchedVersions: this.getPatchedVersion(packageName)
            }
          });
        }
      }

      // Check for deprecated packages
      if (this.isDeprecated(packageName)) {
        warnings.push({
          package: packageName,
          message: `Package is deprecated`,
          suggestion: this.getDeprecationAlternative(packageName)
        });
      }
    }

    // Check for outdated packages
    const outdatedPackages = await this.checkOutdatedPackages(dependencies);
    
    // Check for missing security packages
    const securityRecommendations = this.checkSecurityPackages(dependencies);

    // FIX: Deduplicate BEFORE generating summary to avoid double-counting
    const deduped = this.deduplicateVulnerabilities(vulnerabilities);

    return {
      vulnerabilities: deduped,
      outdatedPackages,
      warnings,
      securityRecommendations,
      metrics: {
        packagesScanned,
        undefinedVersions,
        vulnerablePackages: deduped.length,  // Use deduped count
        outdatedPackages: outdatedPackages.length
      },
      summary: this.generateEnhancedSummary(deduped, outdatedPackages, warnings)  // Pass deduped list
    };
  }

  /**
   * Check if version is vulnerable
   */
  isVulnerable(version, vulnerableVersions) {
    try {
      return semver.satisfies(version, vulnerableVersions);
    } catch {
      return false;
    }
  }

  /**
   * Check for deprecated packages (enhanced)
   */
  isDeprecated(packageName) {
    const deprecated = {
      'request': true,
      'request-promise': true,
      'node-sass': true,
      'tslint': true,
      'moment': true  // FIX: Added moment to deprecated check
    };
    return deprecated[packageName] || false;
  }

  /**
   * Get alternatives for deprecated packages
   */
  getDeprecationAlternative(packageName) {
    const alternatives = {
      'request': 'Use axios, node-fetch, or native fetch API',
      'request-promise': 'Use axios or node-fetch',
      'node-sass': 'Use sass (Dart Sass) instead',
      'tslint': 'Use ESLint with TypeScript support',
      'moment': 'Consider date-fns or dayjs for smaller bundle size'
    };
    return alternatives[packageName] || 'Check npm for modern alternatives';
  }

  /**
   * Enhanced check for security-enhancing packages
   */
  checkSecurityPackages(dependencies) {
    const recommendations = [];
    const securityPackages = {
      'helmet': {
        description: 'Helps secure Express apps by setting various HTTP headers',
        config: 'Consider enabling contentSecurityPolicy for XSS protection'
      },
      'express-rate-limit': {
        description: 'Basic rate-limiting middleware for Express',
        config: 'Configure with appropriate limits for your endpoints'
      },
      'express-validator': {
        description: 'Middleware for input validation',
        config: null
      },
      'bcrypt': {
        description: 'Library for hashing passwords',
        config: null
      },
      'jsonwebtoken': {
        description: 'JWT implementation for authentication',
        config: null
      },
      'dotenv': {
        description: 'Loads environment variables from .env file',
        config: null
      },
      'express-mongo-sanitize': {
        description: 'Prevents MongoDB injection attacks',
        config: null
      }
    };

    // Check if it's an Express app
    if (dependencies['express']) {
      if (!dependencies['helmet']) {
        recommendations.push({
          package: 'helmet',
          reason: securityPackages['helmet'].description,
          priority: 'high',
          config: securityPackages['helmet'].config
        });
      }

      if (!dependencies['express-rate-limit']) {
        recommendations.push({
          package: 'express-rate-limit',
          reason: securityPackages['express-rate-limit'].description,
          priority: 'medium',
          config: securityPackages['express-rate-limit'].config
        });
      }
    }

    // Note about xss-clean being legacy
    if (dependencies['xss-clean']) {
      recommendations.push({
        package: 'xss-clean',
        reason: 'Consider using modern template engines with built-in escaping or DOMPurify on the client',
        priority: 'info',
        type: 'legacy'
      });
    }

    return recommendations;
  }

  /**
   * Get patched version for vulnerable package
   */
  getPatchedVersion(packageName) {
    return this.latestVersions[packageName] || 'Check npm for latest version';
  }

  /**
   * Enhanced check for outdated packages
   */
  async checkOutdatedPackages(dependencies) {
    const outdated = [];
    
    for (const [packageName, version] of Object.entries(dependencies)) {
      // Skip if version is undefined or wildcard
      if (!version || version === '*' || version === 'latest' || version === '') {
        continue;
      }

      const cleanVersion = this.cleanVersion(version);
      const latest = this.latestVersions[packageName];
      
      if (latest && semver.valid(cleanVersion)) {
        try {
          if (semver.lt(cleanVersion, latest)) {
            const majorDiff = semver.major(latest) - semver.major(cleanVersion);
            const minorDiff = semver.minor(latest) - semver.minor(cleanVersion);
            const patchDiff = semver.patch(latest) - semver.patch(cleanVersion);
            
            outdated.push({
              package: packageName,
              current: version,
              installed: cleanVersion,
              latest: latest,
              type: majorDiff > 0 ? 'major' : minorDiff > 0 ? 'minor' : 'patch',
              behindBy: {
                major: majorDiff,
                minor: minorDiff,
                patch: patchDiff
              },
              updateCommand: `npm install ${packageName}@${latest}`
            });
          }
        } catch (error) {
          console.error(`Error comparing versions for ${packageName}:`, error);
        }
      }
    }

    return outdated.sort((a, b) => {
      // Sort by update type priority: major > minor > patch
      const priority = { major: 3, minor: 2, patch: 1 };
      return priority[b.type] - priority[a.type];
    });
  }

  /**
   * Clean version string (enhanced)
   */
  cleanVersion(version) {
    if (!version) return '0.0.0';
    
    // Handle file: and git: protocols
    if (version.startsWith('file:') || version.startsWith('git:')) {
      return '0.0.0';
    }
    
    // Remove common version prefixes and any parentheses/quotes
    let cleaned = version
      .replace(/^[\^~>=<\s"'()]+/, '')
      .replace(/["'()]+$/, '');
    
    // Handle version ranges
    if (cleaned.includes(' ')) {
      cleaned = cleaned.split(' ')[0];
    }
    
    if (cleaned.includes('||')) {
      cleaned = cleaned.split('||')[0].trim();
    }
    
    // Handle .x versions
    cleaned = cleaned.replace(/\.x/g, '.0');
    
    // Ensure it's a valid semver
    if (!semver.valid(cleaned)) {
      // Try to coerce to valid semver
      const coerced = semver.coerce(cleaned);
      if (coerced) {
        return coerced.version;
      }
      return '0.0.0';
    }
    
    return cleaned;
  }

  /**
   * Get CVSS score based on severity (heuristic, not official CVSS)
   */
  getCVSSScore(severity) {
    const normalizedSev = this.normalizeSeverity(severity);
    const scores = {
      'critical': {
        baseScore: 9.8,
        vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
      },
      'high': {
        baseScore: 7.5,
        vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'
      },
      'medium': {
        baseScore: 5.3,
        vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'
      },
      'low': {
        baseScore: 3.1,
        vector: 'CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N'
      },
      'info': {
        baseScore: 0.0,
        vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N'
      }
    };
    
    return scores[normalizedSev] || scores['medium'];
  }

  /**
   * Deduplicate vulnerabilities
   */
  deduplicateVulnerabilities(vulnerabilities) {
    const seen = new Set();
    return vulnerabilities.filter(vuln => {
      const key = `${vuln.package}-${vuln.vulnerability?.cve || vuln.id}`;
      if (seen.has(key)) {
        return false;
      }
      seen.add(key);
      return true;
    });
  }

  /**
   * Generate enhanced summary with actionable insights (FIXED)
   */
  generateEnhancedSummary(vulnerabilities, outdatedPackages, warnings) {
    const severityCount = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0
    };

    vulnerabilities.forEach(vuln => {
      const severity = this.normalizeSeverity(vuln.vulnerability?.severity);
      severityCount[severity]++;
    });

    // Use the SAME calculation function to avoid duplicates
    const riskCalc = calculateDependencyRiskScore(vulnerabilities);

    return {
      riskScore: riskCalc.score,
      riskLevel: riskCalc.level.toUpperCase(),
      totalVulnerabilities: vulnerabilities.length,
      totalOutdated: outdatedPackages.length,
      totalWarnings: warnings.length,
      severityDistribution: severityCount,
      needsImmediateAction: severityCount.critical > 0 || severityCount.high > 2,
      recommendation: this.generateDetailedRecommendation(severityCount, outdatedPackages, warnings),
      actionItems: this.generateActionItems(vulnerabilities, outdatedPackages),
      riskDetails: riskCalc.details
    };
  }

  /**
   * Generate detailed recommendations
   */
  generateDetailedRecommendation(severityCount, outdatedPackages, warnings) {
    const recommendations = [];

    if (severityCount.critical > 0) {
      recommendations.push({
        priority: 'CRITICAL',
        message: 'Critical vulnerabilities detected requiring immediate action',
        action: 'Update affected packages immediately to prevent potential security breaches'
      });
    }
    
    if (severityCount.high > 0) {
      recommendations.push({
        priority: 'HIGH',
        message: `${severityCount.high} high-severity vulnerabilities found`,
        action: 'Schedule updates within the next sprint'
      });
    }
    
    if (severityCount.medium > 0) {
      recommendations.push({
        priority: 'MEDIUM',
        message: `${severityCount.medium} medium-severity issues detected`,
        action: 'Plan updates in regular maintenance cycle'
      });
    }
    
    if (outdatedPackages.length > 10) {
      recommendations.push({
        priority: 'MAINTENANCE',
        message: 'Many outdated packages detected',
        action: 'Implement regular dependency update schedule'
      });
    }

    if (warnings.length > 0) {
      recommendations.push({
        priority: 'INFO',
        message: `${warnings.length} warnings about package configuration`,
        action: 'Review and fix package version specifications'
      });
    }
    
    if (recommendations.length === 0) {
      recommendations.push({
        priority: 'GOOD',
        message: 'Dependencies are relatively secure',
        action: 'Continue regular security monitoring'
      });
    }

    return recommendations;
  }

  /**
   * Generate specific action items
   */
  generateActionItems(vulnerabilities, outdatedPackages) {
    const actions = [];
    
    // Group vulnerabilities by package
    const vulnByPackage = {};
    vulnerabilities.forEach(v => {
      if (!vulnByPackage[v.package]) {
        vulnByPackage[v.package] = [];
      }
      vulnByPackage[v.package].push(v);
    });

    // Generate update commands
    Object.entries(vulnByPackage).forEach(([pkg, vulns]) => {
      const severities = vulns.map(v => this.normalizeSeverity(v.vulnerability?.severity));
      const priority = severities.includes('critical') ? 4 :
                      severities.includes('high') ? 3 :
                      severities.includes('medium') ? 2 : 1;
      
      const latest = this.latestVersions[pkg];
      if (latest) {
        actions.push({
          type: 'update',
          priority: priority,
          package: pkg,
          command: `npm install ${pkg}@${latest}`,
          reason: vulns[0].vulnerability.description
        });
      }
    });

    // Add major version updates
    outdatedPackages
      .filter(p => p.type === 'major')
      .slice(0, 5)
      .forEach(p => {
        actions.push({
          type: 'major-update',
          priority: 2,
          package: p.package,
          command: p.updateCommand,
          reason: `Major version behind (${p.behindBy.major} major versions)`
        });
      });

    return actions.sort((a, b) => b.priority - a.priority);
  }

  /**
   * Scan lock files for exact versions
   */
  async scanLockFile(lockFileContent, type = 'npm') {
    const vulnerabilities = [];
    
    if (type === 'npm') {
      try {
        const lockData = JSON.parse(lockFileContent);
        const packages = lockData.packages || lockData.dependencies || {};
        
        for (const [path, data] of Object.entries(packages)) {
          // FIX: Skip root package and non-node_modules paths
          if (!path || path === '' || (path && !path.startsWith('node_modules/'))) {
            continue;
          }
          
          const packageName = path.replace('node_modules/', '').replace(/^\//, '');
          if (packageName && data.version) {
            const vuln = this.vulnerabilityDB[packageName];
            if (vuln && this.isVulnerable(data.version, vuln.vulnerableVersions)) {
              vulnerabilities.push({
                package: packageName,
                version: data.version,
                installedVersion: data.version,
                vulnerability: {
                  ...vuln,
                  severity: this.normalizeSeverity(vuln.severity),
                  cvss: this.getCVSSScore(vuln.severity)
                }
              });
            }
          }
        }
      } catch (error) {
        console.error('Error parsing lock file:', error);
        return [{
          package: 'lock-file',
          version: 'unknown',
          vulnerability: {
            severity: 'info',
            description: 'Failed to parse lock file',
            remediation: 'Ensure lock file is valid JSON'
          }
        }];
      }
    }
    
    return vulnerabilities;
  }

  /**
   * Update latest versions (for refreshing the versions table)
   */
  updateLatestVersions(versionMap) {
    Object.assign(this.latestVersions, versionMap);
  }
}

/**
 * Enhanced risk score calculation
 */
function calculateDependencyRiskScore(vulnerabilities) {
  const severityPoints = {
    'critical': 40,
    'high': 20,
    'medium': 10,
    'low': 5,
    'info': 1
  };
  
  let score = 0;
  const details = {
    critical: [],
    high: [],
    medium: [],
    low: []
  };
  
  vulnerabilities.forEach(vuln => {
    // Normalize severity for consistency
    const severity = (vuln.vulnerability?.severity || 'medium').toString().toLowerCase();
    score += severityPoints[severity] || 5;
    
    if (severity !== 'info' && details[severity]) {
      details[severity].push(vuln.package);
    }
  });
  
  // Determine risk level
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
      ? '🚨 Immediate action required to update vulnerable dependencies'
      : score > 20
      ? '⚠️ Schedule dependency updates in next sprint'
      : score > 0
      ? 'ℹ️ Minor vulnerabilities detected, include in regular maintenance'
      : '✅ Dependencies are secure'
  };
}

module.exports = {
  DependencyScanner,
  calculateDependencyRiskScore
};