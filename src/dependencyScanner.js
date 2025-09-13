// dependencyScanner.js - Fixed version with external vulnerability database
const semver = require('semver');
const path = require('path');
const fs = require('fs');

// Load vulnerability database from external file
const vulnerabilityDBPath = path.join(__dirname, 'data', 'vulnerabilities-db.json');
const vulnerabilityData = JSON.parse(fs.readFileSync(vulnerabilityDBPath, 'utf8'));

class DependencyScanner {
  constructor() {
    // Use data from the external file instead of hardcoded
    this.vulnerabilityDB = vulnerabilityData.vulnerabilities;
    this.latestVersions = vulnerabilityData.latestVersions;
    this.deprecatedPackages = vulnerabilityData.deprecatedPackages;
  }

  /**
   * Helper to normalize severity strings
   */
  normalizeSeverity(severity) {
    return (severity || 'medium').toString().toLowerCase();
  }

  /**
   * Main scanning method - accepts options parameter and honors includeDevDependencies
   */
  async scanDependencies(packageJson, options = {}) {
    const { includeDevDependencies = true } = options;
    
    const vulnerabilities = [];
    const warnings = [];

    // Conditionally include devDependencies based on options
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
              cvss: vuln.cvss || this.getCVSSScore(vuln.severity),
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

    // Deduplicate BEFORE generating summary to avoid double-counting
    const deduped = this.deduplicateVulnerabilities(vulnerabilities);

    return {
      vulnerabilities: deduped,
      outdatedPackages,
      warnings,
      securityRecommendations,
      metrics: {
        packagesScanned,
        undefinedVersions,
        vulnerablePackages: deduped.length,
        outdatedPackages: outdatedPackages.length
      },
      summary: this.generateEnhancedSummary(deduped, outdatedPackages, warnings)
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
   * Check for deprecated packages
   */
  isDeprecated(packageName) {
    return this.deprecatedPackages && 
           this.deprecatedPackages[packageName] !== undefined;
  }

  /**
   * Get alternatives for deprecated packages
   */
  getDeprecationAlternative(packageName) {
    if (this.deprecatedPackages && this.deprecatedPackages[packageName]) {
      const depInfo = this.deprecatedPackages[packageName];
      if (depInfo.alternatives && depInfo.alternatives.length > 0) {
        return `${depInfo.reason}. Alternatives: ${depInfo.alternatives.join(', ')}`;
      }
      return depInfo.reason || 'Check npm for modern alternatives';
    }
    return 'Check npm for modern alternatives';
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
      },
      'cors': {
        description: 'CORS middleware for Express',
        config: 'Configure with specific origins in production'
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

      if (!dependencies['express-validator'] && !dependencies['joi'] && !dependencies['yup']) {
        recommendations.push({
          package: 'express-validator',
          reason: 'No input validation library detected',
          priority: 'high',
          config: 'Add input validation to all API endpoints'
        });
      }
    }

    // Check for MongoDB without sanitization
    if ((dependencies['mongodb'] || dependencies['mongoose']) && !dependencies['express-mongo-sanitize']) {
      recommendations.push({
        package: 'express-mongo-sanitize',
        reason: securityPackages['express-mongo-sanitize'].description,
        priority: 'high',
        config: null
      });
    }

    // Check for password handling without bcrypt
    if (!dependencies['bcrypt'] && !dependencies['argon2'] && !dependencies['scrypt']) {
      recommendations.push({
        package: 'bcrypt',
        reason: 'No password hashing library detected',
        priority: 'medium',
        config: 'Use for secure password storage'
      });
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
    if (version.startsWith('file:') || version.startsWith('git:') || version.startsWith('http')) {
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
   * Get CVSS score based on severity
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
   * Generate enhanced summary with actionable insights
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
          // Skip root package and non-node_modules paths
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
                  cvss: vuln.cvss || this.getCVSSScore(vuln.severity)
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
    
    // Support for yarn.lock
    if (type === 'yarn') {
      // Simple yarn.lock parsing (could be enhanced)
      const lines = lockFileContent.split('\n');
      const packagePattern = /^"?([^@\s]+)@.*"?:$/;
      const versionPattern = /^\s+version\s+"([^"]+)"/;
      
      let currentPackage = null;
      
      for (const line of lines) {
        const packageMatch = line.match(packagePattern);
        if (packageMatch) {
          currentPackage = packageMatch[1];
          continue;
        }
        
        const versionMatch = line.match(versionPattern);
        if (versionMatch && currentPackage) {
          const version = versionMatch[1];
          const vuln = this.vulnerabilityDB[currentPackage];
          
          if (vuln && this.isVulnerable(version, vuln.vulnerableVersions)) {
            vulnerabilities.push({
              package: currentPackage,
              version: version,
              installedVersion: version,
              vulnerability: {
                ...vuln,
                severity: this.normalizeSeverity(vuln.severity),
                cvss: vuln.cvss || this.getCVSSScore(vuln.severity)
              }
            });
          }
          currentPackage = null;
        }
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
  
  /**
   * Add new vulnerability to database (runtime update)
   */
  addVulnerability(packageName, vulnInfo) {
    this.vulnerabilityDB[packageName] = vulnInfo;
  }
  
  /**
   * Remove vulnerability from database (runtime update)
   */
  removeVulnerability(packageName) {
    delete this.vulnerabilityDB[packageName];
  }
  
  /**
   * Get all known vulnerabilities
   */
  getAllVulnerabilities() {
    return this.vulnerabilityDB;
  }
  
  /**
   * Check if package has known vulnerabilities
   */
  hasVulnerability(packageName) {
    return this.vulnerabilityDB.hasOwnProperty(packageName);
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