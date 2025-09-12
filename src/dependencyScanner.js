// dependencyScanner.js - Scan package.json for vulnerable dependencies
const https = require('https');
const semver = require('semver');

class DependencyScanner {
  constructor() {
    // Known vulnerabilities database (in production, use a real vulnerability DB)
    this.vulnerabilityDB = {
      'lodash': {
        vulnerableVersions: '<4.17.21',
        cve: 'CVE-2021-23337',
        severity: 'high',
        description: 'Command injection vulnerability in lodash',
        remediation: 'Update to lodash@4.17.21 or later'
      },
      'minimist': {
        vulnerableVersions: '<1.2.6',
        cve: 'CVE-2021-44906',
        severity: 'critical',
        description: 'Prototype pollution in minimist',
        remediation: 'Update to minimist@1.2.6 or later'
      },
      'axios': {
        vulnerableVersions: '<0.21.2',
        cve: 'CVE-2021-3749',
        severity: 'high',
        description: 'Server-Side Request Forgery in axios',
        remediation: 'Update to axios@0.21.2 or later'
      },
      'express': {
        vulnerableVersions: '<4.17.3',
        cve: 'CVE-2022-24999',
        severity: 'high',
        description: 'Express.js Open Redirect vulnerability',
        remediation: 'Update to express@4.17.3 or later'
      },
      'node-fetch': {
        vulnerableVersions: '<2.6.7',
        cve: 'CVE-2022-0235',
        severity: 'medium',
        description: 'Regular expression denial of service in node-fetch',
        remediation: 'Update to node-fetch@2.6.7 or later'
      },
      'jquery': {
        vulnerableVersions: '<3.5.0',
        cve: 'CVE-2020-11022',
        severity: 'medium',
        description: 'XSS vulnerability in jQuery',
        remediation: 'Update to jquery@3.5.0 or later'
      },
      'moment': {
        vulnerableVersions: '<2.29.4',
        cve: 'CVE-2022-31129',
        severity: 'high',
        description: 'Path traversal vulnerability in moment',
        remediation: 'Update to moment@2.29.4 or later'
      },
      'webpack': {
        vulnerableVersions: '<5.76.0',
        cve: 'CVE-2023-28154',
        severity: 'medium',
        description: 'Webpack DOM XSS vulnerability',
        remediation: 'Update to webpack@5.76.0 or later'
      },
      'react': {
        vulnerableVersions: '<16.4.2',
        cve: 'CVE-2018-14732',
        severity: 'medium',
        description: 'XSS vulnerability in React',
        remediation: 'Update to react@16.4.2 or later'
      },
      'angular': {
        vulnerableVersions: '<11.0.5',
        cve: 'CVE-2021-21277',
        severity: 'high',
        description: 'XSS vulnerability in Angular',
        remediation: 'Update to @angular/core@11.0.5 or later'
      }
    };
  }

  /**
   * Scan package.json for vulnerable dependencies
   */
  async scanDependencies(packageJson) {
    const vulnerabilities = [];
    const dependencies = {
      ...packageJson.dependencies,
      ...packageJson.devDependencies
    };

    for (const [packageName, version] of Object.entries(dependencies)) {
      // Check if package is in vulnerability database
      const vuln = this.vulnerabilityDB[packageName];
      if (vuln) {
        // Clean version string (remove ^, ~, etc.)
        const cleanVersion = this.cleanVersion(version);
        
        // Check if version is vulnerable
        if (this.isVulnerable(cleanVersion, vuln.vulnerableVersions)) {
          vulnerabilities.push({
            id: `dep-${packageName}-${vuln.cve}`,
            package: packageName,
            version: version,
            installedVersion: cleanVersion,
            vulnerability: {
              cve: vuln.cve,
              severity: vuln.severity,
              description: vuln.description,
              vulnerableVersions: vuln.vulnerableVersions,
              remediation: vuln.remediation,
              cvss: this.getCVSSScore(vuln.severity)
            }
          });
        }
      }

      // Also check with npm registry for additional vulnerabilities
      const npmVulns = await this.checkNpmRegistry(packageName, version);
      vulnerabilities.push(...npmVulns);
    }

    // Check for outdated packages
    const outdatedPackages = await this.checkOutdatedPackages(dependencies);
    
    return {
      vulnerabilities: this.deduplicateVulnerabilities(vulnerabilities),
      outdatedPackages,
      summary: this.generateSummary(vulnerabilities, outdatedPackages)
    };
  }

  /**
   * Check npm registry for vulnerabilities
   */
  async checkNpmRegistry(packageName, version) {
    // In production, this would call the actual npm audit API
    // For now, return empty array to avoid external dependencies
    return [];
    
    /* Production implementation:
    try {
      const response = await fetch(`https://registry.npmjs.org/-/npm/v1/security/audits`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: packageName,
          version: this.cleanVersion(version)
        })
      });
      
      const data = await response.json();
      return this.parseNpmAuditResponse(data);
    } catch (error) {
      console.error(`Failed to check npm registry for ${packageName}:`, error);
      return [];
    }
    */
  }

  /**
   * Check for outdated packages
   */
  async checkOutdatedPackages(dependencies) {
    const outdated = [];
    
    // Common packages with their latest stable versions (as of 2024)
    const latestVersions = {
      'react': '18.2.0',
      'vue': '3.3.4',
      'angular': '17.0.0',
      'express': '4.18.2',
      'lodash': '4.17.21',
      'axios': '1.6.0',
      'webpack': '5.89.0',
      'typescript': '5.3.0',
      'jest': '29.7.0',
      'eslint': '8.55.0'
    };

    for (const [packageName, version] of Object.entries(dependencies)) {
      const cleanVersion = this.cleanVersion(version);
      const latest = latestVersions[packageName];
      
      if (latest && semver.valid(cleanVersion)) {
        try {
          if (semver.lt(cleanVersion, latest)) {
            const majorDiff = semver.major(latest) - semver.major(cleanVersion);
            const minorDiff = semver.minor(latest) - semver.minor(cleanVersion);
            
            outdated.push({
              package: packageName,
              current: version,
              latest: latest,
              severity: majorDiff > 0 ? 'major' : minorDiff > 0 ? 'minor' : 'patch',
              behindBy: {
                major: majorDiff,
                minor: minorDiff,
                patch: semver.patch(latest) - semver.patch(cleanVersion)
              }
            });
          }
        } catch (error) {
          console.error(`Error comparing versions for ${packageName}:`, error);
        }
      }
    }

    return outdated;
  }

  /**
   * Clean version string (remove ^, ~, etc.)
   */
  cleanVersion(version) {
    if (!version) return '0.0.0';
    
    // Remove common version prefixes
    let cleaned = version.replace(/^[\^~>=<\s]+/, '');
    
    // Handle version ranges
    if (cleaned.includes(' ')) {
      cleaned = cleaned.split(' ')[0];
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
   * Check if version is vulnerable
   */
  isVulnerable(version, vulnerableRange) {
    try {
      if (!semver.valid(version)) {
        return false;
      }
      return semver.satisfies(version, vulnerableRange);
    } catch (error) {
      console.error('Error checking vulnerability:', error);
      return false;
    }
  }

  /**
   * Get CVSS score based on severity
   */
  getCVSSScore(severity) {
    const scores = {
      'critical': 9.0,
      'high': 7.5,
      'medium': 5.0,
      'low': 3.0,
      'info': 1.0
    };
    
    return {
      baseScore: scores[severity] || 5.0,
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L'
    };
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
   * Generate summary
   */
  generateSummary(vulnerabilities, outdatedPackages) {
    const severityCount = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0
    };

    vulnerabilities.forEach(vuln => {
      const severity = vuln.vulnerability?.severity || 'medium';
      severityCount[severity]++;
    });

    return {
      totalVulnerabilities: vulnerabilities.length,
      totalOutdated: outdatedPackages.length,
      severityDistribution: severityCount,
      needsImmediateAction: severityCount.critical > 0 || severityCount.high > 2,
      recommendation: this.generateRecommendation(severityCount, outdatedPackages)
    };
  }

  /**
   * Generate recommendation based on findings
   */
  generateRecommendation(severityCount, outdatedPackages) {
    if (severityCount.critical > 0) {
      return 'CRITICAL: Update vulnerable dependencies immediately. Critical security vulnerabilities detected.';
    }
    
    if (severityCount.high > 2) {
      return 'HIGH PRIORITY: Multiple high-severity vulnerabilities detected. Schedule immediate updates.';
    }
    
    if (severityCount.high > 0 || severityCount.medium > 5) {
      return 'MEDIUM PRIORITY: Security vulnerabilities detected. Plan updates in next sprint.';
    }
    
    if (outdatedPackages.length > 10) {
      return 'MAINTENANCE NEEDED: Many outdated packages detected. Schedule regular dependency updates.';
    }
    
    if (severityCount.low > 0 || outdatedPackages.length > 0) {
      return 'LOW PRIORITY: Minor issues detected. Include in regular maintenance cycle.';
    }
    
    return 'SECURE: No known vulnerabilities detected in dependencies.';
  }

  /**
   * Scan lock files for exact versions
   */
  async scanLockFile(lockFileContent, type = 'npm') {
    const vulnerabilities = [];
    
    if (type === 'npm') {
      // Parse package-lock.json
      try {
        const lockData = JSON.parse(lockFileContent);
        const packages = lockData.packages || lockData.dependencies;
        
        for (const [path, data] of Object.entries(packages)) {
          const packageName = path.replace('node_modules/', '');
          if (packageName && data.version) {
            const vuln = this.vulnerabilityDB[packageName];
            if (vuln && this.isVulnerable(data.version, vuln.vulnerableVersions)) {
              vulnerabilities.push({
                package: packageName,
                version: data.version,
                vulnerability: vuln
              });
            }
          }
        }
      } catch (error) {
        console.error('Error parsing lock file:', error);
      }
    } else if (type === 'yarn') {
      // Parse yarn.lock - simplified parsing
      const lines = lockFileContent.split('\n');
      let currentPackage = null;
      let currentVersion = null;
      
      lines.forEach(line => {
        if (line.match(/^[a-zA-Z@]/)) {
          const match = line.match(/^(.+?)@/);
          if (match) {
            currentPackage = match[1];
          }
        } else if (line.includes('version')) {
          const match = line.match(/version\s+"(.+?)"/);
          if (match && currentPackage) {
            currentVersion = match[1];
            const vuln = this.vulnerabilityDB[currentPackage];
            if (vuln && this.isVulnerable(currentVersion, vuln.vulnerableVersions)) {
              vulnerabilities.push({
                package: currentPackage,
                version: currentVersion,
                vulnerability: vuln
              });
            }
          }
        }
      });
    }
    
    return vulnerabilities;
  }
}

// Add endpoint to server.js
function addDependencyScanEndpoint(app) {
  const scanner = new DependencyScanner();
  
  app.post('/scan-dependencies', async (req, res) => {
    console.log('=== DEPENDENCY SCAN REQUEST ===');
    
    try {
      const { packageJson, lockFile, lockFileType } = req.body;
      
      if (!packageJson) {
        return res.status(400).json({
          status: 'error',
          message: 'No package.json provided'
        });
      }
      
      // Parse package.json if it's a string
      const pkgData = typeof packageJson === 'string' 
        ? JSON.parse(packageJson) 
        : packageJson;
      
      // Scan dependencies
      const results = await scanner.scanDependencies(pkgData);
      
      // If lock file provided, scan it too
      if (lockFile) {
        const lockVulns = await scanner.scanLockFile(lockFile, lockFileType || 'npm');
        results.vulnerabilities.push(...lockVulns);
        results.vulnerabilities = scanner.deduplicateVulnerabilities(results.vulnerabilities);
      }
      
      // Calculate risk score
      const riskScore = calculateDependencyRiskScore(results.vulnerabilities);
      
      res.json({
        status: 'success',
        ...results,
        riskScore,
        scanDate: new Date().toISOString()
      });
      
    } catch (error) {
      console.error('Dependency scan error:', error);
      res.status(500).json({
        status: 'error',
        message: 'Dependency scan failed',
        error: error.message
      });
    }
  });
}

/**
 * Calculate risk score for dependencies
 */
function calculateDependencyRiskScore(vulnerabilities) {
  const severityPoints = {
    'critical': 25,
    'high': 15,
    'medium': 8,
    'low': 3,
    'info': 1
  };
  
  let score = 0;
  vulnerabilities.forEach(vuln => {
    const severity = vuln.vulnerability?.severity || 'medium';
    score += severityPoints[severity] || 5;
  });
  
  // Determine risk level
  let level;
  if (score >= 50) level = 'critical';
  else if (score >= 25) level = 'high';
  else if (score >= 10) level = 'medium';
  else if (score > 0) level = 'low';
  else level = 'none';
  
  return {
    score,
    level,
    recommendation: score > 25 
      ? 'Immediate action required to update vulnerable dependencies'
      : score > 10
      ? 'Schedule dependency updates in next sprint'
      : score > 0
      ? 'Minor vulnerabilities detected, include in regular maintenance'
      : 'Dependencies are secure'
  };
}

module.exports = {
  DependencyScanner,
  addDependencyScanEndpoint,
  calculateDependencyRiskScore
};

// For testing
if (require.main === module) {
  const scanner = new DependencyScanner();
  const testPackageJson = {
    dependencies: {
      'express': '4.16.0',
      'lodash': '4.17.11',
      'axios': '0.19.0'
    },
    devDependencies: {
      'webpack': '5.0.0',
      'jest': '26.0.0'
    }
  };
  
  scanner.scanDependencies(testPackageJson).then(results => {
    console.log('Scan results:', JSON.stringify(results, null, 2));
  });
}