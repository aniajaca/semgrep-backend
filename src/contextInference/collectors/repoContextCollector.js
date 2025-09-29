// src/contextInference/collectors/repoContextCollector.js
// ==============================================================================

const fs = require('fs').promises;
const path = require('path');

class RepoContextCollector {
  constructor(config = {}) {
    this.config = config;
    this.cache = new Map();
  }

  /**
   * Collect repository-level context
   */
  async collectRepoContext(repoPath) {
    // Check cache
    if (this.cache.has(repoPath)) {
      const cached = this.cache.get(repoPath);
      if (Date.now() - cached.timestamp < 300000) { // 5 min cache
        return cached.context;
      }
    }
    
    const context = {};
    
    // Check for production signals
    const productionSignals = await this.detectProductionSignals(repoPath);
    if (productionSignals.detected) {
      context.production = {
        value: true,
        confidence: productionSignals.confidence,
        evidence: productionSignals.evidence
      };
    }
    
    // Check for Docker
    const dockerSignals = await this.detectDockerSignals(repoPath);
    if (dockerSignals.production) {
      context.production = {
        value: true,
        confidence: Math.max(context.production?.confidence || 0, dockerSignals.confidence),
        evidence: [...(context.production?.evidence || []), ...dockerSignals.evidence]
      };
    }
    
    // Check for Kubernetes
    const k8sSignals = await this.detectKubernetesSignals(repoPath);
    if (k8sSignals.detected) {
      context.production = {
        value: true,
        confidence: Math.max(context.production?.confidence || 0, 0.9),
        evidence: [...(context.production?.evidence || []), ...k8sSignals.evidence]
      };
    }
    
    // Check for CI/CD
    const cicdSignals = await this.detectCICDSignals(repoPath);
    if (cicdSignals.production) {
      context.production = {
        value: true,
        confidence: Math.max(context.production?.confidence || 0, cicdSignals.confidence),
        evidence: [...(context.production?.evidence || []), ...cicdSignals.evidence]
      };
    }
    
    // Check for compliance/regulation signals
    const complianceSignals = await this.detectComplianceSignals(repoPath);
    if (complianceSignals.detected) {
      context.regulated = {
        value: true,
        confidence: complianceSignals.confidence,
        evidence: complianceSignals.evidence
      };
    }
    
    // Cache result
    this.cache.set(repoPath, {
      context,
      timestamp: Date.now()
    });
    
    return context;
  }

  /**
   * Detect production signals in config files
   */
  async detectProductionSignals(repoPath) {
    const evidence = [];
    let confidence = 0;
    
    // Check for production config files
    const configPatterns = [
      'config/production.json',
      'config/prod.json',
      '.env.production',
      '.env.prod',
      'application-prod.properties',
      'application-prod.yml',
      'settings/production.py'
    ];
    
    for (const pattern of configPatterns) {
      try {
        const filePath = path.join(repoPath, pattern);
        await fs.access(filePath);
        evidence.push(`Production config: ${pattern}`);
        confidence = Math.max(confidence, 0.8);
      } catch {
        // File doesn't exist
      }
    }
    
    // Check package.json for production scripts
    try {
      const pkgPath = path.join(repoPath, 'package.json');
      const pkg = JSON.parse(await fs.readFile(pkgPath, 'utf8'));
      
      if (pkg.scripts) {
        const prodScripts = ['start:prod', 'production', 'build:prod', 'deploy'];
        for (const script of prodScripts) {
          if (pkg.scripts[script]) {
            evidence.push(`Production script: ${script}`);
            confidence = Math.max(confidence, 0.7);
          }
        }
      }
    } catch {
      // No package.json
    }
    
    return {
      detected: confidence > 0,
      confidence,
      evidence
    };
  }

  /**
   * Detect Docker production signals
   */
  async detectDockerSignals(repoPath) {
    const evidence = [];
    let confidence = 0;
    let production = false;
    
    try {
      const dockerfilePath = path.join(repoPath, 'Dockerfile');
      const content = await fs.readFile(dockerfilePath, 'utf8');
      
      // Check for multi-stage with production stage
      if (/FROM.*AS\s+production/gi.test(content)) {
        evidence.push('Dockerfile: production stage');
        production = true;
        confidence = 0.9;
      }
      
      // Check for production environment variables
      if (/ENV\s+NODE_ENV\s*=?\s*production/gi.test(content)) {
        evidence.push('Dockerfile: NODE_ENV=production');
        production = true;
        confidence = Math.max(confidence, 0.8);
      }
      
      // Check for production commands
      if (/CMD.*prod|RUN.*build:prod/gi.test(content)) {
        evidence.push('Dockerfile: production commands');
        production = true;
        confidence = Math.max(confidence, 0.7);
      }
    } catch {
      // No Dockerfile
    }
    
    // Check docker-compose
    try {
      const composePath = path.join(repoPath, 'docker-compose.yml');
      const content = await fs.readFile(composePath, 'utf8');
      
      if (/docker-compose\.prod\.yml/gi.test(content)) {
        evidence.push('docker-compose: production config');
        production = true;
        confidence = Math.max(confidence, 0.7);
      }
    } catch {
      // No docker-compose
    }
    
    return {
      production,
      confidence,
      evidence
    };
  }

  /**
   * Detect Kubernetes deployments
   */
  async detectKubernetesSignals(repoPath) {
    const evidence = [];
    let detected = false;
    
    const k8sPatterns = [
      'k8s/',
      'kubernetes/',
      'manifests/',
      'deployment.yaml',
      'deployment.yml',
      'service.yaml',
      'service.yml',
      'ingress.yaml',
      'ingress.yml'
    ];
    
    for (const pattern of k8sPatterns) {
      try {
        const filePath = path.join(repoPath, pattern);
        const stats = await fs.stat(filePath);
        if (stats.isFile() || stats.isDirectory()) {
          evidence.push(`Kubernetes: ${pattern}`);
          detected = true;
        }
      } catch {
        // Path doesn't exist
      }
    }
    
    // Check for Helm charts
    try {
      const helmPath = path.join(repoPath, 'Chart.yaml');
      await fs.access(helmPath);
      evidence.push('Helm chart detected');
      detected = true;
    } catch {
      // No Helm chart
    }
    
    return {
      detected,
      evidence
    };
  }

  /**
   * Detect CI/CD production deployment
   */
  async detectCICDSignals(repoPath) {
    const evidence = [];
    let confidence = 0;
    let production = false;
    
    // GitHub Actions
    try {
      const workflowsPath = path.join(repoPath, '.github', 'workflows');
      const files = await fs.readdir(workflowsPath);
      
      for (const file of files) {
        if (file.endsWith('.yml') || file.endsWith('.yaml')) {
          const content = await fs.readFile(path.join(workflowsPath, file), 'utf8');
          
          if (/deploy.*production|production.*deploy/gi.test(content)) {
            evidence.push(`GitHub Actions: ${file} deploys to production`);
            production = true;
            confidence = Math.max(confidence, 0.8);
          }
        }
      }
    } catch {
      // No GitHub Actions
    }
    
    // GitLab CI
    try {
      const gitlabPath = path.join(repoPath, '.gitlab-ci.yml');
      const content = await fs.readFile(gitlabPath, 'utf8');
      
      if (/stage:\s*production|deploy:production/gi.test(content)) {
        evidence.push('GitLab CI: production deployment');
        production = true;
        confidence = Math.max(confidence, 0.8);
      }
    } catch {
      // No GitLab CI
    }
    
    // Jenkins
    try {
      const jenkinsPath = path.join(repoPath, 'Jenkinsfile');
      const content = await fs.readFile(jenkinsPath, 'utf8');
      
      if (/stage.*production|deploy.*prod/gi.test(content)) {
        evidence.push('Jenkins: production stage');
        production = true;
        confidence = Math.max(confidence, 0.8);
      }
    } catch {
      // No Jenkinsfile
    }
    
    return {
      production,
      confidence,
      evidence
    };
  }

  /**
   * Detect compliance/regulatory signals
   */
  async detectComplianceSignals(repoPath) {
    const evidence = [];
    let confidence = 0;
    
    // Check for compliance documentation
    const compliancePatterns = [
      'GDPR',
      'HIPAA',
      'PCI-DSS',
      'SOC2',
      'ISO27001',
      'COMPLIANCE.md',
      'compliance/',
      'privacy-policy',
      'data-protection'
    ];
    
    for (const pattern of compliancePatterns) {
      try {
        // Check root directory
        const files = await fs.readdir(repoPath);
        const matches = files.filter(f => 
          f.toLowerCase().includes(pattern.toLowerCase())
        );
        
        if (matches.length > 0) {
          evidence.push(`Compliance indicator: ${matches.join(', ')}`);
          confidence = Math.max(confidence, 0.7);
        }
      } catch {
        // Error reading directory
      }
    }
    
    // Check README for compliance mentions
    try {
      const readmePath = path.join(repoPath, 'README.md');
      const content = await fs.readFile(readmePath, 'utf8');
      
      const regulations = ['GDPR', 'HIPAA', 'PCI DSS', 'SOC 2', 'ISO 27001'];
      for (const reg of regulations) {
        if (new RegExp(reg, 'gi').test(content)) {
          evidence.push(`README mentions ${reg}`);
          confidence = Math.max(confidence, 0.6);
        }
      }
    } catch {
      // No README
    }
    
    return {
      detected: confidence > 0,
      confidence,
      evidence
    };
  }
}

module.exports = RepoContextCollector;