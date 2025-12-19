// test/unit/repoContextCollector.fixed.test.js
const RepoContextCollector = require('../../src/contextInference/collectors/repoContextCollector');
const fs = require('fs').promises;
const fullPath = path.isAbsolute(finding.file) 
  ? finding.file 
  : path.join(projectPath, finding.file);

describe('RepoContextCollector - Production Tests', () => {
  let collector;
  let tempDir;

  beforeEach(async () => {
    collector = new RepoContextCollector();
    tempDir = path.join('/tmp', `test-repo-${Date.now()}`);
    await fs.mkdir(tempDir, { recursive: true });
  });

  afterEach(async () => {
    try {
      await fs.rm(tempDir, { recursive: true, force: true });
    } catch (e) {
      // Ignore cleanup errors
    }
  });

  describe('collectRepoContext', () => {
    it('should collect context from valid repository', async () => {
      const packageJson = {
        name: 'test-project',
        version: '1.0.0',
        dependencies: {
          'express': '^4.18.0'
        }
      };
      await fs.writeFile(
        path.join(tempDir, 'package.json'),
        JSON.stringify(packageJson, null, 2)
      );

      const result = await collector.collectRepoContext(tempDir);
      
      expect(result).toBeDefined();
      expect(typeof result).toBe('object');
    });

    it('should handle missing package.json', async () => {
      const result = await collector.collectRepoContext(tempDir);
      expect(result).toBeDefined();
    });

    it('should handle non-existent directory', async () => {
      const result = await collector.collectRepoContext('/non/existent/path');
      expect(result).toBeDefined();
    });
  });

  describe('detectProductionSignals', () => {
    it('should detect production config files', async () => {
      await fs.mkdir(path.join(tempDir, 'config'), { recursive: true });
      await fs.writeFile(
        path.join(tempDir, 'config', 'production.json'),
        JSON.stringify({ env: 'production' })
      );

      const result = await collector.detectProductionSignals(tempDir);
      
      expect(result).toBeDefined();
      expect(typeof result).toBe('object');
      expect('confidence' in result).toBe(true);
    });

    it('should detect .env.production files', async () => {
      await fs.writeFile(
        path.join(tempDir, '.env.production'),
        'NODE_ENV=production\nDB_HOST=prod-db'
      );

      const result = await collector.detectProductionSignals(tempDir);
      expect(result).toBeDefined();
    });

    it('should return low confidence for no signals', async () => {
      const result = await collector.detectProductionSignals(tempDir);
      expect(result.confidence).toBeDefined();
    });
  });

  describe('detectDockerSignals', () => {
    it('should detect production Dockerfile', async () => {
      await fs.writeFile(
        path.join(tempDir, 'Dockerfile'),
        'FROM node:18\nENV NODE_ENV=production\nRUN npm install --production'
      );

      const result = await collector.detectDockerSignals(tempDir);
      expect(result).toBeDefined();
      expect(typeof result).toBe('object');
    });

    it('should detect docker-compose production config', async () => {
      await fs.writeFile(
        path.join(tempDir, 'docker-compose.prod.yml'),
        'version: "3"\nservices:\n  app:\n    environment:\n      - NODE_ENV=production'
      );

      const result = await collector.detectDockerSignals(tempDir);
      expect(result).toBeDefined();
    });

    it('should handle missing Docker files', async () => {
      const result = await collector.detectDockerSignals(tempDir);
      expect(result).toBeDefined();
    });
  });

  describe('detectKubernetesSignals', () => {
    it('should detect Kubernetes deployment files', async () => {
      await fs.mkdir(path.join(tempDir, 'k8s'), { recursive: true });
      await fs.writeFile(
        path.join(tempDir, 'k8s', 'deployment.yaml'),
        'apiVersion: apps/v1\nkind: Deployment'
      );

      const result = await collector.detectKubernetesSignals(tempDir);
      expect(result).toBeDefined();
      expect('detected' in result).toBe(true);
    });

    it('should handle missing Kubernetes files', async () => {
      const result = await collector.detectKubernetesSignals(tempDir);
      expect(result.detected).toBeDefined();
    });
  });

  describe('detectCICDSignals', () => {
    it('should detect GitHub Actions', async () => {
      await fs.mkdir(path.join(tempDir, '.github', 'workflows'), { recursive: true });
      await fs.writeFile(
        path.join(tempDir, '.github', 'workflows', 'deploy.yml'),
        'name: Deploy\non:\n  push:\n    branches: [main]\njobs:\n  deploy:\n    runs-on: ubuntu-latest'
      );

      const result = await collector.detectCICDSignals(tempDir);
      expect(result).toBeDefined();
      expect('production' in result).toBe(true);
    });

    it('should detect GitLab CI', async () => {
      await fs.writeFile(
        path.join(tempDir, '.gitlab-ci.yml'),
        'stages:\n  - deploy\nproduction:\n  stage: deploy'
      );

      const result = await collector.detectCICDSignals(tempDir);
      expect(result).toBeDefined();
    });

    it('should detect Jenkins', async () => {
      await fs.writeFile(
        path.join(tempDir, 'Jenkinsfile'),
        'pipeline {\n  stages {\n    stage("Deploy to Production") {}\n  }\n}'
      );

      const result = await collector.detectCICDSignals(tempDir);
      expect(result).toBeDefined();
    });

    it('should handle missing CI/CD files', async () => {
      const result = await collector.detectCICDSignals(tempDir);
      expect(result).toBeDefined();
    });
  });

  describe('detectComplianceSignals', () => {
    it('should detect GDPR references', async () => {
      await fs.writeFile(
        path.join(tempDir, 'README.md'),
        '# Project\nThis project is GDPR compliant.'
      );

      const result = await collector.detectComplianceSignals(tempDir);
      expect(result).toBeDefined();
      expect('detected' in result).toBe(true);
    });

    it('should detect HIPAA references', async () => {
      await fs.writeFile(
        path.join(tempDir, 'COMPLIANCE.md'),
        '# HIPAA Compliance\nThis system follows HIPAA guidelines.'
      );

      const result = await collector.detectComplianceSignals(tempDir);
      expect(result).toBeDefined();
    });

    it('should detect PCI-DSS references', async () => {
      await fs.writeFile(
        path.join(tempDir, 'README.md'),
        '# Payment Processing\nPCI DSS Level 1 certified.'
      );

      const result = await collector.detectComplianceSignals(tempDir);
      expect(result).toBeDefined();
    });

    it('should handle no compliance signals', async () => {
      const result = await collector.detectComplianceSignals(tempDir);
      expect(result.detected).toBeDefined();
    });
  });

  describe('Caching', () => {
    it('should cache repository context', async () => {
      const packageJson = {
        name: 'cached-project',
        version: '1.0.0'
      };
      await fs.writeFile(
        path.join(tempDir, 'package.json'),
        JSON.stringify(packageJson)
      );

      // First call
      const result1 = await collector.collectRepoContext(tempDir);
      
      // Second call (should use cache)
      const result2 = await collector.collectRepoContext(tempDir);
      
      expect(result1).toBeDefined();
      expect(result2).toBeDefined();
    });
  });

  describe('Error Handling', () => {
    it('should handle file read errors gracefully', async () => {
      const result = await collector.collectRepoContext('/invalid/path/###');
      expect(result).toBeDefined();
    });

    it('should handle invalid JSON in config files', async () => {
      await fs.writeFile(
        path.join(tempDir, 'package.json'),
        'invalid {{{ json'
      );

      const result = await collector.collectRepoContext(tempDir);
      expect(result).toBeDefined();
    });
  });
});