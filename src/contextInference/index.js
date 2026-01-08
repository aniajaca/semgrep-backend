// src/contextInference/index.js - Main context inference orchestrator

const JSContextDetector = require('./detectors/jsDetector');
const PythonContextDetector = require('./detectors/pythonDetector');
const JavaContextDetector = require('./detectors/javaDetector');
const RepoContextCollector = require('./collectors/repoContextCollector');
const ProfileManager = require('./profiles/profileManager');
const { canonicalizeContext } = require('./utils/canonicalizer');

class ContextInferenceSystem {
  constructor(config = {}) {
    this.config = config;
    this.detectors = {
      js: new JSContextDetector(config),
      python: new PythonContextDetector(config),
      java: new JavaContextDetector(config)
    };
    this.repoCollector = new RepoContextCollector(config);
    this.profileManager = new ProfileManager(config);
    
    // Feature flags from config
    this.features = config.features?.contextInference || {
      js: { routes: true, auth: true, pii: true },
      py: { routes: true, auth: true, pii: true },
      java: { routes: true, auth: true, pii: true }
    };
  }

  /**
   * Main entry point: Infer context for a finding
   * Returns { factorKey: { value: bool, confidence: number, evidence: string[] } }
   */
  async inferFindingContext(finding, fileContent, repoPath, options = {}) {
    const result = {};
    const language = this.detectLanguage(finding.file);
    
    if (!language || !this.detectors[language]) {
      return result;
    }

    try {
      const detector = this.detectors[language];
      
      // Route/Internet-facing detection
      if (this.isFeatureEnabled(language, 'routes')) {
        const routeResult = await detector.detectRoutes(fileContent, finding);
        if (routeResult.detected) {
          result.internetFacing = {
            value: true,
            confidence: routeResult.confidence,
            evidence: routeResult.evidence
          };
        }
      }

      // Auth detection
      if (this.isFeatureEnabled(language, 'auth')) {
        const authResult = await detector.detectAuth(fileContent, finding);
        if (authResult.missing) {
          result.noAuth = {
            value: true,
            confidence: authResult.confidence,
            evidence: authResult.evidence
          };
        }
      }

      // PII detection
      if (this.isFeatureEnabled(language, 'pii')) {
        const piiResult = await detector.detectPII(fileContent, finding);
        if (piiResult.detected) {
          result.handlesPI = {
            value: true,
            confidence: piiResult.confidence,
            evidence: piiResult.evidence
          };
        }
      }

    // Apply repo-level context
if (repoPath) {
  const repoContext = await this.repoCollector.collectRepoContext(repoPath);
  
  // Merge ALL repo-level context factors
  if (repoContext.production) {
    result.production = repoContext.production;
  }
  if (repoContext.internetFacing) {
    // Don't overwrite file-level detection if already found
    if (!result.internetFacing) {
      result.internetFacing = repoContext.internetFacing;
    }
  }
  if (repoContext.handlesPII) {
    // Don't overwrite file-level detection if already found
    if (!result.handlesPI) {
      result.handlesPI = repoContext.handlesPII;
    }
  }
  if (repoContext.regulated) {
    result.regulated = repoContext.regulated;
  }
}

    } catch (error) {
      console.error(`Context inference error for ${finding.file}:`, error.message);
      // Fail-open: continue without context
    }

    return result;
  }

  /**
   * Infer file-level exposure context
   */
  async inferFileContext(filePath, fileContent, options = {}) {
    const result = {};
    const language = this.detectLanguage(filePath);
    
    if (!language || !this.detectors[language]) {
      return result;
    }

    try {
      const detector = this.detectors[language];
      
      // Public API detection
      const apiResult = await detector.detectPublicAPI(fileContent);
      if (apiResult.detected) {
        result.publicAPI = {
          value: true,
          confidence: apiResult.confidence,
          evidence: apiResult.evidence
        };
      }

      // User input detection
      const inputResult = await detector.detectUserInput(fileContent);
      if (inputResult.detected) {
        result.userInput = {
          value: true,
          confidence: inputResult.confidence,
          evidence: inputResult.evidence
        };
      }

      // Auth presence for the file
      const authResult = await detector.detectFileAuth(fileContent);
      if (authResult.missing) {
        result.noAuth = {
          value: true,
          confidence: authResult.confidence,
          evidence: authResult.evidence
        };
      }

    } catch (error) {
      console.error(`File context inference error for ${filePath}:`, error.message);
    }

    return result;
  }

  /**
   * Flatten context to boolean values for calculators
   */
  flattenContext(enrichedContext) {
    const flattened = {};
    
    for (const [key, data] of Object.entries(enrichedContext)) {
      if (typeof data === 'object' && data.value !== undefined) {
        flattened[key] = Boolean(data.value);
      } else {
        flattened[key] = Boolean(data);
      }
    }
    
    return canonicalizeContext(flattened);
  }

  /**
   * Check if a feature is enabled
   */
  isFeatureEnabled(language, feature) {
    const langMap = { js: 'js', javascript: 'js', typescript: 'js', python: 'py', java: 'java' };
    const lang = langMap[language.toLowerCase()];
    return this.features[lang]?.[feature] !== false;
  }

  /**
   * Detect language from file extension
   */
  detectLanguage(filePath) {
    const ext = filePath.split('.').pop()?.toLowerCase();
    const langMap = {
      'js': 'js',
      'jsx': 'js', 
      'ts': 'js',
      'tsx': 'js',
      'mjs': 'js',
      'py': 'python',
      'pyi': 'python',
      'java': 'java'
    };
    return langMap[ext];
  }
}

module.exports = ContextInferenceSystem;