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
    
    // Detect test/dev file paths (language-independent)
    const lowerPath = (finding.file || '').toLowerCase().replace(/\\/g, '/');
    const nonProductionPatterns = [
      /\btest[s]?\//,
      /\bspec[s]?\//,
      /\b__test__\//,
      /\bscripts?\/(dev|util)\//,
      /\bfixtures?\//,
      /\bmocks?\//,
      /\.test\.[jt]sx?$/,
      /\.spec\.[jt]sx?$/,
    ];
    
    if (nonProductionPatterns.some(p => p.test(lowerPath))) {
      result.testOrDevCode = {
        value: true,
        confidence: 0.9,
        evidence: [`File path matches non-production pattern: ${finding.file}`]
      };
    }
    
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

      // =====================================================================
      // Post-processing: Auth-aware internetFacing adjustment (Fix #6)
      // =====================================================================
      // After all three detectors have run, cross-reference their results.
      //
      // Problem this solves:
      //   detectRoutes() finds app.get()/app.use() → sets internetFacing
      //   detectAuth()  finds requireAuth          → does NOT set noAuth
      //   But internetFacing stays set even though the service requires auth.
      //
      // Logic:
      //   IF routes were detected (internetFacing is set)
      //   AND auth middleware IS present (noAuth was NOT set)
      //   AND at least one additional internal-service indicator exists:
      //     - Non-standard port (not 80/443/3000)
      //     - /admin/ path prefix
      //     - /internal/ path prefix
      //   THEN: reclassify from internetFacing → authenticatedInternal
      //
      // This means:
      //   - Public API (routes + no auth)     → internetFacing stays  → P0
      //   - Internal tool (routes + auth + internal signals) → authenticatedInternal → P1
      //   - Public API with auth (routes + auth, standard port) → internetFacing stays → P0
      //     (because auth alone is not enough — public APIs have auth too)
      // =====================================================================
      if (result.internetFacing && !result.noAuth && fileContent) {
        const lowerContent = fileContent.toLowerCase();
        const internalSignals = ['Auth middleware detected (noAuth not triggered)'];

        // Non-standard ports suggest internal service (80/443/3000 are typical public ports)
        const portMatch = lowerContent.match(/\.listen\s*\(\s*(\d+)/);
        if (portMatch) {
          const port = parseInt(portMatch[1]);
          if (![80, 443, 3000].includes(port)) {
            internalSignals.push(`Non-standard port ${port} suggests internal service`);
          }
        }

        // Admin or internal path prefixes
        if (/['"`]\/admin\b/i.test(lowerContent)) {
          internalSignals.push('Admin path prefix detected');
        }
        if (/['"`]\/internal\b/i.test(lowerContent)) {
          internalSignals.push('Internal path prefix detected');
        }

        // Auth + at least one additional internal indicator → reclassify
        if (internalSignals.length >= 2) {
          delete result.internetFacing;
          result.authenticatedInternal = {
            value: true,
            confidence: 0.85,
            evidence: internalSignals
          };
        }
      }
      // =====================================================================
      // End post-processing
      // =====================================================================

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
    
    // === NEW: Detect test/dev/script file paths ===
    const lowerPath = (filePath || '').toLowerCase().replace(/\\/g, '/');
    const nonProductionPatterns = [
      /\btest[s]?\b/,          // test/, tests/
      /\bspec[s]?\b/,          // spec/, specs/
      /\b__test__\b/,          // __test__/
      /\b__spec__\b/,          // __spec__/
      /\bscripts?\/(dev|util)/, // scripts/dev/, script/util/
      /\bdev[-_]?tools?\b/,    // dev-tools/, devtool/
      /\bfixtures?\b/,         // fixtures/
      /\bmocks?\b/,            // mocks/
      /\.test\.[jt]sx?$/,      // *.test.js, *.test.ts
      /\.spec\.[jt]sx?$/,      // *.spec.js, *.spec.ts
    ];
    
    if (nonProductionPatterns.some(p => p.test(lowerPath))) {
      result.testOrDevCode = {
        value: true,
        confidence: 0.9,
        evidence: [`File path matches non-production pattern: ${filePath}`]
      };
    }
    // === END NEW ===


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