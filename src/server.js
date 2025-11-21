// server.js - CORRECTED TOP SECTION
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const path = require('path');
const fs = require('fs').promises;
const os = require('os');

// Security and utility imports
const rateLimit = require('express-rate-limit');

// Scanner imports
const { ASTVulnerabilityScanner } = require('./astScanner');
const { DependencyScanner } = require('./dependencyScanner');
const { runSemgrep, checkSemgrepAvailable, getSemgrepVersion } = require('./semgrepAdapter');const { normalizeFindings, enrichFindings, deduplicateFindings } = require('./lib/normalize');
const SnippetExtractor = require('./lib/snippetExtractor');

// Context and Profile imports (CORRECT ORDER)
const ContextInferenceSystem = require('./contextInference');
const ProfileManager = require('./contextInference/profiles/profileManager');

// Risk calculation
const EnhancedRiskCalculator = require('./enhancedRiskCalculator');
const Taxonomy = require('../data/taxonomy');

// Configuration
const config = require('./config/scanner.config.json');

// Initialize scanners (AFTER imports)
const astScanner = new ASTVulnerabilityScanner();
const depScanner = new DependencyScanner();
const snippetExtractor = new SnippetExtractor();
const contextInference = new ContextInferenceSystem();
const profileManager = new ProfileManager();

// Helper function for creating rate limiters
function createRateLimiter(max, windowMs) {
  return rateLimit({
    windowMs: windowMs,
    max: max,
    standardHeaders: true,
    legacyHeaders: false,
    message: 'Too many requests from this IP, please try again later.',
    // Skip validation for X-Forwarded-For header
    skip: (req) => false,
    keyGenerator: (req) => {
      return req.ip || req.connection.remoteAddress || 'unknown';
    }
  });
}

const app = express();
const PORT = process.env.PORT || 3000;

// Trust proxy headers (fixes X-Forwarded-For warning)
app.set('trust proxy', true);

// Security middleware - Helmet with proper CSP
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
}));

// CORS middleware
app.use(cors({
  origin: true,
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Body parsing middleware
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Global Semgrep availability flag
let semgrepAvailable = false;
let semgrepVersion = null;

/**
 * Helper function to extract CWE ID from various formats
 */
function extractCweId(cweField) {
  if (!cweField) return 'CWE-1';
  
  // Handle array format (from normalization)
  if (Array.isArray(cweField)) {
    return cweField[0] || 'CWE-1';
  }
  
  // Handle object format (from AST scanner)
  if (typeof cweField === 'object' && cweField !== null) {
    return cweField.id || cweField.cweId || 'CWE-1';
  }
  
  // Already a string
  return String(cweField);
}

/**
 * Sanitize and validate risk configuration
 */
function sanitizeRiskConfig(cfg = {}) {
  const config = JSON.parse(JSON.stringify(cfg)); // Deep clone
  
  // Sanitize severity points
  const points = config.severityPoints || config.fileLevel?.severityPoints;
  if (points) {
    ['critical', 'high', 'medium', 'low', 'info'].forEach(k => {
      if (points[k] != null) {
        points[k] = Math.max(0, Math.min(100, Number(points[k]) || 0));
      }
    });
  }
  
  // Sanitize risk thresholds
  const thresholds = config.riskThresholds || config.fileLevel?.riskThresholds;
  if (thresholds) {
    Object.keys(thresholds).forEach(k => {
      if (thresholds[k] != null) {
        thresholds[k] = Math.max(0, Math.min(100, Number(thresholds[k]) || 0));
      }
    });
    
    // Ensure proper ordering
    if (thresholds.critical != null && thresholds.high != null) {
      thresholds.high = Math.min(thresholds.high, thresholds.critical);
    }
    if (thresholds.high != null && thresholds.medium != null) {
      thresholds.medium = Math.min(thresholds.medium, thresholds.high);
    }
    if (thresholds.medium != null && thresholds.low != null) {
      thresholds.low = Math.min(thresholds.low, thresholds.medium);
    }
    if (thresholds.low != null && thresholds.minimal != null) {
      thresholds.minimal = Math.min(thresholds.minimal, thresholds.low);
    }
  }
  
  return config;
}

/**
 * Sanitize context factors
 */
function sanitizeContextFactors(context = {}) {
  const sanitized = { ...context };
  
  // Sanitize boolean context flags
  const booleanFlags = [
    'internetFacing', 'production', 'handlesPI', 'legacyCode',
    'businessCritical', 'compliance', 'thirdPartyIntegration', 'complexAuth'
  ];
  
  booleanFlags.forEach(flag => {
    if (sanitized[flag] !== undefined) {
      sanitized[flag] = !!sanitized[flag];
    }
  });
  
  // Sanitize custom factors
  if (sanitized.factors) {
    Object.keys(sanitized.factors).forEach(factorName => {
      const factor = sanitized.factors[factorName];
      if (factor && factor.weight != null) {
        factor.weight = Math.max(0.5, Math.min(3.0, Number(factor.weight) || 1.0));
      }
    });
  }
  
  return sanitized;
}

/**
 * Helper function to normalize severity strings
 */
function normalizeSeverity(severity) {
  return (severity || 'info').toString().toLowerCase();
}

/**
 * Process findings through context inference and risk calculation
 */
async function processFindingsWithContext(findings, profile, manualContext = {}, code = null, targetPath = null) {
  const profileManager = new ProfileManager();
  const contextInference = new ContextInferenceSystem();
  
  // Get profile hash for provenance
  const profileHash = profileManager.calculateProfileHash(profile);
  
  // Convert profile to calculator config
  const calculatorConfig = profileManager.translateProfileToCalculatorConfig(profile);
  
  // Create calculator with profile config
  const riskCalculator = new EnhancedRiskCalculator(calculatorConfig);
  
  // Process each finding
  const enrichedFindings = [];
  
  for (const finding of findings) {
    // Infer context
    let inferredContext = {};
    let contextEvidence = {};
    
    if (code || targetPath) {
      const fileContent = code || await fs.readFile(
        path.join(targetPath || '.', finding.file), 
        'utf8'
      ).catch(() => '');
      
      const inferenceResult = await contextInference.inferFindingContext(
        finding,
        fileContent,
        targetPath,
        { features: profile.features?.contextInference }
      );
      
      // Separate evidence from values
      Object.entries(inferenceResult).forEach(([factor, data]) => {
        if (typeof data === 'object' && data.value !== undefined) {
          inferredContext[factor] = data.value;
          contextEvidence[factor] = {
            confidence: data.confidence,
            evidence: data.evidence
          };
        } else {
          inferredContext[factor] = Boolean(data);
        }
      });
    }
    
    // Merge with manual context
    const finalContext = {
      ...inferredContext,
      ...manualContext
    };
    
    // Apply profile's enabled factors
    if (profile.contextFactors?.enabled) {
      Object.entries(profile.contextFactors.enabled).forEach(([factor, enabled]) => {
        if (!enabled) {
          delete finalContext[factor];
        }
      });
    }
    
    // Calculate risk
    const vulnData = {
      severity: normalizeSeverity(finding.severity),
      cwe: extractCweId(finding.cwe),
      cweId: extractCweId(finding.cwe),
      cvss: finding.cvss,
      file: finding.file,
      line: finding.startLine || finding.line
    };
    
    const riskResult = riskCalculator.calculateVulnerabilityRisk(vulnData, finalContext);
    
    // Enrich finding
    enrichedFindings.push({
      ...finding,
      bts: riskResult.original.cvss,
      crs: Math.min(100, riskResult.adjusted.score * 10),
      adjustedSeverity: riskResult.adjusted.severity,
      priority: riskResult.adjusted.priority,
      context: finalContext,
      contextEvidence: contextEvidence,
      inferredFactors: Object.keys(inferredContext),
      appliedFactors: riskResult.factors.applied.map(f => f.id),
      remediation: riskResult.remediation,
      sla: profile.slaMapping?.[riskResult.adjusted.priority.priority]?.days || 90
    });
  }
  
  return enrichedFindings;
}

/**
 * Get JavaScript/TypeScript files from a directory
 */
async function getJavaScriptFiles(dir, files = []) {
  try {
    const items = await fs.readdir(dir, { withFileTypes: true });
    
    for (const item of items) {
      const fullPath = path.join(dir, item.name);
      
      // Skip excluded directories
      if (config.scanning.excludePaths.includes(item.name)) {
        continue;
      }
      
      if (item.isDirectory()) {
        await getJavaScriptFiles(fullPath, files);
      } else if (item.name.match(/\.(js|jsx|ts|tsx)$/)) {
        files.push(fullPath);
      }
    }
  } catch (error) {
    console.error(`Error reading directory ${dir}:`, error.message);
  }
  
  return files;
}

/**
 * Detect languages in a directory
 */
async function detectLanguages(targetPath) {
  const languages = new Set();
  
  async function scanDir(dir) {
    try {
      const items = await fs.readdir(dir, { withFileTypes: true });
      
      for (const item of items) {
        if (config.scanning.excludePaths.includes(item.name)) {
          continue;
        }
        
        const fullPath = path.join(dir, item.name);
        
        if (item.isDirectory()) {
          await scanDir(fullPath);
        } else {
          const ext = path.extname(item.name);
          if (['.js', '.jsx', '.ts', '.tsx'].includes(ext)) {
            languages.add('javascript');
          } else if (ext === '.py') {
            languages.add('python');
          } else if (ext === '.java') {
            languages.add('java');
          }
        }
      }
    } catch (error) {
      console.error(`Error scanning directory ${dir}:`, error.message);
    }
  }
  
  await scanDir(targetPath);
  return Array.from(languages);
}

/**
 * Calculate risk index for summaries
 */
function calculateRiskIndex(findings) {
  if (!findings || findings.length === 0) return 0;
  
  const weights = {
    critical: 10,
    high: 5,
    medium: 2,
    low: 0.5,
    info: 0.1
  };
  
  let totalRisk = 0;
  findings.forEach(f => {
    const severity = normalizeSeverity(f.adjustedSeverity || f.severity);
    const weight = weights[severity] || 1;
    const score = f.adjustedScore || f.cvssBase || 5;
    totalRisk += score * weight;
  });
  
  return Math.min(100, Math.round(totalRisk / Math.max(1, findings.length)));
}

// Replace the entire /scan-code endpoint with this corrected version:
app.post('/scan-code', createRateLimiter(50, 60000), async (req, res) => {
  console.log('=== CODE SCAN REQUEST RECEIVED ===');
  
  const startTime = Date.now();
  let tempDir = null;
  
  try {
    const { 
      code,
      path: targetPath,
      language = 'javascript',
      languages,
      filename = 'code.js',
      engine = 'auto',
      profileId = 'default',  // Use profile instead of raw config
      manualContext = {}      // Still allow manual overrides
    } = req.body;
    
    // Validate input
    if (!code && !targetPath) {
      return res.status(400).json({ 
        status: 'error', 
        message: 'No code or path provided' 
      });
    }
    
    console.log('Scan type:', code ? 'code string' : 'file path');
    console.log('Language:', language);
    console.log('Profile:', profileId);
    
    // Load the profile
    let profile;
    try {
      profile = await profileManager.loadProfile(profileId);
      console.log(`Loaded profile: ${profile.name}`);
    } catch (error) {
      console.log(`Profile ${profileId} not found, using default`);
      profile = profileManager.getDefaultProfile();
    }
    
    // Get profile hash for provenance
    const profileHash = profileManager.calculateProfileHash(profile);
    
    // Convert profile to calculator config
    const calculatorConfig = profileManager.translateProfileToCalculatorConfig(profile);
    
    // Create calculator with profile config
    const riskCalculator = new EnhancedRiskCalculator(calculatorConfig);
    
    // Initialize findings array
    const allFindings = [];
    let usedEngine = null;
    let actualTargetPath = targetPath;
    
    // CREATE TEMP FILE FOR SEMGREP WHEN CODE STRING PROVIDED
    if (code && !targetPath && semgrepAvailable) {
      tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'neperia-'));
      const tempFile = path.join(tempDir, filename);
      await fs.writeFile(tempFile, code);
      actualTargetPath = tempDir;
      console.log('Created temp file for Semgrep:', tempFile);
    }
    
    // RUN SCANNERS
    if (actualTargetPath && semgrepAvailable) {
      try {
        const scanLanguages = languages || [language];
        console.log('Running Semgrep scan on path:', actualTargetPath);
        
        const semgrepOptions = {
          languages: scanLanguages,
          severity: config.semgrepConfig?.severity || 'ERROR,WARNING',
          timeout: config.semgrepConfig?.timeout || 30,
          rulesets: config.semgrepConfig?.rulesets || []
        };
        
        const semgrepFindings = await runSemgrep(actualTargetPath, semgrepOptions);
        allFindings.push(...semgrepFindings);
        usedEngine = 'semgrep';
        
        console.log(`Semgrep found ${semgrepFindings.length} issues`);
      } catch (semgrepError) {
        console.error('Semgrep scan failed:', semgrepError.message);
        
        if (language === 'javascript' && code) {
          console.log('Falling back to AST scanner for JavaScript');
          usedEngine = null;
        } else {
          throw new Error(`Semgrep failed for ${language}: ${semgrepError.message}`);
        }
      }
    }
    
    // Fallback to AST for JavaScript
    if (!usedEngine && code && language === 'javascript') {
      console.log('Using AST scanner for JavaScript');
      const astFindings = astScanner.scan(code, filename, 'javascript');
      
      const enhancedAstFindings = astFindings.map(f => ({
        engine: 'ast',
        ruleId: f.check_id,
        category: 'sast',
        severity: f.severity.toUpperCase(),
        message: f.message,
        cwe: [f.cweId],
        owasp: [f.owasp?.category || 'A06:2021'],
        file: f.file,
        startLine: f.line,
        endLine: f.line,
        snippet: f.snippet,
        confidence: 'HIGH'
      }));
      
      allFindings.push(...enhancedAstFindings);
      usedEngine = 'ast';
      
      console.log(`AST scanner found ${astFindings.length} issues`);
    }
    
    // Clean up temp directory
    if (tempDir) {
      try {
        await fs.rm(tempDir, { recursive: true, force: true });
        console.log('Cleaned up temp directory');
      } catch (cleanupError) {
        console.error('Failed to clean up temp directory:', cleanupError);
      }
    }
    
        // Normalize findings
      const normalized = normalizeFindings(allFindings);
      const enriched = enrichFindings(normalized);
      const deduplicated = deduplicateFindings(enriched);

      // 🔧 FIX: Normalize CWE to strings BEFORE processing
      const safeFindings = deduplicated.map(f => ({
        ...f,
        cwe: extractCweId(f.cwe),
        cweId: extractCweId(f.cwe || f.cweId)
      }));

      // CONTEXT INFERENCE INTEGRATION
      const enrichedFindings = [];

      for (const finding of safeFindings) {  // ← Use safeFindings, not deduplicated
        // Step 1: Infer context for this finding
        let inferredContext = {};
        let contextEvidence = {};

      
      if (code || targetPath) {
        const fileContent = code || await fs.readFile(
          path.join(targetPath || '.', finding.file), 
          'utf8'
        ).catch(() => '');
        
        // Run context inference
        const inferenceResult = await contextInference.inferFindingContext(
          finding,
          fileContent,
          targetPath,
          { features: profile.features?.contextInference }
        );
        
        // Separate evidence from values
        Object.entries(inferenceResult).forEach(([factor, data]) => {
          if (typeof data === 'object' && data.value !== undefined) {
            inferredContext[factor] = data.value;
            contextEvidence[factor] = {
              confidence: data.confidence,
              evidence: data.evidence
            };
          } else {
            inferredContext[factor] = Boolean(data);
          }
        });
      }
      
      // Step 2: Merge with manual context (manual overrides inference)
      const finalContext = {
        ...inferredContext,
        ...manualContext
      };
      
      // Step 3: Apply profile's enabled factors
      if (profile.contextFactors?.enabled) {
        Object.entries(profile.contextFactors.enabled).forEach(([factor, enabled]) => {
          if (!enabled) {
            delete finalContext[factor];
          }
        });
      }
      
      // Step 4: Calculate risk with real calculator
      const vulnData = {
        severity: normalizeSeverity(finding.severity),
        cwe: extractCweId(finding.cwe),
        cweId: extractCweId(finding.cwe),
        cvss: finding.cvss,
        file: finding.file,
        line: finding.startLine || finding.line
      };
      
      const riskResult = riskCalculator.calculateVulnerabilityRisk(vulnData, finalContext);
      
      // Step 5: Enrich finding with all results
      enrichedFindings.push({
        ...finding,
        
        // Risk scores
        bts: riskResult.original.cvss,
        crs: Math.min(100, riskResult.adjusted.score * 10),
        adjustedSeverity: riskResult.adjusted.severity,
        priority: riskResult.adjusted.priority,
        
        // Context information
        context: finalContext,
        contextEvidence: contextEvidence,
        inferredFactors: Object.keys(inferredContext),
        appliedFactors: riskResult.factors.applied.map(f => f.id),
        
        // Remediation
        remediation: riskResult.remediation,
        sla: profile.slaMapping?.[riskResult.adjusted.priority.priority]?.days || 90
      });
    }
    
    // Sort by CRS descending
    enrichedFindings.sort((a, b) => b.crs - a.crs);
    
    // Calculate overall project risk
    const overallRisk = riskCalculator.calculateFileRisk(
      enrichedFindings,
      manualContext
    );
    
    // Build severity distribution
    const severityDistribution = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0
    };
    
    enrichedFindings.forEach(f => {
      const severity = normalizeSeverity(f.adjustedSeverity);
      if (severityDistribution.hasOwnProperty(severity)) {
        severityDistribution[severity]++;
      }
    });
    
    // Build response with provenance
    res.json({
      status: 'success',
      engine: usedEngine,
      findings: enrichedFindings,
      overallRisk: {
        score: overallRisk.score,
        risk: overallRisk.risk,
        level: overallRisk.risk.level,
        priority: overallRisk.risk.priority
      },
      summary: {
        totalFindings: enrichedFindings.length,
        severityDistribution,
        contextFactorsDetected: [...new Set(enrichedFindings.flatMap(f => f.inferredFactors))],
        top5: enrichedFindings.slice(0, 5).map(f => ({
          file: path.basename(f.file),
          line: f.startLine || f.line,
          cwe: f.cwe,
          severity: f.adjustedSeverity,
          crs: Math.round(f.crs),
          priority: f.priority.priority,
          message: f.message
        }))
      },
      provenance: {
        profileId: profileId,
        profileHash: profileHash,
        profileVersion: profile.version,
        taxonomyVersion: '2.0.0',
        contextInferenceVersion: '1.0.0',
        timestamp: new Date().toISOString(),
        scanDuration: `${Date.now() - startTime}ms`,
        configuration: {
          language: language,
          engine: usedEngine,
          contextInferenceEnabled: true,
          featuresEnabled: profile.features?.contextInference || {}
        }
      }
    });
    
  } catch (error) {
    console.error('Scan error:', error);
    
    if (tempDir) {
      try {
        await fs.rm(tempDir, { recursive: true, force: true });
      } catch (cleanupError) {
        console.error('Failed to clean up temp directory:', cleanupError);
      }
    }
    
    res.status(500).json({ 
      status: 'error', 
      message: 'Code scan failed',
      error: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

/**
 * Enhanced dependency scanning endpoint
 */
app.post('/scan-dependencies', createRateLimiter(50, 60000), async (req, res) => {
  console.log('=== DEPENDENCY SCAN REQUEST RECEIVED ===');
  
  try {
    const {
      packageJson,
      packageLock,
      lockFile,
      lockFileType = 'npm',
      path: projectPath,
      includeDevDependencies = false,
      riskConfig = {},
      context = {}
    } = req.body;
    
    // Handle file-based scanning
    let pkgJson = packageJson;
    let lockData = packageLock || lockFile;
    
    if (projectPath && !packageJson) {
      try {
        const pkgPath = path.join(projectPath, 'package.json');
        const pkgContent = await fs.readFile(pkgPath, 'utf8');
        pkgJson = JSON.parse(pkgContent);
        
        // Try to find lock file
        const lockPaths = [
          path.join(projectPath, 'package-lock.json'),
          path.join(projectPath, 'yarn.lock'),
          path.join(projectPath, 'pnpm-lock.yaml')
        ];
        
        for (const lockPath of lockPaths) {
          try {
            lockData = await fs.readFile(lockPath, 'utf8');
            if (lockPath.includes('yarn')) lockFileType = 'yarn';
            if (lockPath.includes('pnpm')) lockFileType = 'pnpm';
            break;
          } catch (e) {
            // Continue to next lock file
          }
        }
      } catch (error) {
        return res.status(400).json({
          status: 'error',
          message: 'Could not read package.json from path',
          error: error.message
        });
      }
    }
    
    if (!pkgJson) {
      return res.status(400).json({
        status: 'error',
        message: 'No package.json provided or found'
      });
    }
    
    // Parse packageJson if string
    if (typeof pkgJson === 'string') {
      pkgJson = JSON.parse(pkgJson);
    }
    
    // Scan dependencies
    const scanResults = await depScanner.scanDependencies(pkgJson, {
      includeDevDependencies
    });
    
    // Process lock file if provided
    if (lockData) {
      try {
        const lockVulns = await depScanner.scanLockFile(lockData, lockFileType);
        if (lockVulns && lockVulns.length > 0) {
          scanResults.vulnerabilities.push(...lockVulns);
          scanResults.vulnerabilities = depScanner.deduplicateVulnerabilities(scanResults.vulnerabilities);
          scanResults.summary.totalVulnerabilities = scanResults.vulnerabilities.length;
        }
      } catch (lockError) {
        console.warn('Lock file scan failed:', lockError.message);
      }
    }
    
    // Sanitize configurations
    const sanitizedConfig = sanitizeRiskConfig(riskConfig);
    const sanitizedContext = sanitizeContextFactors(context);
    
    // Calculate risk scores
    const calc = new EnhancedRiskCalculator(sanitizedConfig);
    
    // Score each vulnerability
    const scoredVulnerabilities = scanResults.vulnerabilities.map(vuln => {
      const cweId = extractCweId(vuln.cwe || vuln.cweId);
      
      const v = {
        severity: normalizeSeverity(vuln.severity),
        cwe: cweId,
        cweId: cweId,
        cvss: vuln.cvss
      };
      
      const riskResult = calc.calculateVulnerabilityRisk(v, sanitizedContext);
      
      return {
        ...vuln,
        cwe: cweId,  // Ensure CWE is a string
        cvssBase: vuln.cvss?.baseScore || riskResult.original.cvss,
        adjustedScore: riskResult.adjusted.score,
        adjustedSeverity: riskResult.adjusted.severity,
        priority: riskResult.adjusted.priority.priority,
        remediation: riskResult.remediation
      };
    });
    
    // Sort by adjusted score
    scoredVulnerabilities.sort((a, b) => b.adjustedScore - a.adjustedScore);
    
    // Get severity distribution
    const dist = scanResults.summary?.severityDistribution || {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0
    };
    
    // Calculate overall risk
    const { score, risk } = calc.calculateFromSeverityDistribution(dist, sanitizedContext);
    
    // Build enhanced results
    const enhancedResults = {
      ...scanResults,
      vulnerabilities: scoredVulnerabilities,
      score,
      risk,
      summary: {
        ...scanResults.summary,
        riskScore: score.final,
        riskLevel: risk.level.charAt(0).toUpperCase() + risk.level.slice(1),
        confidence: risk.confidence,
        priority: risk.priority,
        adjustedRiskIndex: calculateRiskIndex(scoredVulnerabilities),
        top5: scoredVulnerabilities.slice(0, 5).map(v => ({
          package: v.package,
          vulnerability: v.vulnerability,
          severity: v.adjustedSeverity,
          score: v.adjustedScore
        }))
      }
    };
    
    res.json({
      status: 'success',
      ...enhancedResults,
      metadata: {
        scanned_at: new Date().toISOString(),
        configuration: {
          customConfig: Object.keys(riskConfig).length > 0,
          contextProvided: Object.keys(context).length > 0,
          includeDevDependencies,
          lockFileScanned: !!lockData
        }
      }
    });
    
  } catch (error) {
    console.error('Dependency scan error:', error);
    res.status(500).json({
      status: 'error',
      message: 'Dependency scan failed',
      error: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

/**
 * Combined scan endpoint - both code and dependencies
 */
app.post('/scan', createRateLimiter(20, 60000), async (req, res) => {
  console.log('=== COMBINED SCAN REQUEST RECEIVED ===');
  
  try {
    const { 
      path: projectPath,
      riskConfig = {},
      context = {}
    } = req.body;
    
    if (!projectPath) {
      return res.status(400).json({
        status: 'error',
        message: 'No project path provided'
      });
    }
    
    // Check if path exists
    try {
      await fs.access(projectPath);
    } catch (error) {
      return res.status(400).json({
        status: 'error',
        message: `Project path does not exist: ${projectPath}`
      });
    }
    
    // Run both scans in parallel
    const [codeResult, depResult] = await Promise.allSettled([
      // Code scan
      (async () => {
        try {
          const languages = await detectLanguages(projectPath);
          const allFindings = [];
          
          if (semgrepAvailable) {
            const semgrepOptions = {
              languages: languages,
              severity: config.semgrepConfig?.severity || 'ERROR,WARNING',
              timeout: config.semgrepConfig?.timeout || 30,
              rulesets: config.semgrepConfig?.rulesets || []
            };
            const semgrepFindings = await runSemgrep(projectPath, semgrepOptions);
            allFindings.push(...semgrepFindings);
          }
          
          const normalized = normalizeFindings(allFindings);
          const enriched = enrichFindings(normalized);
          const deduplicated = deduplicateFindings(enriched);
          
          const calc = new EnhancedRiskCalculator(sanitizeRiskConfig(riskConfig));
          const scoredFindings = deduplicated.map(finding => {
            const cweId = extractCweId(finding.cwe);
            const vuln = {
              severity: normalizeSeverity(finding.severity),
              cwe: cweId,
              cweId: cweId,
              file: finding.file,
              line: finding.startLine
            };
            const riskResult = calc.calculateVulnerabilityRisk(vuln, sanitizeContextFactors(context));
            return {
              ...finding,
              cwe: cweId,
              cvssBase: riskResult.original.cvss,
              adjustedScore: riskResult.adjusted.score,
              adjustedSeverity: riskResult.adjusted.severity,
              priority: riskResult.adjusted.priority.priority,
              environmentalFactors: riskResult.factors.applied.map(f => f.id),
              remediation: riskResult.remediation
            };
          });
          
          scoredFindings.sort((a, b) => b.adjustedScore - a.adjustedScore);
          
          const normalizedForRisk = scoredFindings.map(f => ({
            ...f,
            cwe: extractCweId(f.cwe),
            cweId: extractCweId(f.cwe)
          }));
          
          const { score, risk } = calc.calculateFileRisk(normalizedForRisk, sanitizeContextFactors(context));
          
          return {
            status: 'success',
            findings: scoredFindings,
            score,
            risk
          };
        } catch (error) {
          return { status: 'error', message: error.message };
        }
      })(),
      
      // Dependency scan
      (async () => {
        try {
          const pkgPath = path.join(projectPath, 'package.json');
          const pkgContent = await fs.readFile(pkgPath, 'utf8');
          const pkgJson = JSON.parse(pkgContent);
          
          const scanResults = await depScanner.scanDependencies(pkgJson, {
            includeDevDependencies: false
          });
          
          const calc = new EnhancedRiskCalculator(sanitizeRiskConfig(riskConfig));
          const scoredVulnerabilities = scanResults.vulnerabilities.map(vuln => {
            const cweId = extractCweId(vuln.vulnerability?.cweId || vuln.cwe);
            const v = {
              severity: normalizeSeverity(vuln.vulnerability?.severity),
              cwe: cweId,
              cweId: cweId,
              cvss: vuln.vulnerability?.cvss
            };
            const riskResult = calc.calculateVulnerabilityRisk(v, sanitizeContextFactors(context));
            return {
              ...vuln,
              cwe: cweId,
              cvssBase: vuln.vulnerability?.cvss?.baseScore || riskResult.original.cvss,
              adjustedScore: riskResult.adjusted.score,
              adjustedSeverity: riskResult.adjusted.severity,
              priority: riskResult.adjusted.priority.priority,
              remediation: riskResult.remediation
            };
          });
          
          scoredVulnerabilities.sort((a, b) => b.adjustedScore - a.adjustedScore);
          
          return {
            status: 'success',
            vulnerabilities: scoredVulnerabilities,
            ...scanResults
          };
        } catch (error) {
          return { status: 'error', message: error.message };
        }
      })()
    ]);
    
    // Process results
    const results = {
      code: codeResult.status === 'fulfilled' ? codeResult.value : { status: 'error', findings: [], message: codeResult.reason?.message },
      dependencies: depResult.status === 'fulfilled' ? depResult.value : { status: 'error', vulnerabilities: [], message: depResult.reason?.message }
    };
    
    // Combine findings for overall risk calculation
    const allFindings = [
      ...(results.code.findings || []),
      ...(results.dependencies.vulnerabilities || [])
    ];
    
    // Calculate combined risk index
    const combinedRiskIndex = calculateRiskIndex(allFindings);
    
    res.json({
      status: 'success',
      results,
      summary: {
        totalIssues: allFindings.length,
        codeIssues: results.code.findings?.length || 0,
        dependencyIssues: results.dependencies.vulnerabilities?.length || 0,
        combinedRiskIndex,
        codeRiskScore: results.code.score?.final || 0,
        dependencyRiskScore: results.dependencies.score?.final || 0,
        overallRiskLevel: combinedRiskIndex >= 80 ? 'Critical' :
                          combinedRiskIndex >= 60 ? 'High' :
                          combinedRiskIndex >= 40 ? 'Medium' :
                          combinedRiskIndex >= 20 ? 'Low' : 'Minimal'
      },
      metadata: {
        scanned_at: new Date().toISOString(),
        projectPath,
        semgrepAvailable,
        configuration: {
          customConfig: Object.keys(riskConfig).length > 0,
          contextProvided: Object.keys(context).length > 0
        }
      }
    });
    
  } catch (error) {
    console.error('Combined scan error:', error);
    res.status(500).json({
      status: 'error',
      message: 'Combined scan failed',
      error: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

/**
 * File upload scanning endpoint
 */
app.post('/scan-file', createRateLimiter(50, 60000), async (req, res) => {
  console.log('=== FILE SCAN REQUEST RECEIVED ===');
  
  try {
    const {
      content,
      filename = 'uploaded-file',
      language = 'javascript',
      riskConfig = {},
      context = {}
    } = req.body;
    
    if (!content) {
      return res.status(400).json({
        status: 'error',
        message: 'No file content provided'
      });
    }
    
    // Scan the file with AST scanner
    const findings = astScanner.scan(content, filename, language);
    
    // Normalize findings to ensure CWE is a string
    const normalizedFindings = findings.map(f => ({
      ...f,
      cwe: extractCweId(f.cwe || f.cweId),
      cweId: extractCweId(f.cweId || f.cwe)
    }));
    
    // Sanitize configurations
    const sanitizedConfig = sanitizeRiskConfig(riskConfig);
    const sanitizedContext = sanitizeContextFactors(context);
    
    // Calculate risk
    const calc = new EnhancedRiskCalculator(sanitizedConfig);
    const { score, risk } = calc.calculateFileRisk(normalizedFindings, sanitizedContext);
    
    res.json({
      status: 'success',
      filename,
      language,
      findings: normalizedFindings,
      score,
      risk,
      vulnerabilities: {
        total: normalizedFindings.length,
        critical: normalizedFindings.filter(f => normalizeSeverity(f.severity) === 'critical').length,
        high: normalizedFindings.filter(f => normalizeSeverity(f.severity) === 'high').length,
        medium: normalizedFindings.filter(f => normalizeSeverity(f.severity) === 'medium').length,
        low: normalizedFindings.filter(f => normalizeSeverity(f.severity) === 'low').length
      },
      metadata: {
        scanned_at: new Date().toISOString(),
        file_size: content.length,
        engine: 'ast',
        configuration: {
          customConfig: Object.keys(riskConfig).length > 0,
          contextProvided: Object.keys(context).length > 0
        }
      }
    });
    
  } catch (error) {
    console.error('File scan error:', error);
    res.status(500).json({
      status: 'error',
      message: 'File scan failed',
      error: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

/**
 * Batch scanning endpoint
 */
app.post('/scan-batch', createRateLimiter(20, 60000), async (req, res) => {
  console.log('=== BATCH SCAN REQUEST RECEIVED ===');
  
  try {
    const {
      files = [],
      riskConfig = {},
      context = {}
    } = req.body;
    
    if (!Array.isArray(files) || files.length === 0) {
      return res.status(400).json({
        status: 'error',
        message: 'No files provided for batch scanning'
      });
    }
    
    const sanitizedConfig = sanitizeRiskConfig(riskConfig);
    const sanitizedContext = sanitizeContextFactors(context);
    const calc = new EnhancedRiskCalculator(sanitizedConfig);
    
    const results = [];
    let totalFindings = [];
    
    // Scan each file
    for (const file of files.slice(0, 100)) {
      try {
        const { content, filename = 'unknown', language = 'javascript' } = file;
        
        if (!content) continue;
        
        const findings = astScanner.scan(content, filename, language);
        
        // Normalize findings
        const normalizedFindings = findings.map(f => ({
          ...f,
          cwe: extractCweId(f.cwe || f.cweId),
          cweId: extractCweId(f.cweId || f.cwe)
        }));
        
        totalFindings = totalFindings.concat(normalizedFindings);
        
        results.push({
          filename,
          language,
          findings: normalizedFindings.length,
          vulnerabilities: normalizedFindings
        });
      } catch (fileError) {
        console.error(`Error scanning file ${file.filename}:`, fileError);
        results.push({
          filename: file.filename || 'unknown',
          error: fileError.message
        });
      }
    }
    
    // Calculate overall risk
    const { score, risk } = calc.calculateFileRisk(totalFindings, sanitizedContext);
    
    res.json({
      status: 'success',
      filesScanned: files.length,
      results,
      overallScore: score,
      overallRisk: risk,
      summary: {
        totalFindings: totalFindings.length,
        critical: totalFindings.filter(f => normalizeSeverity(f.severity) === 'critical').length,
        high: totalFindings.filter(f => normalizeSeverity(f.severity) === 'high').length,
        medium: totalFindings.filter(f => normalizeSeverity(f.severity) === 'medium').length,
        low: totalFindings.filter(f => normalizeSeverity(f.severity) === 'low').length,
        adjustedRiskIndex: calculateRiskIndex(totalFindings)
      },
      metadata: {
        scanned_at: new Date().toISOString(),
        engine: 'ast',
        configuration: {
          customConfig: Object.keys(riskConfig).length > 0,
          contextProvided: Object.keys(context).length > 0
        }
      }
    });
    
  } catch (error) {
    console.error('Batch scan error:', error);
    res.status(500).json({
      status: 'error',
      message: 'Batch scan failed',
      error: error.message,
      timestamp: new Date().toISOString()
    });
  }
});
/**
 * Profile management endpoints
 */

// List all available profiles
app.get('/profiles', async (req, res) => {
  try {
    const profiles = await profileManager.listProfiles();
    res.json({
      status: 'success',
      profiles,
      currentProfile: profileManager.currentProfile?.name || 'default'
    });
  } catch (error) {
    res.status(500).json({
      status: 'error',
      message: 'Failed to list profiles',
      error: error.message
    });
  }
});

// Get specific profile
app.get('/profiles/:profileId', async (req, res) => {
  try {
    const profile = await profileManager.loadProfile(req.params.profileId);
    res.json({
      status: 'success',
      profile
    });
  } catch (error) {
    res.status(404).json({
      status: 'error',
      message: `Profile ${req.params.profileId} not found`,
      error: error.message
    });
  }
});

// Create or update profile
app.post('/profiles/:profileId', async (req, res) => {
  try {
    const { profile } = req.body;
    if (!profile) {
      return res.status(400).json({
        status: 'error',
        message: 'Profile configuration required'
      });
    }
    
    const result = await profileManager.saveProfile(req.params.profileId, profile);
    res.json({
      status: 'success',
      ...result
    });
  } catch (error) {
    res.status(400).json({
      status: 'error',
      message: 'Failed to save profile',
      error: error.message
    });
  }
});

// Simulate profile changes
app.post('/profiles/:profileId/simulate', async (req, res) => {
  try {
    const { newProfile, sampleFindings } = req.body;
    
    if (!newProfile || !sampleFindings) {
      return res.status(400).json({
        status: 'error',
        message: 'newProfile and sampleFindings required'
      });
    }
    
    const simulation = await profileManager.simulateProfile(newProfile, sampleFindings);
    
    res.json({
      status: 'success',
      simulation
    });
  } catch (error) {
    res.status(400).json({
      status: 'error', 
      message: 'Simulation failed',
      error: error.message
    });
  }
});

// Validate profile
app.post('/profiles/validate', (req, res) => {
  try {
    const { profile } = req.body;
    if (!profile) {
      return res.status(400).json({
        status: 'error',
        message: 'Profile required for validation'
      });
    }
    
    const validation = profileManager.validateProfile(profile);
    
    res.json({
      status: validation.valid ? 'success' : 'error',
      validation
    });
  } catch (error) {
    res.status(400).json({
      status: 'error',
      message: 'Validation failed',
      error: error.message
    });
  }
});
// Keep all the other endpoints (health, config, capabilities, etc.) the same...
// [Rest of the code remains unchanged from line 1000 onwards]

/**
 * Health check endpoints
 */
app.get('/health', async (req, res) => {
  const semgrepStatus = semgrepAvailable ? 'available' : 'not installed';
  
  res.json({ 
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    services: {
      ast: 'ready',
      semgrep: semgrepStatus,
      semgrepVersion: semgrepVersion,
      dependency: 'ready',
      riskCalculator: 'ready',
      taxonomy: 'ready'
    },
    features: {
      customRiskConfig: true,
      contextualAnalysis: true,
      enhancedRiskCalculator: true,
      batchScanning: true,
      dependencyScanning: true,
      astScanning: true,
      semgrepScanning: semgrepAvailable,
      helmetSecurity: true,
      rateLimiting: true
    }
  });
});

app.get('/healthz', (req, res) => {
  res.status(200).send('OK');
});

/**
 * Get current default configuration
 */
app.get('/config/defaults', (req, res) => {
  res.json({
    status: 'success',
    defaults: {
      severityPoints: config.scoring?.baseScoreMapping || {
        critical: 25,
        high: 15,
        medium: 8,
        low: 3,
        info: 1
      },
      riskThresholds: {
        critical: 80,
        high: 60,
        medium: 40,
        low: 20,
        minimal: 0
      },
      environmentalFactors: {
        internetFacing: { additive: 0.6, description: 'Component exposed to internet' },
        production: { additive: 0.4, description: 'Running in production' },
        handlesPI: { additive: 0.4, description: 'Processes personal information' },
        legacyCode: { additive: 0.2, description: 'Legacy system with technical debt' }
      },
      semgrep: {
        available: semgrepAvailable,
        version: semgrepVersion,
        rulesets: config.semgrepConfig?.rulesets || ['auto']
      }
    }
  });
});

/**
 * Get scanner capabilities
 */
app.get('/capabilities', async (req, res) => {
  const languages = ['javascript', 'typescript'];
  
  if (semgrepAvailable) {
    languages.push('python', 'java', 'go', 'ruby', 'php', 'csharp');
  }
  
  res.json({
    status: 'success',
    capabilities: {
      languages,
      engines: {
        ast: {
          available: true,
          languages: ['javascript', 'typescript'],
          features: ['pattern-matching', 'cwe-mapping', 'owasp-classification']
        },
        semgrep: {
          available: semgrepAvailable,
          version: semgrepVersion,
          languages: semgrepAvailable ? ['javascript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'] : [],
          rulesets: config.semgrepConfig?.rulesets || ['auto'],
          features: ['production-rules', 'cross-file-analysis', 'taint-analysis']
        }
      },
      scoring: {
        cvss: true,
        environmental: true,
        contextual: true,
        customizable: true
      },
      reporting: {
        formats: ['json', 'html', 'pdf'],
        realtime: true,
        batch: true
      }
    }
  });
});

/**
 * Root endpoint with API information
 */
app.get('/', (req, res) => {
  res.json({
    name: 'Neperia Security Scanner - Production Edition',
    version: '5.0',
    status: 'operational',
    endpoints: {
      'POST /scan-code': 'Scan code with AST or Semgrep with context inference',
      'POST /scan-dependencies': 'Scan dependencies for vulnerabilities',
      'POST /scan': 'Combined code and dependency scanning',
      'POST /scan-file': 'Scan uploaded file content',
      'POST /scan-batch': 'Batch scan multiple files',
      'GET /profiles': 'List all available risk profiles',
      'GET /profiles/:profileId': 'Get specific profile configuration',
      'POST /profiles/:profileId': 'Create or update risk profile',
      'POST /profiles/:profileId/simulate': 'Simulate profile changes',
      'POST /profiles/validate': 'Validate profile configuration',
      'GET /config/defaults': 'Get default configuration values',
      'GET /capabilities': 'Get scanner capabilities',
      'GET /health': 'Detailed health check',
      'GET /healthz': 'Simple health check'
    },
    features: [
      'Production Semgrep integration (2000+ rules)',
      'AST-based vulnerability detection',
      'Dependency vulnerability scanning',
      'Context-aware risk scoring with automatic inference',
      'Risk profile management and simulation',
      'User-configurable risk scoring',
      'Contextual risk analysis',
      'Environmental factor adjustments',
      'Batch file scanning',
      'OWASP/CWE/CVSS classification',
      'Helmet security headers',
      'Rate limiting protection'
    ],
    engines: {
      ast: 'Built-in AST scanner for JavaScript/TypeScript',
      semgrep: semgrepAvailable ? `Semgrep ${semgrepVersion} (production rules)` : 'Not installed (run: pip install semgrep)'
    },
    supported_languages: semgrepAvailable ? 
      ['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php', 'csharp'] :
      ['javascript', 'typescript'],
    api_version: '5.0.0'
  });
});

/**
 * 404 handler
 */
/**
 * 404 handler
 */
app.use('*', (req, res) => {
  res.status(404).json({ 
    status: 'error', 
    message: 'Route not found',
    path: req.originalUrl,
    method: req.method,
    available_routes: [
      'GET /',
      'GET /health',
      'GET /healthz',
      'GET /config/defaults',
      'GET /capabilities',
      'GET /profiles',
      'GET /profiles/:profileId',
      'POST /profiles/:profileId',
      'POST /profiles/:profileId/simulate',
      'POST /profiles/validate',
      'POST /scan-code',
      'POST /scan-dependencies',
      'POST /scan',
      'POST /scan-file',
      'POST /scan-batch',
    ],
    timestamp: new Date().toISOString()
  });
});
/**
 * Error handling middleware
 */
app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  
  if (res.headersSent) {
    return next(error);
  }
  
  res.status(500).json({ 
    status: 'error', 
    message: 'Internal server error',
    error: process.env.NODE_ENV === 'development' ? error.message : undefined,
    timestamp: new Date().toISOString()
  });
});

/**
 * Initialize and start server
 */
async function initialize() {
  semgrepAvailable = await checkSemgrepAvailable();
  if (semgrepAvailable) {
    semgrepVersion = await getSemgrepVersion();
    console.log(`✓ Semgrep ${semgrepVersion} is available`);
  } else {
    console.log('⚠ Semgrep not found - AST scanner only mode');
    console.log('  To enable Semgrep: pip install semgrep');
  }
}

// Start server
const server = app.listen(PORT, '0.0.0.0', async () => {
  await initialize();
  
  console.log(`
╔══════════════════════════════════════════════════════════════╗
║     NEPERIA SECURITY SCANNER - PRODUCTION EDITION v5.0      ║
╠══════════════════════════════════════════════════════════════╣
║  Server running on port ${PORT}                                 ║
║  Status: OPERATIONAL                                         ║
║                                                              ║
║  ENGINES:                                                    ║
║  ✓ AST Scanner (JavaScript/TypeScript)                       ║
║  ${semgrepAvailable ? '✓' : '✗'} Semgrep ${semgrepAvailable ? `(${semgrepVersion})` : '(not installed)'}                              ║
║                                                              ║
║  FEATURES:                                                   ║
║  ✓ User-configurable risk scoring                           ║
║  ✓ Contextual risk analysis                                 ║
║  ✓ Environmental factor adjustments                         ║
║  ✓ Dependency vulnerability scanning                        ║
║  ✓ Batch file scanning                                      ║
║  ✓ OWASP/CWE/CVSS classification                           ║
║  ✓ Helmet security headers                                  ║
║  ✓ Rate limiting protection                                 ║
║                                                              ║
║  ENDPOINTS:                                                  ║
║  • POST /scan-code         - Code analysis                   ║
║  • POST /scan-dependencies - Dependency analysis             ║
║  • POST /scan              - Combined analysis               ║
║  • POST /scan-file         - File analysis                   ║
║  • POST /scan-batch        - Batch analysis                  ║
║  • GET /capabilities       - Scanner capabilities            ║
║                                                              ║
║  ${semgrepAvailable ? 'Production mode: Using Semgrep registry rules' : 'Limited mode: Install Semgrep for full capabilities'}         ║
╚══════════════════════════════════════════════════════════════╝
  `);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, closing server...');
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  console.log('SIGINT received, closing server...');
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
});

module.exports = app;