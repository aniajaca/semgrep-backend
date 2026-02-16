// ==============================================================================
// src/contextInference/profiles/profileManager.js - REFACTORED
// ==============================================================================

const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');
const EnhancedRiskCalculator = require('../../enhancedRiskCalculator');

// Define paths
const PROFILES_DIR = path.join(__dirname, '../../../profiles');
const DEFAULT_PROFILE_PATH = path.join(PROFILES_DIR, 'default.json');

class ProfileManager {
  constructor(config = {}) {
    this.profilesDir = PROFILES_DIR;
    this.profilesPath = config.profilesPath || PROFILES_DIR;
    this.profiles = new Map();
    this.currentProfile = null;
    
    // Ensure profiles directory exists synchronously in constructor
    const fsSync = require('fs');
    if (!fsSync.existsSync(this.profilesDir)) {
      fsSync.mkdirSync(this.profilesDir, { recursive: true });
    }
    
    // Create default profile if it doesn't exist
    if (!fsSync.existsSync(DEFAULT_PROFILE_PATH)) {
      const defaultProfile = this.getDefaultProfile();
      fsSync.writeFileSync(DEFAULT_PROFILE_PATH, JSON.stringify(defaultProfile, null, 2));
    }
  }

      /**
       * Load a profile by ID
       */
      async loadProfile(profileId) {
        try {
          const profilePath = path.join(this.profilesPath, `${profileId}.json`);
          const content = await fs.readFile(profilePath, 'utf8');
          const profile = JSON.parse(content);
          
          // Validate profile
          const validation = this.validateProfile(profile);
          if (!validation.valid) {
            throw new Error(`Invalid profile: ${validation.errors.join(', ')}`);
          }
          
          this.profiles.set(profileId, profile);
          this.currentProfile = profile;
          
          return profile;
        } catch (error) {
          console.error(`Failed to load profile ${profileId}:`, error.message);
          return this.getDefaultProfile();
        }
      }
    
      /**
       * Validate profile configuration
       */
      validateProfile(profile) {
        const errors = [];
        const warnings = [];

        // ✅ Check null/undefined FIRST
        if (!profile) {
          errors.push('Profile is required');
          return { valid: false, errors, warnings };  // ← MUST RETURN HERE
        }
        
        
        // Check version (now safe - profile exists)
        if (!profile.version) {
          errors.push('Profile version is required');
        }

        
        // Validate weights (they should be 0-1 for additive factors)
        if (profile.contextFactors?.weights) {
          for (const [factor, weight] of Object.entries(profile.contextFactors.weights)) {
            if (weight < 0 || weight > 1) {
              errors.push(`Weight for ${factor} must be between 0 and 1`);
            }
          }
        }
        
        // Validate exploit caps
        if (profile.contextFactors?.exploitCaps) {
          const { kev, publicExploit, epss } = profile.contextFactors.exploitCaps;
          if (kev && (kev < 0 || kev > 0.5)) {
            errors.push('KEV cap must be between 0 and 0.5');
          }
          if (publicExploit && (publicExploit < 0 || publicExploit > 0.5)) {
            errors.push('publicExploit cap must be between 0 and 0.5');
          }
          if (epss && (epss < 0 || epss > 0.5)) {
            errors.push('EPSS cap must be between 0 and 0.5');
          }
        }
        
        // Validate total lift cap
        const totalLiftCap = profile.contextFactors?.totalLiftCap;
        if (totalLiftCap !== undefined) {
          if (totalLiftCap < 0 || totalLiftCap > 1.0) {
            errors.push('totalLiftCap must be between 0 and 1.0');
          }
          if (totalLiftCap > 0.70) {
            warnings.push('totalLiftCap > 0.70 may cause excessive score inflation');
          }
        }
        
        // Validate file risk caps
        if (profile.fileRisk?.caps) {
          const { density, diversity, exposure } = profile.fileRisk.caps;
          if (density && density > 30) warnings.push('Density cap > 30 may overweight');
          if (diversity && diversity > 20) warnings.push('Diversity cap > 20 may overweight');
          if (exposure && exposure > 25) warnings.push('Exposure cap > 25 may overweight');
        }

        // Add monotonicity validation
        const monotonicityCheck = this.validateMonotonicity(profile);
        errors.push(...monotonicityCheck.errors);
        warnings.push(...monotonicityCheck.warnings);

        return {
          valid: errors.length === 0,
          errors,
          warnings
        };
      }
    
      /**
       * Translate profile format to calculator config format
       */
      translateProfileToCalculatorConfig(profile) {
        // Map profile's context factors to calculator's expected format
        const config = {
          // File-level scoring configuration
          fileLevel: {
            severityPoints: {
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
            }
          },
          
          // Vulnerability-level configuration
          vulnerabilityLevel: {
            severityThresholds: {
              critical: 9.0,
              high: 7.0,
              medium: 4.0,
              low: 0.1,
              info: 0
            },
            allowMultipliers: false  // We use additive for vulnerability factors
          }
        };
        
        // If profile has custom severity points, use them
        if (profile.scoring?.severityPoints) {
          config.fileLevel.severityPoints = profile.scoring.severityPoints;
        }
        
        // If profile has custom thresholds, use them
        if (profile.scoring?.riskThresholds) {
          config.fileLevel.riskThresholds = profile.scoring.riskThresholds;
        }
        
        // If profile has context multipliers, pass them to the factor system
        // These override the default file-level multipliers in customEnvironmentalFactors.js
        if (profile.contextMultipliers) {
          config.contextMultipliers = profile.contextMultipliers;
        }
        
        return config;
      }
    
      /**
       * Save profile with versioning
       */
      async saveProfile(profileId, profile) {
        // Validate first
        const validation = this.validateProfile(profile);
        if (!validation.valid) {
          throw new Error(`Cannot save invalid profile: ${validation.errors.join(', ')}`);
        }
        
        // Update version (increment patch)
        const version = profile.version.split('.');
        version[2] = (parseInt(version[2]) + 1).toString();
        profile.version = version.join('.');
        
        // Calculate hash
        profile.profileHash = this.calculateProfileHash(profile);
        
        // Save to file
        const profilePath = path.join(this.profilesPath, `${profileId}.json`);
        await fs.writeFile(profilePath, JSON.stringify(profile, null, 2));
        
        this.profiles.set(profileId, profile);
        
        return {
          profileId,
          version: profile.version,
          profileHash: profile.profileHash
        };
      }
    
      /**
 * Validate monotonicity of profile changes
 * Ensures that increasing a factor weight always increases or maintains the risk score
 */
validateMonotonicity(profile, testFindings = null) {
  const errors = [];
  const warnings = [];
  
  // Check priority thresholds are monotonic (descending)
  if (profile.slaMapping) {
    const priorities = ['P0', 'P1', 'P2', 'P3'];
    let prevThreshold = 100;
    
    for (const priority of priorities) {
      const threshold = profile.slaMapping[priority]?.threshold;
      if (threshold !== undefined) {
        if (threshold > prevThreshold) {
          errors.push(`Priority thresholds must be monotonic: ${priority} (${threshold}) > previous (${prevThreshold})`);
        }
        prevThreshold = threshold;
      }
    }
  }
  
  // Check that exploit factors maintain precedence
  const exploitWeights = {
    kevListed: profile.contextFactors?.weights?.kevListed,
    publicExploit: profile.contextFactors?.weights?.publicExploit,
    epss: profile.contextFactors?.weights?.epss
  };
  
  // KEV should have highest weight (precedence rule)
  if (exploitWeights.kevListed && exploitWeights.publicExploit) {
    if (exploitWeights.kevListed < exploitWeights.publicExploit) {
      warnings.push('KEV should have higher weight than publicExploit due to precedence');
    }
  }
  
  // Test with sample findings if provided
  if (testFindings && testFindings.length > 0) {
    const baseProfile = this.getDefaultProfile();
    
    // Test each factor individually
    const factors = Object.keys(profile.contextFactors?.weights || {});
    
    for (const factor of factors) {
      const testProfile1 = JSON.parse(JSON.stringify(profile));
      const testProfile2 = JSON.parse(JSON.stringify(profile));
      
      // Set lower weight
      testProfile1.contextFactors.weights[factor] = 0.1;
      // Set higher weight  
      testProfile2.contextFactors.weights[factor] = 0.3;
      
      // Calculate scores
      const calc1 = new EnhancedRiskCalculator(this.translateProfileToCalculatorConfig(testProfile1));
      const calc2 = new EnhancedRiskCalculator(this.translateProfileToCalculatorConfig(testProfile2));
      
      for (const finding of testFindings) {
        const context = { [factor]: true };
        
        const result1 = calc1.calculateVulnerabilityRisk(finding, context);
        const result2 = calc2.calculateVulnerabilityRisk(finding, context);
        
        // Higher weight should produce higher or equal score
        if (result2.adjusted.score < result1.adjusted.score) {
          errors.push(`Monotonicity violation: Increasing ${factor} weight decreased score`);
          break;
        }
      }
    }
  }
  
  // Check weight ranges
  if (profile.contextFactors?.weights) {
    for (const [factor, weight] of Object.entries(profile.contextFactors.weights)) {
      if (weight < 0) {
        errors.push(`Negative weight for ${factor}: weights must be non-negative for monotonicity`);
      }
      if (weight > 1) {
        warnings.push(`Weight for ${factor} > 1.0 may cause excessive amplification`);
      }
    }
  }
  
  // Check that caps are reasonable
  const totalLiftCap = profile.contextFactors?.totalLiftCap;
  if (totalLiftCap !== undefined) {
    if (totalLiftCap < 0) {
      errors.push('totalLiftCap must be non-negative');
    }
    if (totalLiftCap > 1.0) {
      warnings.push('totalLiftCap > 1.0 allows score doubling');
    }
    
    // Check if individual weights sum could exceed cap
    const maxPossibleLift = Object.values(profile.contextFactors?.weights || {})
      .reduce((sum, w) => sum + (typeof w === 'number' ? w : 0), 0);
    
    if (maxPossibleLift > totalLiftCap + 0.1) { // Allow small tolerance
      warnings.push(`Sum of all weights (${maxPossibleLift.toFixed(2)}) exceeds totalLiftCap (${totalLiftCap})`);
    }
  }
  
  return {
    monotonic: errors.length === 0,
    errors,
    warnings
  };
}
      
      /**
       * Simulate profile changes using REAL calculator
       */
      async simulateProfile(newProfile, sampleFindings) {
        const currentScores = [];
        const newScores = [];
        
        // Get profiles
        const currentProfile = this.currentProfile || this.getDefaultProfile();
        
        // Create REAL calculators with translated configs
        const currentConfig = this.translateProfileToCalculatorConfig(currentProfile);
        const newConfig = this.translateProfileToCalculatorConfig(newProfile);
        
        const currentCalc = new EnhancedRiskCalculator(currentConfig);
        const newCalc = new EnhancedRiskCalculator(newConfig);
        
        // Process each finding through the real calculator
        for (const finding of sampleFindings) {
          // Prepare finding for calculator (ensure proper structure)
          const vulnData = {
            severity: finding.severity || 'medium',
            cwe: finding.cwe || finding.cweId || 'CWE-1',
            cweId: finding.cwe || finding.cweId || 'CWE-1',
            cvss: finding.cvss || null,
            file: finding.file || 'unknown',
            line: finding.line || 0
          };
          
          // Prepare context with factors from both finding and profiles
          const currentContext = this.prepareContext(finding.context, currentProfile);
          const newContext = this.prepareContext(finding.context, newProfile);
          
          // Calculate using real calculator's vulnerability risk method
          const currentResult = currentCalc.calculateVulnerabilityRisk(vulnData, currentContext);
          const newResult = newCalc.calculateVulnerabilityRisk(vulnData, newContext);
          
          // Extract CRS (adjusted score * 10 to get 0-100 range)
          const currentCRS = Math.min(100, currentResult.adjusted.score * 10);
          const newCRS = Math.min(100, newResult.adjusted.score * 10);
          
          currentScores.push(currentCRS);
          newScores.push(newCRS);
        }
        
        // Calculate summary statistics
        const avgCurrentScore = currentScores.length > 0 
          ? currentScores.reduce((a, b) => a + b, 0) / currentScores.length 
          : 0;
        const avgNewScore = newScores.length > 0
          ? newScores.reduce((a, b) => a + b, 0) / newScores.length
          : 0;
        
        const bandMovements = this.calculateBandMovements(currentScores, newScores);
        
        return {
          current: {
            avgScore: Math.round(avgCurrentScore),
            distribution: this.getScoreDistribution(currentScores)
          },
          simulated: {
            avgScore: Math.round(avgNewScore),
            distribution: this.getScoreDistribution(newScores)
          },
          delta: {
            avgScoreChange: Math.round(avgNewScore - avgCurrentScore),
            percentChange: avgCurrentScore > 0 
              ? Math.round(((avgNewScore - avgCurrentScore) / avgCurrentScore) * 100)
              : 0,
            bandMovements,
            summary: this.generateMovementSummary(bandMovements)
          }
        };
      }
    
      /**
       * Prepare context for calculator from finding + profile
       */
      prepareContext(findingContext = {}, profile) {
        const context = { ...findingContext };
        
        // Apply profile's enabled factors
        if (profile.contextFactors?.enabled) {
          Object.entries(profile.contextFactors.enabled).forEach(([factor, enabled]) => {
            if (enabled && context[factor] === undefined) {
              // Don't override existing context, but enable if not specified
              context[factor] = false;
            }
          });
        }
        
        // Apply weights as custom factors for the calculator
        if (profile.contextFactors?.weights) {
          context.customFactors = {};
          Object.entries(profile.contextFactors.weights).forEach(([factor, weight]) => {
            context.customFactors[factor] = {
              enabled: context[factor] === true,
              weight: weight
            };
          });
        }
        
        return context;
      }
    
      /**
       * Calculate priority band movements
       */
      calculateBandMovements(currentScores, newScores) {
        const movements = {
          'P0→P0': 0, 'P0→P1': 0, 'P0→P2': 0, 'P0→P3': 0,
          'P1→P0': 0, 'P1→P1': 0, 'P1→P2': 0, 'P1→P3': 0,
          'P2→P0': 0, 'P2→P1': 0, 'P2→P2': 0, 'P2→P3': 0,
          'P3→P0': 0, 'P3→P1': 0, 'P3→P2': 0, 'P3→P3': 0
        };
        
        for (let i = 0; i < currentScores.length; i++) {
          const currentBand = this.scoreToPriority(currentScores[i]);
          const newBand = this.scoreToPriority(newScores[i] || 0);
          
          const movement = `${currentBand}→${newBand}`;
          if (movements[movement] !== undefined) {
            movements[movement]++;
          }
        }
        
        return movements;
      }
    
      /**
       * Generate human-readable movement summary
       */
      generateMovementSummary(movements) {
        const improved = movements['P1→P0'] + movements['P2→P1'] + 
                        movements['P2→P0'] + movements['P3→P2'] + 
                        movements['P3→P1'] + movements['P3→P0'];
        
        const worsened = movements['P0→P1'] + movements['P0→P2'] + 
                        movements['P0→P3'] + movements['P1→P2'] + 
                        movements['P1→P3'] + movements['P2→P3'];
        
        if (improved > worsened) {
          return `Net improvement: ${improved} findings moved to higher priority`;
        } else if (worsened > improved) {
          return `Net degradation: ${worsened} findings moved to lower priority`;
        } else {
          return 'No significant priority changes';
        }
      }
    
      /**
       * Map score to priority band (using profile's SLA mapping if available)
       */
      scoreToPriority(score, profile = null) {
        const slaMapping = profile?.slaMapping || this.currentProfile?.slaMapping || {
          P0: { threshold: 80 },
          P1: { threshold: 65 },
          P2: { threshold: 50 },
          P3: { threshold: 0 }
        };
        
        if (score >= slaMapping.P0.threshold) return 'P0';
        if (score >= slaMapping.P1.threshold) return 'P1';
        if (score >= slaMapping.P2.threshold) return 'P2';
        return 'P3';
      }
    
      /**
       * Get score distribution
       */
      getScoreDistribution(scores) {
        const profile = this.currentProfile || this.getDefaultProfile();
        const slaMapping = profile.slaMapping;
        
        return {
          P0: scores.filter(s => s >= slaMapping.P0.threshold).length,
          P1: scores.filter(s => s >= slaMapping.P1.threshold && s < slaMapping.P0.threshold).length,
          P2: scores.filter(s => s >= slaMapping.P2.threshold && s < slaMapping.P1.threshold).length,
          P3: scores.filter(s => s < slaMapping.P2.threshold).length
        };
      }
    
      /**
       * Calculate profile hash for provenance
       */
      calculateProfileHash(profile) {
        const relevantData = {
          version: profile.version,
          contextFactors: profile.contextFactors,
          fileRisk: profile.fileRisk,
          slaMapping: profile.slaMapping,
          scoring: profile.scoring
        };
        
        const hash = crypto
          .createHash('sha256')
          .update(JSON.stringify(relevantData))
          .digest('hex');
        
        return hash.substring(0, 12);
      }
    
      /**
       * Get current profile hash without modifying profile
       */
      getCurrentProfileHash() {
        const profile = this.currentProfile || this.getDefaultProfile();
        return this.calculateProfileHash(profile);
      }
    
      /**
       * List all available profiles
       */
      async listProfiles() {
        try {
          const files = await fs.readdir(this.profilesPath);
          const profiles = [];
          
          for (const file of files) {
            if (file.endsWith('.json')) {
              const profileId = file.replace('.json', '');
              const profile = await this.loadProfile(profileId);
              profiles.push({
                id: profileId,
                name: profile.name,
                version: profile.version,
                description: profile.description,
                profileHash: profile.profileHash || this.calculateProfileHash(profile)
              });
            }
          }
          
          return profiles;
        } catch (error) {
          console.error('Failed to list profiles:', error);
          return [];
        }
      }
    
      /**
       * Get default profile
       */
      getDefaultProfile() {
        return {
          version: "1.1.0",
          name: "default-v1",
          description: "Default balanced security profile",
          profileHash: null, // Will be calculated when needed
          
          contextFactors: {
            enabled: {
              kevListed: true,
              publicExploit: true,
              epss: true,
              internetFacing: true,
              production: true,
              handlesPI: true,
              userBaseLarge: true,
              regulated: true,
              noAuth: true
            },
            weights: {
              kevListed: 0.25,      // Exploit precedence: highest
              publicExploit: 0.15,  // Exploit precedence: medium
              epss: 0.25,           // Exploit precedence: statistical
              internetFacing: 0.20,
              production: 0.15,
              handlesPI: 0.15,
              userBaseLarge: 0.10,
              regulated: 0.15,
              noAuth: 0.10
            },
            exploitCaps: {
              kev: 0.25,
              publicExploit: 0.15,
              epss: 0.25
            },
            totalLiftCap: 0.70
          },
          
          fileRisk: {
            topK: 5,
            weights: {
              core: 0.6,
              density: 0.2,
              diversity: 0.1,
              exposure: 0.1
            },
            caps: {
              density: 30,
              diversity: 20,
              exposure: 25
            }
          },
          
          slaMapping: {
            P0: { threshold: 80, days: 7 },
            P1: { threshold: 65, days: 14 },
            P2: { threshold: 50, days: 30 },
            P3: { threshold: 0, days: 90 }
          },
          
          scoring: {
            severityPoints: {
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
            }
          },
          
          features: {
            contextInference: {
              js: { routes: true, auth: true, pii: true },
              py: { routes: true, auth: true, pii: true },
              java: { routes: true, auth: true, pii: true }
            }
          }
        };
      }
    }
    
    module.exports = ProfileManager;