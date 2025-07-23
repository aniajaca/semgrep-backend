// src/aiRouter.js - Enhanced AI router integrated with SecurityClassificationSystem
const express = require('express');
const OpenAI = require('openai');
const NodeCache = require('node-cache');
const { 
  buildPrompt, 
  buildRiskAssessmentPrompt, 
  buildRemediationPrompt,
  buildCompliancePrompt,
  generateContextMetadata 
} = require('./aiUtils');

const router = express.Router();

// Initialize OpenAI client
const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY
});

// Cache for AI responses (24 hour TTL)
const cache = new NodeCache({ stdTTL: 86400 });

// Rate limiting and error handling
const MAX_RETRIES = 3;
const RETRY_DELAY = 1000; // 1 second

console.log('🤖 AI Router initialized with enhanced classification integration');

/**
 * Generic AI completion function with retry logic
 * 🤖 AI PROCESSING: Core AI interaction with error handling
 */
async function getAICompletion(prompt, options = {}) {
  const {
    temperature = 0.7,
    maxTokens = 800,
    model = "gpt-4",
    retries = MAX_RETRIES
  } = options;

  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      console.log(`🤖 AI completion attempt ${attempt}/${retries} (${prompt.length} chars)`);
      
      const completion = await openai.chat.completions.create({
        model: model,
        messages: [{ role: "user", content: prompt }],
        temperature: temperature,
        max_tokens: maxTokens,
        presence_penalty: 0.1,
        frequency_penalty: 0.1
      });

      const response = completion.choices[0].message.content.trim();
      console.log(`🤖 AI completion successful (${response.length} chars generated)`);
      return response;

    } catch (error) {
      console.error(`🤖 AI completion attempt ${attempt} failed:`, error.message);
      
      if (attempt === retries) {
        throw new Error(`AI service failed after ${retries} attempts: ${error.message}`);
      }
      
      // Wait before retry (exponential backoff)
      await new Promise(resolve => setTimeout(resolve, RETRY_DELAY * attempt));
    }
  }
}

/**
 * POST /api/explain-finding
 * 🤖 AI ENDPOINT: Explain a single security finding for a specific audience
 * Uses enhanced classification data from SecurityClassificationSystem
 */
router.post('/explain-finding', async (req, res) => {
  try {
    console.log('🤖 AI: /explain-finding request received');
    
    const { 
      finding, 
      audience = 'developer', 
      context = {},
      useCache = true 
    } = req.body;

    // Validate input - expect enhanced finding from SecurityClassificationSystem
    if (!finding || (!finding.ruleId && !finding.check_id)) {
      return res.status(400).json({ 
        error: 'Missing or invalid finding payload',
        required: 'Enhanced finding object from SecurityClassificationSystem with ruleId',
        hint: 'Make sure finding has been processed through SecurityClassificationSystem.classifyFinding()'
      });
    }

    // Generate cache key using enhanced finding data
    const cacheKey = `explain:${finding.id || finding.ruleId}:${audience}:${JSON.stringify(context)}`;
    
    if (useCache) {
      const cached = cache.get(cacheKey);
      if (cached) {
        console.log('🤖 AI: Returning cached explanation');
        return res.json({ 
          explanation: cached, 
          cached: true,
          audience,
          findingId: finding.id,
          metadata: {
            cweClassification: finding.cwe,
            cvssScore: finding.cvss?.adjustedScore,
            severity: finding.severity,
            aiMetadata: finding.aiMetadata
          }
        });
      }
    }

    // Build AI prompt using enhanced finding data
    console.log(`🤖 AI: Building explanation for ${audience} audience - ${finding.cwe?.name}`);
    const prompt = buildPrompt(finding, audience, context);

    // Get AI explanation
    const explanation = await getAICompletion(prompt, {
      temperature: 0.7,
      maxTokens: 600,
      model: "gpt-4"
    });

    // Cache the result
    if (useCache) {
      cache.set(cacheKey, explanation);
      console.log('🤖 AI: Explanation cached for future use');
    }

    res.json({ 
      explanation,
      cached: false,
      audience,
      findingId: finding.id,
      metadata: {
        // 🔧 STATIC data from classification
        cweClassification: finding.cwe,
        owaspCategory: finding.owaspCategory,
        cvssScore: finding.cvss?.adjustedScore,
        severity: finding.severity,
        businessImpact: finding.impact,
        complianceViolations: finding.complianceMapping,
        // 🤖 AI processing metadata  
        aiEnhanced: true,
        promptLength: prompt.length,
        responseLength: explanation.length,
        model: "gpt-4"
      }
    });

  } catch (error) {
    console.error('🤖 AI explain error:', error);
    res.status(500).json({ 
      error: 'AI explanation failed',
      details: error.message,
      service: 'OpenAI GPT-4',
      timestamp: new Date().toISOString()
    });
  }
});

/**
 * POST /api/assess-risk
 * 🤖 AI ENDPOINT: Provide overall risk assessment for multiple findings
 * Integrates with aggregated risk data from SecurityClassificationSystem
 */
router.post('/assess-risk', async (req, res) => {
  try {
    console.log('🤖 AI: /assess-risk request received');
    
    const { 
      findings = [], 
      riskAssessment = {}, // From SecurityClassificationSystem.aggregateRiskScore()
      context = {},
      useCache = true 
    } = req.body;

    if (!Array.isArray(findings) || findings.length === 0) {
      return res.status(400).json({ 
        error: 'Missing or empty findings array',
        required: 'Array of enhanced security findings from SecurityClassificationSystem'
      });
    }

    // Use aggregated risk data if available
    const aggregatedRisk = riskAssessment.riskScore ? riskAssessment : null;
    
    // Generate cache key
    const findingIds = findings.map(f => f.id || f.ruleId).sort().join(',');
    const cacheKey = `risk-assessment:${findingIds}:${aggregatedRisk?.riskScore || 'calc'}:${JSON.stringify(context)}`;
    
    if (useCache) {
      const cached = cache.get(cacheKey);
      if (cached) {
        console.log('🤖 AI: Returning cached risk assessment');
        return res.json({ 
          assessment: cached, 
          cached: true,
          findingsCount: findings.length,
          aggregatedRisk
        });
      }
    }

    // Build enhanced risk assessment prompt
    console.log(`🤖 AI: Building risk assessment for ${findings.length} findings`);
    const prompt = buildRiskAssessmentPrompt(findings, context, aggregatedRisk);

    // Get AI assessment
    const assessment = await getAICompletion(prompt, {
      temperature: 0.6,
      maxTokens: 1200,
      model: "gpt-4"
    });

    // Cache the result
    if (useCache) {
      cache.set(cacheKey, assessment);
      console.log('🤖 AI: Risk assessment cached');
    }

    res.json({ 
      assessment,
      cached: false,
      findingsCount: findings.length,
      metadata: {
        // 🔧 STATIC aggregated data
        aggregatedRisk,
        findingsBreakdown: aggregatedRisk?.findingsBreakdown,
        overallSeverity: aggregatedRisk?.riskLevel,
        confidenceLevel: aggregatedRisk?.confidence,
        // 🤖 AI processing metadata
        aiEnhanced: true,
        model: "gpt-4",
        contextFactors: generateContextMetadata(context)
      }
    });

  } catch (error) {
    console.error('🤖 AI risk assessment error:', error);
    res.status(500).json({ 
      error: 'Risk assessment failed',
      details: error.message,
      service: 'OpenAI GPT-4',
      timestamp: new Date().toISOString()
    });
  }
});

/**
 * POST /api/plan-remediation
 * 🤖 AI ENDPOINT: Generate detailed remediation plan for a specific finding
 * Uses enhanced remediation complexity data from SecurityClassificationSystem
 */
router.post('/plan-remediation', async (req, res) => {
  try {
    console.log('🤖 AI: /plan-remediation request received');
    
    const { 
      finding, 
      projectContext = {},
      useCache = true 
    } = req.body;

    if (!finding || (!finding.ruleId && !finding.check_id)) {
      return res.status(400).json({ 
        error: 'Missing or invalid finding payload',
        required: 'Enhanced finding object from SecurityClassificationSystem'
      });
    }

    // Generate cache key using enhanced finding data
    const cacheKey = `remediation:${finding.id}:${JSON.stringify(projectContext)}`;
    
    if (useCache) {
      const cached = cache.get(cacheKey);
      if (cached) {
        console.log('🤖 AI: Returning cached remediation plan');
        return res.json({ 
          remediationPlan: cached, 
          cached: true,
          findingId: finding.id,
          complexity: finding.remediationComplexity
        });
      }
    }

    // Build enhanced remediation prompt using static remediation guidance
    console.log(`🤖 AI: Building remediation plan for ${finding.cwe?.name} (complexity: ${finding.remediationComplexity?.level})`);
    const prompt = buildRemediationPrompt(finding, projectContext);

    // Get AI remediation plan
    const remediationPlan = await getAICompletion(prompt, {
      temperature: 0.5,
      maxTokens: 1400,
      model: "gpt-4"
    });

    // Cache the result
    if (useCache) {
      cache.set(cacheKey, remediationPlan);
      console.log('🤖 AI: Remediation plan cached');
    }

    res.json({ 
      remediationPlan,
      cached: false,
      metadata: {
        // 🔧 STATIC remediation data
        findingId: finding.id,
        cweType: finding.cwe?.name,
        severity: finding.severity,
        complexity: finding.remediationComplexity,
        staticGuidance: finding.remediation,
        // 🤖 AI enhancement metadata
        aiEnhanced: true,
        model: "gpt-4",
        detailedPlanGenerated: true
      }
    });

  } catch (error) {
    console.error('🤖 AI remediation planning error:', error);
    res.status(500).json({ 
      error: 'Remediation planning failed',
      details: error.message,
      service: 'OpenAI GPT-4',
      timestamp: new Date().toISOString()
    });
  }
});

/**
 * POST /api/compliance-analysis
 * 🤖 AI ENDPOINT: Analyze findings for compliance and regulatory impact
 * Uses compliance mappings from SecurityClassificationSystem
 */
router.post('/compliance-analysis', async (req, res) => {
  try {
    console.log('🤖 AI: /compliance-analysis request received');
    
    const { 
      findings = [], 
      complianceContext = {},
      useCache = true 
    } = req.body;

    if (!Array.isArray(findings) || findings.length === 0) {
      return res.status(400).json({ 
        error: 'Missing or empty findings array',
        required: 'Array of enhanced security findings with compliance mappings'
      });
    }

    // Extract compliance mappings from enhanced findings
    const complianceMappings = findings.map(f => ({
      finding: f.id,
      cwe: f.cwe?.name,
      severity: f.severity,
      mappings: f.complianceMapping || []
    }));

    // Generate cache key
    const findingIds = findings.map(f => f.id || f.ruleId).sort().join(',');
    const cacheKey = `compliance:${findingIds}:${JSON.stringify(complianceContext)}`;
    
    if (useCache) {
      const cached = cache.get(cacheKey);
      if (cached) {
        console.log('🤖 AI: Returning cached compliance analysis');
        return res.json({ 
          complianceAnalysis: cached, 
          cached: true,
          findingsCount: findings.length,
          complianceMappings
        });
      }
    }

    // Build enhanced compliance prompt
    console.log(`🤖 AI: Building compliance analysis for ${findings.length} findings`);
    const prompt = buildCompliancePrompt(findings, complianceContext);

    // Get AI compliance analysis
    const complianceAnalysis = await getAICompletion(prompt, {
      temperature: 0.4,
      maxTokens: 1200,
      model: "gpt-4"
    });

    // Cache the result
    if (useCache) {
      cache.set(cacheKey, complianceAnalysis);
      console.log('🤖 AI: Compliance analysis cached');
    }

    res.json({ 
      complianceAnalysis,
      cached: false,
      metadata: {
        // 🔧 STATIC compliance data
        findingsCount: findings.length,
        complianceMappings,
        frameworks: [...new Set(complianceMappings.flatMap(c => c.mappings.map(m => m.framework)))],
        // 🤖 AI processing metadata
        aiEnhanced: true,
        model: "gpt-4",
        regulatoryInterpretation: true
      }
    });

  } catch (error) {
    console.error('🤖 AI compliance analysis error:', error);
    res.status(500).json({ 
      error: 'Compliance analysis failed',
      details: error.message,
      service: 'OpenAI GPT-4',
      timestamp: new Date().toISOString()
    });
  }
});

/**
 * POST /api/generate-report
 * 🤖 AI ENDPOINT: Generate comprehensive AI-enhanced security report
 * Integrates all enhanced classification data for executive reporting
 */
router.post('/generate-report', async (req, res) => {
  try {
    console.log('🤖 AI: /generate-report request received');
    
    const { 
      findings = [], 
      riskAssessment = {},
      context = {},
      reportType = 'comprehensive',
      audience = 'consultant'
    } = req.body;

    if (!Array.isArray(findings) || findings.length === 0) {
      return res.status(400).json({ 
        error: 'Missing or empty findings array'
      });
    }

    console.log(`🤖 AI: Generating ${reportType} report for ${audience} audience`);

    // Extract enhanced data for report generation
    const severityBreakdown = findings.reduce((acc, f) => {
      acc[f.severity] = (acc[f.severity] || 0) + 1;
      return acc;
    }, { Critical: 0, High: 0, Medium: 0, Low: 0 });

    const topFindings = findings
      .sort((a, b) => (b.cvss?.adjustedScore || 0) - (a.cvss?.adjustedScore || 0))
      .slice(0, 5);

    const complianceViolations = [...new Set(
      findings.flatMap(f => f.complianceMapping?.map(c => `${c.framework}: ${c.category || c.requirement}`) || [])
    )];

    // Build comprehensive report prompt with enhanced data
    const reportPrompt = `
You are generating a ${reportType} cybersecurity report for ${audience}s working on Neperia Group legacy system modernization.

## 🔧 STATIC SCAN RESULTS SUMMARY:
- **Total Findings**: ${findings.length}
- **Severity Breakdown**: Critical: ${severityBreakdown.Critical}, High: ${severityBreakdown.High}, Medium: ${severityBreakdown.Medium}, Low: ${severityBreakdown.Low}
- **Overall Risk Score**: ${riskAssessment.riskScore || 'Not calculated'} (${riskAssessment.riskLevel || 'Unknown'})
- **Risk Confidence**: ${riskAssessment.confidence || 'Not assessed'}

## 🌍 ENVIRONMENTAL CONTEXT:
- **Environment**: ${context.environment || 'production'}
- **Deployment**: ${context.deployment || 'internet-facing'}
- **Data Handling**: ${JSON.stringify(context.dataHandling || {})}
- **Compliance Requirements**: ${context.regulatoryRequirements?.join(', ') || 'Standard requirements'}

## 🔍 TOP SECURITY FINDINGS:
${topFindings.map(f => `- **${f.cwe?.name}** (${f.severity}, CVSS: ${f.cvss?.adjustedScore}): ${f.impact} in ${f.scannerData?.location?.file}`).join('\n')}

## ⚖️ COMPLIANCE VIOLATIONS IDENTIFIED:
${complianceViolations.join('\n- ') || 'None detected'}

## 📊 BUSINESS IMPACT INDICATORS:
- **System Type**: ${topFindings[0]?.aiMetadata?.environmentalContext?.systemType || 'business-application'}
- **Risk Amplifiers**: ${topFindings[0]?.aiMetadata?.environmentalContext?.riskAmplifiers?.join(', ') || 'none'}
- **Industry Context**: ${topFindings[0]?.aiMetadata?.environmentalContext?.businessContext?.industry || 'general-business'}

Generate a professional security report tailored for Neperia Group's modernization approach with:

1. **Executive Summary**: High-level overview of security posture and key risks for legacy system modernization

2. **Risk Assessment**: Detailed analysis of threat landscape and vulnerability impact on modernization timeline

3. **Priority Recommendations**: Top 5 actions to improve security posture during modernization

4. **Implementation Roadmap**: Phased approach to addressing vulnerabilities that integrates with modernization planning

5. **Compliance Implications**: How findings relate to regulatory requirements and modernization compliance goals

6. **Neperia Integration**: Specific recommendations for integrating security improvements with SEA Manager and KPS workflows

7. **Next Steps**: Specific actions for the modernization project team

Format as professional markdown suitable for stakeholder presentation and Neperia's structured documentation approach.`;

    // Get AI-generated report
    const report = await getAICompletion(reportPrompt, {
      temperature: 0.6,
      maxTokens: 2500,
      model: "gpt-4"
    });

    console.log('🤖 AI: Comprehensive report generated successfully');

    res.json({ 
      report,
      metadata: {
        // 🔧 STATIC report data
        reportType,
        audience,
        findingsCount: findings.length,
        severityBreakdown,
        overallRisk: riskAssessment,
        complianceViolations,
        // 🤖 AI generation metadata
        aiGenerated: true,
        model: "gpt-4",
        reportLength: report.length,
        generatedAt: new Date().toISOString(),
        integratedWithClassification: true
      }
    });

  } catch (error) {
    console.error('🤖 AI report generation error:', error);
    res.status(500).json({ 
      error: 'Report generation failed',
      details: error.message,
      service: 'OpenAI GPT-4',
      timestamp: new Date().toISOString()
    });
  }
});

/**
 * GET /api/cache-stats
 * Get AI cache statistics and performance metrics
 */
router.get('/cache-stats', (req, res) => {
  const stats = cache.getStats();
  
  res.json({
    aiCache: {
      keys: stats.keys,
      hits: stats.hits,
      misses: stats.misses,
      hitRate: stats.hits / (stats.hits + stats.misses) || 0,
      memoryUsage: `${Math.round(process.memoryUsage().heapUsed / 1024 / 1024)}MB`
    },
    endpoints: [
      'POST /api/explain-finding - AI explanations for individual vulnerabilities',
      'POST /api/assess-risk - Overall risk assessment with AI analysis', 
      'POST /api/plan-remediation - Detailed remediation planning',
      'POST /api/compliance-analysis - Regulatory compliance interpretation',
      'POST /api/generate-report - Comprehensive security reports',
      'GET /api/cache-stats - Performance statistics'
    ],
    integration: {
      classificationSystem: 'SecurityClassificationSystem v2.0',
      aiModel: 'OpenAI GPT-4',
      staticAnalysis: 'Semgrep + CWE + OWASP + CVSS',
      aiEnhancement: 'Contextual explanations + Business intelligence'
    },
    timestamp: new Date().toISOString()
  });
});

/**
 * DELETE /api/cache
 * Clear the AI response cache
 */
router.delete('/cache', (req, res) => {
  const keyCount = cache.keys().length;
  cache.flushAll();
  
  console.log(`🤖 AI: Cleared ${keyCount} cached responses`);
  
  res.json({
    message: 'AI cache cleared successfully',
    clearedKeys: keyCount,
    service: 'AI Response Cache',
    timestamp: new Date().toISOString()
  });
});

console.log('🤖 AI Router: All endpoints configured with SecurityClassificationSystem integration');

module.exports = router;