// src/aiUtils.js - AI prompt generation utilities for Neperia Security Analysis Tool
// 🤖 AI PROMPT ENGINEERING: Context-aware prompts for different audiences

/**
 * Build contextual AI prompt for explaining individual security findings
 * 🤖 AI INPUT: Generates audience-specific explanations using enhanced finding data
 * @param {Object} finding - Enhanced finding from SecurityClassificationSystem
 * @param {string} audience - Target audience ('developer', 'consultant', 'executive', 'auditor')
 * @param {Object} context - Environmental context
 * @returns {string} AI-ready prompt
 */
function buildPrompt(finding, audience = 'developer', context = {}) {
  console.log(`🤖 AI: Building ${audience} prompt for ${finding.cwe?.name || finding.ruleId}`);
  
  // Extract key information from enhanced finding
  const cweInfo = finding.cwe || { id: 'Unknown', name: 'Security Issue', category: 'General' };
  const cvssScore = finding.cvss?.adjustedScore || finding.cvss?.baseScore || 0;
  const severity = finding.severity || 'Medium';
  const location = finding.scannerData?.location || {};
  const businessImpact = finding.impact || 'Potential security risk';
  const complianceViolations = finding.complianceMapping || [];
  const environmentalContext = finding.aiMetadata?.environmentalContext || {};
  
  // Base prompt components
  const baseContext = `
## 🔍 SECURITY FINDING ANALYSIS FOR NEPERIA MODERNIZATION

You are analyzing a security vulnerability for Neperia Group's legacy system modernization project.

### 📊 FINDING DETAILS:
- **Vulnerability**: ${cweInfo.name} (${cweInfo.id})
- **OWASP Category**: ${finding.owaspCategory || 'Not classified'}
- **Severity**: ${severity} (CVSS: ${cvssScore})
- **Location**: ${location.file || 'unknown file'}:${location.line || 0}
- **Rule**: ${finding.ruleId}

### 💻 CODE CONTEXT:
\`\`\`
${finding.codeSnippet || finding.extractedCode || 'Code not available'}
\`\`\`

### 🌍 SYSTEM CONTEXT:
- **Environment**: ${context.environment || 'production'} ${context.deployment || 'system'}
- **System Type**: ${environmentalContext.systemType || 'business-application'}
- **Data Handling**: ${JSON.stringify(context.dataHandling || {})}
- **Risk Amplifiers**: ${environmentalContext.riskAmplifiers?.join(', ') || 'none'}
- **Business Impact**: ${businessImpact}

### ⚖️ COMPLIANCE IMPLICATIONS:
${complianceViolations.length > 0 
  ? complianceViolations.map(c => `- **${c.framework}**: ${c.requirement || c.category}`).join('\n')
  : '- Standard security requirements apply'
}
`;

  // Audience-specific instructions
  const audienceInstructions = {
    developer: `
### 🎯 DEVELOPER EXPLANATION REQUIRED:

Provide a technical explanation for a **software developer** working on Neperia's legacy modernization project:

1. **Technical Root Cause**: Explain exactly what causes this vulnerability at the code level
2. **Exploitation Scenario**: How could an attacker exploit this in a ${context.environment || 'production'} environment?
3. **Code Fix**: Provide specific code changes or patterns to fix this issue
4. **Testing Strategy**: How to verify the fix works and prevent regression
5. **Integration Notes**: How this fix fits into modern development workflows

Focus on actionable technical details, code examples, and implementation guidance.
Language: Technical but clear, with practical examples.`,

    consultant: `
### 🎯 CONSULTANT EXPLANATION REQUIRED:

Provide a comprehensive analysis for a **Neperia consultant** managing legacy system transformation:

1. **Business Risk Assessment**: What are the real-world business implications of this vulnerability?
2. **Modernization Impact**: How does this finding affect the modernization timeline and approach?
3. **Client Communication**: How to explain this risk to non-technical stakeholders?
4. **Remediation Planning**: Phased approach for addressing this in the transformation project
5. **Neperia Methodology Integration**: How this fits into SEA Manager and KPS workflows

Focus on project management, client relations, and strategic planning aspects.
Language: Professional consulting tone, business-focused with technical accuracy.`,

    executive: `
### 🎯 EXECUTIVE EXPLANATION REQUIRED:

Provide a strategic overview for **executive stakeholders** overseeing the modernization project:

1. **Business Impact Summary**: What does this mean for the organization's risk profile?
2. **Financial Implications**: Potential costs of not addressing this vulnerability
3. **Regulatory Concerns**: Compliance risks and audit implications
4. **Strategic Recommendations**: High-level actions required from leadership
5. **Timeline Considerations**: How this affects project milestones and deliverables

Focus on strategic decision-making, risk management, and business outcomes.
Language: Executive summary style, quantified risks where possible, actionable recommendations.`,

    auditor: `
### 🎯 AUDITOR EXPLANATION REQUIRED:

Provide a compliance-focused analysis for **auditors and compliance officers**:

1. **Regulatory Mapping**: Which specific regulations or standards are violated?
2. **Risk Rating Justification**: Why this CVSS score and severity level?
3. **Evidence Documentation**: What evidence supports this finding?
4. **Compliance Gap Analysis**: How this relates to overall security posture
5. **Audit Trail Requirements**: Documentation needed for compliance reporting

Focus on compliance frameworks, audit trails, and regulatory requirements.
Language: Formal audit language, standards-based, with clear risk categorization.`
  };

  const instruction = audienceInstructions[audience] || audienceInstructions.developer;

  return `${baseContext}

${instruction}

### 📋 RESPONSE FORMAT:
Provide a clear, structured response in markdown format. Include specific recommendations tailored to the ${audience} audience and the Neperia modernization context.

**Important**: This is part of Neperia's systematic approach to transforming legacy systems. Your explanation should support informed decision-making and actionable next steps.`;
}

/**
 * Build AI prompt for overall risk assessment
 * 🤖 AI INPUT: Comprehensive risk analysis using aggregated data
 * @param {Array} findings - Array of enhanced security findings
 * @param {Object} context - System and business context
 * @param {Object} aggregatedRisk - Risk data from SecurityClassificationSystem
 * @returns {string} Risk assessment prompt
 */
function buildRiskAssessmentPrompt(findings, context = {}, aggregatedRisk = null) {
  console.log(`🤖 AI: Building risk assessment prompt for ${findings.length} findings`);
  
  // Calculate finding distribution
  const severityBreakdown = findings.reduce((acc, f) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1;
    return acc;
  }, { Critical: 0, High: 0, Medium: 0, Low: 0 });

  // Extract top risks
  const topFindings = findings
    .sort((a, b) => (b.cvss?.adjustedScore || 0) - (a.cvss?.adjustedScore || 0))
    .slice(0, 5)
    .map(f => `- **${f.cwe?.name}** (${f.severity}, CVSS: ${f.cvss?.adjustedScore || 0}) in ${f.scannerData?.location?.file || 'unknown'}`);

  // Extract unique CWE categories
  const vulnerabilityTypes = [...new Set(findings.map(f => f.cwe?.category || 'General'))];
  
  // Extract compliance violations
  const complianceIssues = [...new Set(
    findings.flatMap(f => f.complianceMapping?.map(c => `${c.framework}: ${c.requirement || c.category}`) || [])
  )];

  return `
## 🎯 COMPREHENSIVE RISK ASSESSMENT FOR NEPERIA MODERNIZATION PROJECT

You are conducting a holistic security risk assessment for a Neperia Group legacy system modernization project.

### 📊 SCAN RESULTS SUMMARY:
- **Total Findings**: ${findings.length}
- **Severity Distribution**: Critical: ${severityBreakdown.Critical}, High: ${severityBreakdown.High}, Medium: ${severityBreakdown.Medium}, Low: ${severityBreakdown.Low}
- **Overall Risk Score**: ${aggregatedRisk?.riskScore || 'Not calculated'} (${aggregatedRisk?.riskLevel || 'Unknown'})
- **Assessment Confidence**: ${aggregatedRisk?.confidence || 'Medium'}

### 🔍 TOP SECURITY RISKS:
${topFindings.join('\n')}

### 🏗️ VULNERABILITY LANDSCAPE:
- **Primary Categories**: ${vulnerabilityTypes.join(', ')}
- **System Context**: ${context.environment || 'production'} ${context.deployment || 'environment'}
- **Data Sensitivity**: ${JSON.stringify(context.dataHandling || {})}

### ⚖️ COMPLIANCE IMPLICATIONS:
${complianceIssues.length > 0 
  ? complianceIssues.map(issue => `- ${issue}`).join('\n')
  : '- Standard security compliance requirements'}

### 🌍 BUSINESS CONTEXT:
- **Industry**: ${context.industry || 'general business'}
- **Regulatory Requirements**: ${context.regulatoryRequirements?.join(', ') || 'standard requirements'}
- **System Criticality**: ${context.isProduction ? 'Production system' : 'Non-production'}
- **Internet Exposure**: ${context.isInternetFacing ? 'Internet-facing' : 'Internal system'}

### 🎯 RISK ASSESSMENT REQUIRED:

Provide a comprehensive risk assessment that addresses:

1. **Overall Security Posture**: What is the current risk level and why?

2. **Business Impact Analysis**: How do these vulnerabilities threaten business operations, especially during modernization?

3. **Risk Prioritization**: Which findings require immediate attention vs. those that can be addressed during planned modernization?

4. **Modernization Strategy Impact**: How do these security findings affect the transformation approach and timeline?

5. **Neperia Methodology Integration**: How should this risk assessment inform SEA Manager analysis and KPS knowledge processing?

6. **Stakeholder Communication**: Key messages for different stakeholders (technical teams, project managers, executives)

7. **Success Metrics**: How to measure security improvement throughout the modernization process

### 📋 RESPONSE FORMAT:
Structure your response as a professional risk assessment report suitable for Neperia's client deliverables. Include:
- Executive summary
- Detailed risk analysis
- Prioritized recommendations
- Integration guidance for Neperia's modernization methodology

**Context**: This assessment will guide critical decisions in a legacy system transformation project. Focus on actionable insights that support both security improvement and successful modernization.`;
}

/**
 * Build AI prompt for detailed remediation planning
 * 🤖 AI INPUT: Detailed fix planning using static remediation guidance
 * @param {Object} finding - Enhanced security finding
 * @param {Object} projectContext - Project-specific context
 * @returns {string} Remediation planning prompt
 */
function buildRemediationPrompt(finding, projectContext = {}) {
  console.log(`🤖 AI: Building remediation prompt for ${finding.cwe?.name || finding.ruleId}`);
  
  const cweInfo = finding.cwe || {};
  const staticGuidance = finding.remediation || {};
  const complexity = finding.remediationComplexity || {};
  const businessImpact = finding.impact || 'Security risk';

  return `
## 🔧 DETAILED REMEDIATION PLAN FOR NEPERIA MODERNIZATION

You are creating a comprehensive remediation plan for a security vulnerability discovered during Neperia's legacy system analysis.

### 🔍 VULNERABILITY DETAILS:
- **Issue**: ${cweInfo.name || 'Security Vulnerability'} (${cweInfo.id || 'Unknown'})
- **Severity**: ${finding.severity} (CVSS: ${finding.cvss?.adjustedScore || 0})
- **Location**: ${finding.scannerData?.location?.file || 'unknown'}:${finding.scannerData?.location?.line || 0}
- **Business Impact**: ${businessImpact}

### 💻 AFFECTED CODE:
\`\`\`
${finding.codeSnippet || finding.extractedCode || 'Code context not available'}
\`\`\`

### 🏗️ PROJECT CONTEXT:
- **Modernization Phase**: ${projectContext.modernizationPhase || 'analysis'}
- **Timeline**: ${projectContext.timeline || 'standard project timeline'}
- **Technology Stack**: ${projectContext.targetTechnology || 'to be determined'}
- **Resource Constraints**: ${projectContext.resourceConstraints || 'standard resources'}
- **Legacy System**: ${projectContext.legacySystem || 'inherited system'}

### 📊 COMPLEXITY ASSESSMENT:
- **Remediation Complexity**: ${complexity.level || 'medium'} (Score: ${complexity.score || 5}/10)
- **Factors**: ${Object.entries(complexity.factors || {}).map(([k, v]) => `${k}: ${v}`).join(', ') || 'standard complexity factors'}

### 🎯 STATIC REMEDIATION GUIDANCE:
${staticGuidance.immediate ? `- **Immediate**: ${staticGuidance.immediate}` : ''}
${staticGuidance.shortTerm ? `- **Short-term**: ${staticGuidance.shortTerm}` : ''}
${staticGuidance.longTerm ? `- **Long-term**: ${staticGuidance.longTerm}` : ''}

### 📋 COMPREHENSIVE REMEDIATION PLAN REQUIRED:

Create a detailed, phased remediation plan that includes:

### Phase 1: Immediate Actions (0-2 weeks)
- **Emergency Mitigations**: What can be done immediately to reduce risk?
- **Temporary Fixes**: Quick patches or configurations to buy time
- **Risk Reduction**: How to minimize exposure during modernization

### Phase 2: Short-term Solutions (2-8 weeks)
- **Targeted Fixes**: Specific code changes or security controls
- **Testing Strategy**: How to validate fixes without disrupting operations
- **Integration Approach**: How fixes fit into ongoing modernization work

### Phase 3: Long-term Strategic Implementation (2-6 months)
- **Architectural Changes**: How modernization can eliminate this vulnerability class
- **Preventive Measures**: Controls to prevent similar issues in the new system
- **Knowledge Transfer**: Ensuring the new system avoids these patterns

### 📊 IMPLEMENTATION DETAILS:

1. **Technical Implementation**:
   - Specific code changes required
   - Configuration updates needed
   - New security controls to implement

2. **Resource Requirements**:
   - Developer time estimates
   - Security expert involvement
   - Testing and validation effort

3. **Risk Management**:
   - What could go wrong during remediation?
   - Rollback procedures if fixes cause issues
   - Communication plan for stakeholders

4. **Success Criteria**:
   - How to verify the vulnerability is resolved
   - Metrics to track improvement
   - Long-term monitoring approach

5. **Neperia Integration**:
   - How this fits into SEA Manager documentation
   - KPS knowledge updates required
   - Client communication strategy

### 📋 RESPONSE FORMAT:
Provide a structured, actionable remediation plan in markdown format. Focus on practical steps that can be executed by Neperia's technical teams and integrated into the modernization project workflow.

**Important**: This plan will guide actual remediation work. Be specific, realistic, and consider the constraints of working with legacy systems during active modernization.`;
}

/**
 * Build AI prompt for compliance analysis
 * 🤖 AI INPUT: Regulatory compliance interpretation
 * @param {Array} findings - Enhanced security findings with compliance mappings
 * @param {Object} complianceContext - Compliance requirements and context
 * @returns {string} Compliance analysis prompt
 */
function buildCompliancePrompt(findings, complianceContext = {}) {
  console.log(`🤖 AI: Building compliance prompt for ${findings.length} findings`);
  
  // Extract compliance mappings
  const complianceMappings = findings.flatMap(f => 
    (f.complianceMapping || []).map(c => ({
      finding: f.cwe?.name || f.ruleId,
      severity: f.severity,
      framework: c.framework,
      requirement: c.requirement || c.category,
      cvssScore: f.cvss?.adjustedScore || 0
    }))
  );

  // Group by framework
  const frameworkGroups = complianceMappings.reduce((acc, mapping) => {
    if (!acc[mapping.framework]) acc[mapping.framework] = [];
    acc[mapping.framework].push(mapping);
    return acc;
  }, {});

  // Calculate severity distribution
  const severityBreakdown = findings.reduce((acc, f) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1;
    return acc;
  }, { Critical: 0, High: 0, Medium: 0, Low: 0 });

  return `
## ⚖️ COMPLIANCE ANALYSIS FOR NEPERIA MODERNIZATION PROJECT

You are conducting a regulatory compliance analysis for security vulnerabilities discovered during Neperia's legacy system modernization.

### 📊 COMPLIANCE SCOPE:
- **Required Frameworks**: ${complianceContext.requirements?.join(', ') || 'Standard security frameworks'}
- **Industry Context**: ${complianceContext.industry || 'general business'}
- **Regulatory Environment**: ${complianceContext.regulatoryEnvironment || 'standard regulatory requirements'}
- **Audit Timeline**: ${complianceContext.auditTimeline || 'standard timeline'}

### 🔍 FINDINGS SUMMARY:
- **Total Security Issues**: ${findings.length}
- **Severity Distribution**: Critical: ${severityBreakdown.Critical}, High: ${severityBreakdown.High}, Medium: ${severityBreakdown.Medium}, Low: ${severityBreakdown.Low}

### 📋 COMPLIANCE MAPPINGS BY FRAMEWORK:

${Object.entries(frameworkGroups).map(([framework, mappings]) => `
#### ${framework}:
${mappings.map(m => `- **${m.finding}** (${m.severity}) → ${m.requirement}`).join('\n')}
`).join('')}

### 🎯 COMPREHENSIVE COMPLIANCE ANALYSIS REQUIRED:

Provide a thorough compliance analysis that addresses:

### 1. Regulatory Impact Assessment
- Which specific regulations or standards are affected by these findings?
- What are the potential penalties or sanctions for non-compliance?
- How do these vulnerabilities create audit risks?

### 2. Compliance Gap Analysis
- What specific requirements are currently not met?
- Which findings represent the highest compliance risk?
- How do these gaps affect overall security posture?

### 3. Remediation Prioritization from Compliance Perspective
- Which issues must be addressed immediately for compliance?
- What can be scheduled as part of planned modernization?
- How to balance technical debt with compliance requirements?

### 4. Audit Preparation Strategy
- What documentation is needed to demonstrate due diligence?
- How to present these findings to auditors or regulators?
- What evidence is required to show remediation progress?

### 5. Framework-Specific Guidance
${Object.keys(frameworkGroups).map(framework => `
#### ${framework} Specific Requirements:
- Detailed requirement analysis
- Risk assessment methodology
- Remediation timeline expectations
- Documentation standards
`).join('')}

### 6. Neperia Methodology Integration
- How compliance requirements affect SEA Manager analysis
- KPS documentation needs for audit trail
- Client communication strategy for compliance issues

### 7. Ongoing Compliance Strategy
- How to maintain compliance during modernization
- Preventive measures for the new system
- Continuous monitoring and assessment approach

### 📋 RESPONSE FORMAT:
Structure your response as a formal compliance analysis report suitable for:
- Internal compliance teams
- External auditors
- Regulatory submissions
- Client compliance documentation

Include specific regulatory citations where applicable and provide clear, actionable recommendations for achieving and maintaining compliance throughout the modernization process.

**Context**: This analysis will inform critical compliance decisions and may be used in regulatory discussions. Ensure accuracy and completeness in all regulatory interpretations.`;
}

/**
 * Generate metadata about the scanning context for AI processing
 * 🤖 AI METADATA: Context enrichment for better AI responses
 * @param {Object} scanContext - Context information from the scan
 * @returns {Object} Structured metadata for AI processing
 */
function generateContextMetadata(scanContext = {}) {
  return {
    // Environment classification
    environmentType: scanContext.environment || 'production',
    deploymentModel: scanContext.deployment || 'standard',
    
    // System characteristics
    systemCriticality: scanContext.isProduction ? 'high' : 'standard',
    exposureLevel: scanContext.isInternetFacing ? 'external' : 'internal',
    
    // Data sensitivity flags
    dataClassification: {
      hasPersonalData: scanContext.dataHandling?.personalData || false,
      hasFinancialData: scanContext.dataHandling?.financialData || false,
      hasHealthData: scanContext.dataHandling?.healthData || false
    },
    
    // Compliance requirements
    regulatoryScope: scanContext.regulatoryRequirements || [],
    
    // Business context
    industryContext: scanContext.industry || 'general-business',
    
    // Risk amplification factors
    riskAmplifiers: [
      ...(scanContext.isInternetFacing ? ['public-exposure'] : []),
      ...(scanContext.isProduction ? ['production-system'] : []),
      ...(scanContext.dataHandling?.personalData ? ['personal-data'] : []),
      ...(scanContext.regulatoryRequirements?.length > 0 ? ['regulatory-requirements'] : [])
    ],
    
    // Modernization context
    modernizationPhase: scanContext.modernizationPhase || 'analysis',
    legacySystemIndicators: scanContext.isLegacy || false,
    
    // AI processing hints
    complexity: scanContext.systemComplexity || 'medium',
    priorityLevel: calculatePriorityLevel(scanContext),
    audienceRelevance: determineAudienceRelevance(scanContext)
  };
}

/**
 * Calculate priority level based on context factors
 * @param {Object} scanContext - Scanning context
 * @returns {string} Priority level
 */
function calculatePriorityLevel(scanContext) {
  let priorityScore = 0;
  
  if (scanContext.isProduction) priorityScore += 3;
  if (scanContext.isInternetFacing) priorityScore += 2;
  if (scanContext.dataHandling?.financialData) priorityScore += 2;
  if (scanContext.dataHandling?.healthData) priorityScore += 3;
  if (scanContext.dataHandling?.personalData) priorityScore += 1;
  if (scanContext.regulatoryRequirements?.length > 0) priorityScore += 2;
  
  if (priorityScore >= 7) return 'critical';
  if (priorityScore >= 4) return 'high';
  if (priorityScore >= 2) return 'medium';
  return 'low';
}

/**
 * Determine which audiences are most relevant for the context
 * @param {Object} scanContext - Scanning context
 * @returns {Array} Relevant audiences in priority order
 */
function determineAudienceRelevance(scanContext) {
  const audiences = [];
  
  // Always include developer for technical details
  audiences.push('developer');
  
  // Consultant for modernization projects
  if (scanContext.modernizationPhase || scanContext.isLegacy) {
    audiences.push('consultant');
  }
  
  // Executive for high-risk or production systems
  if (scanContext.isProduction || scanContext.isInternetFacing) {
    audiences.push('executive');
  }
  
  // Auditor for compliance-heavy contexts
  if (scanContext.regulatoryRequirements?.length > 0) {
    audiences.push('auditor');
  }
  
  return audiences;
}

// Export all functions for use in aiRouter.js
module.exports = {
  buildPrompt,
  buildRiskAssessmentPrompt,
  buildRemediationPrompt,
  buildCompliancePrompt,
  generateContextMetadata
};

console.log('🤖 AI Utils: All prompt generation functions loaded successfully');
console.log('🎯 Configured for Neperia modernization methodology');
console.log('👥 Supporting audiences: developer, consultant, executive, auditor');
console.log('⚖️ Compliance frameworks: OWASP, CWE, CVSS, PCI-DSS, GDPR, HIPAA');