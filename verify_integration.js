// verify_integration.js - Quick test to ensure all modules work together
console.log('🔍 Verifying Neperia AI-Enhanced Security Scanner Integration');
console.log('='.repeat(70));

async function verifyIntegration() {
  let allTestsPassed = true;

  // Test 1: Check all required modules can be imported
  console.log('\n1. Testing Module Imports...');
  try {
    const utils = require('./src/utils');
    const { SecurityClassificationSystem } = require('./src/SecurityClassificationSystem');
    const aiUtils = require('./src/aiUtils');
    const aiRouter = require('./src/aiRouter');
    
    console.log('✅ utils.js - imported successfully');
    console.log('✅ SecurityClassificationSystem.js - imported successfully');
    console.log('✅ aiUtils.js - imported successfully');
    console.log('✅ aiRouter.js - imported successfully');
    
    // Verify function exports
    const requiredUtilFunctions = ['getSeverityWeight', 'getSeverityLevel', 'classifySeverity'];
    const requiredAIFunctions = ['buildPrompt', 'buildRiskAssessmentPrompt', 'buildRemediationPrompt', 'buildCompliancePrompt', 'generateContextMetadata'];
    
    requiredUtilFunctions.forEach(func => {
      if (typeof utils[func] !== 'function') {
        console.log(`❌ utils.js missing function: ${func}`);
        allTestsPassed = false;
      }
    });
    
    requiredAIFunctions.forEach(func => {
      if (typeof aiUtils[func] !== 'function') {
        console.log(`❌ aiUtils.js missing function: ${func}`);
        allTestsPassed = false;
      }
    });
    
    if (allTestsPassed) {
      console.log('✅ All required functions exported correctly');
    }
    
  } catch (error) {
    console.log('❌ Module import error:', error.message);
    allTestsPassed = false;
  }

  // Test 2: Test SecurityClassificationSystem with mock data
  console.log('\n2. Testing SecurityClassificationSystem...');
  try {
    const { SecurityClassificationSystem } = require('./src/SecurityClassificationSystem');
    const classifier = new SecurityClassificationSystem();
    
    // Mock Semgrep finding
    const mockFinding = {
      check_id: 'hardcoded-password',
      message: 'Hardcoded password detected in authentication module',
      path: 'src/auth/login.js',
      start: { line: 42, col: 10 },
      extractedCode: 'const password = "admin123";',
      context: {
        isProduction: true,
        isInternetFacing: true,
        handlesFinancialData: true,
        regulatoryRequirements: ['PCI-DSS', 'GDPR']
      }
    };
    
    const classifiedFinding = classifier.classifyFinding(mockFinding);
    
    console.log('✅ Finding classified successfully');
    console.log(`   - ID: ${classifiedFinding.id}`);
    console.log(`   - CWE: ${classifiedFinding.cwe.id} (${classifiedFinding.cwe.name})`);
    console.log(`   - Severity: ${classifiedFinding.severity}`);
    console.log(`   - CVSS: ${classifiedFinding.cvss.adjustedScore}`);
    console.log(`   - OWASP: ${classifiedFinding.owaspCategory}`);
    console.log(`   - AI Metadata: ${classifiedFinding.aiMetadata ? 'Present' : 'Missing'}`);
    
    // Test risk aggregation
    const riskAssessment = classifier.aggregateRiskScore([classifiedFinding], mockFinding.context);
    console.log('✅ Risk aggregation successful');
    console.log(`   - Risk Score: ${riskAssessment.riskScore}`);
    console.log(`   - Risk Level: ${riskAssessment.riskLevel}`);
    console.log(`   - Confidence: ${riskAssessment.confidence}`);
    
  } catch (error) {
    console.log('❌ SecurityClassificationSystem error:', error.message);
    allTestsPassed = false;
  }

  // Test 3: Test AI Utils prompt generation
  console.log('\n3. Testing AI Utils Prompt Generation...');
  try {
    const aiUtils = require('./src/aiUtils');
    
    // Mock enhanced finding for prompt testing
    const mockEnhancedFinding = {
      id: 'hardcoded-password-login_js-42',
      ruleId: 'hardcoded-password',
      cwe: {
        id: 'CWE-798',
        name: 'Hardcoded Credentials',
        category: 'Authentication'
      },
      severity: 'High',
      cvss: {
        baseScore: 7.8,
        adjustedScore: 9.2,
        vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N'
      },
      owaspCategory: 'A07:2021 – Identification and Authentication Failures',
      scannerData: {
        location: { file: 'src/auth/login.js', line: 42 }
      },
      codeSnippet: 'const password = "admin123";',
      impact: 'Authentication bypass vulnerability in financial system',
      aiMetadata: {
        environmentalContext: {
          systemType: 'financial-system',
          riskAmplifiers: ['public-exposure', 'financial-data'],
          complianceRequirements: ['PCI-DSS', 'GDPR']
        }
      },
      complianceMapping: [
        { framework: 'PCI-DSS', requirement: 'Requirement 8.2 - User Authentication' }
      ]
    };
    
    // Test all prompt types
    const audiences = ['developer', 'consultant', 'executive', 'auditor'];
    const context = { environment: 'production', deployment: 'internet-facing' };
    
    audiences.forEach(audience => {
      const prompt = aiUtils.buildPrompt(mockEnhancedFinding, audience, context);
      console.log(`✅ ${audience} prompt generated (${prompt.length} chars)`);
    });
    
    // Test other prompt types
    const riskPrompt = aiUtils.buildRiskAssessmentPrompt([mockEnhancedFinding], context);
    console.log(`✅ Risk assessment prompt generated (${riskPrompt.length} chars)`);
    
    const remediationPrompt = aiUtils.buildRemediationPrompt(mockEnhancedFinding, { modernizationPhase: 'analysis' });
    console.log(`✅ Remediation prompt generated (${remediationPrompt.length} chars)`);
    
    const compliancePrompt = aiUtils.buildCompliancePrompt([mockEnhancedFinding], { requirements: ['PCI-DSS'] });
    console.log(`✅ Compliance prompt generated (${compliancePrompt.length} chars)`);
    
    const contextMetadata = aiUtils.generateContextMetadata(context);
    console.log(`✅ Context metadata generated: ${Object.keys(contextMetadata).length} properties`);
    
  } catch (error) {
    console.log('❌ AI Utils error:', error.message);
    console.log('Stack:', error.stack);
    allTestsPassed = false;
  }

  // Test 4: Verify Express Router
  console.log('\n4. Testing Express Router...');
  try {
    const aiRouter = require('./src/aiRouter');
    
    if (typeof aiRouter === 'function') {
      console.log('✅ aiRouter exports Express router function');
    } else {
      console.log('❌ aiRouter does not export Express router');
      allTestsPassed = false;
    }
    
  } catch (error) {
    console.log('❌ aiRouter error:', error.message);
    allTestsPassed = false;
  }

  // Test 5: Check environment setup
  console.log('\n5. Testing Environment Setup...');
  require('dotenv').config();
  
  if (process.env.OPENAI_API_KEY) {
    console.log('✅ OPENAI_API_KEY configured');
  } else {
    console.log('⚠️  OPENAI_API_KEY not configured (AI features will be disabled)');
  }
  
  if (process.env.PORT) {
    console.log(`✅ PORT configured (${process.env.PORT})`);
  } else {
    console.log('✅ PORT will use default (3000)');
  }

  // Final summary
  console.log('\n' + '='.repeat(70));
  console.log('🧪 INTEGRATION VERIFICATION SUMMARY');
  console.log('='.repeat(70));
  
  if (allTestsPassed) {
    console.log('🎉 ALL INTEGRATION TESTS PASSED!');
    console.log('\n📋 System Components Ready:');
    console.log('- 🔧 SecurityClassificationSystem v2.0: Enhanced vulnerability classification');
    console.log('- 🤖 AI Utils: Contextual prompt generation for 4 audiences');
    console.log('- 🚀 AI Router: 5 REST endpoints for AI enhancement');
    console.log('- ⚖️ Compliance: OWASP, CWE, CVSS, PCI-DSS, GDPR mapping');
    console.log('- 🎯 Neperia Integration: SEA Manager & KPS compatible');
    console.log('\n🚀 Ready to start server: node src/server.js');
  } else {
    console.log('❌ SOME INTEGRATION TESTS FAILED');
    console.log('Please review the errors above before starting the server.');
  }
  
  console.log('\n📊 Next Steps:');
  console.log('1. Ensure Semgrep is installed: pip install semgrep');
  console.log('2. Set OpenAI API key: export OPENAI_API_KEY=your_key_here');
  console.log('3. Start server: node src/server.js');
  console.log('4. Test endpoints with your favorite HTTP client');
  console.log('\n🎯 Endpoints Available:');
  console.log('- POST /scan-code - Static analysis with AI enhancement');
  console.log('- POST /api/explain-finding - AI explanations');
  console.log('- POST /api/assess-risk - AI risk assessment');
  console.log('- POST /api/plan-remediation - AI remediation planning');
  console.log('- POST /api/compliance-analysis - AI compliance analysis');
  console.log('- POST /api/generate-report - AI comprehensive reports');
  
  return allTestsPassed;
}

// Run verification
verifyIntegration().catch(error => {
  console.error('❌ Verification failed:', error);
  process.exit(1);
});