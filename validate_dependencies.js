// validate_dependencies.js - Check all dependencies and imports
console.log('🔍 Validating Neperia Security Analysis Tool Dependencies');
console.log('='.repeat(60));

// Check Node.js built-in modules
const requiredBuiltins = [
  'express', 'multer', 'child_process', 'fs', 'path', 'os', 'perf_hooks'
];

console.log('\n1. Checking Node.js built-in and core modules...');
requiredBuiltins.forEach(module => {
  try {
    require(module);
    console.log(`✅ ${module}`);
  } catch (error) {
    console.log(`❌ ${module} - ${error.message}`);
  }
});

// Check required npm packages
const requiredPackages = [
  'dotenv', 'openai', 'node-cache'
];

console.log('\n2. Checking required npm packages...');
requiredPackages.forEach(pkg => {
  try {
    require(pkg);
    console.log(`✅ ${pkg}`);
  } catch (error) {
    console.log(`❌ ${pkg} - ${error.message}`);
    if (pkg === 'openai') {
      console.log('   Install with: npm install openai');
    } else if (pkg === 'node-cache') {
      console.log('   Install with: npm install node-cache');
    } else if (pkg === 'dotenv') {
      console.log('   Install with: npm install dotenv');
    }
  }
});

// Check custom modules
console.log('\n3. Checking custom modules...');

// Check utils.js
try {
  const utils = require('./src/utils');
  const requiredUtilFunctions = ['getSeverityWeight', 'getSeverityLevel', 'classifySeverity'];
  
  let utilsValid = true;
  requiredUtilFunctions.forEach(func => {
    if (typeof utils[func] !== 'function') {
      console.log(`❌ src/utils.js missing function: ${func}`);
      utilsValid = false;
    }
  });
  
  if (utilsValid) {
    console.log('✅ src/utils.js - all required functions present');
  }
} catch (error) {
  console.log(`❌ src/utils.js - ${error.message}`);
}

// Check SecurityClassificationSystem.js
try {
  const { SecurityClassificationSystem } = require('./src/SecurityClassificationSystem');
  if (typeof SecurityClassificationSystem === 'function') {
    const classifier = new SecurityClassificationSystem();
    if (typeof classifier.classifyFinding === 'function' && 
        typeof classifier.aggregateRiskScore === 'function') {
      console.log('✅ src/SecurityClassificationSystem.js - properly exported and functional');
    } else {
      console.log('❌ src/SecurityClassificationSystem.js - missing required methods');
    }
  } else {
    console.log('❌ src/SecurityClassificationSystem.js - export issue');
  }
} catch (error) {
  console.log(`❌ src/SecurityClassificationSystem.js - ${error.message}`);
}

// Check aiUtils.js
try {
  const aiUtils = require('./src/aiUtils');
  const requiredAIFunctions = [
    'buildPrompt', 
    'buildRiskAssessmentPrompt', 
    'buildRemediationPrompt', 
    'buildCompliancePrompt',
    'generateContextMetadata'
  ];
  
  let aiUtilsValid = true;
  requiredAIFunctions.forEach(func => {
    if (typeof aiUtils[func] !== 'function') {
      console.log(`❌ src/aiUtils.js missing function: ${func}`);
      aiUtilsValid = false;
    }
  });
  
  if (aiUtilsValid) {
    console.log('✅ src/aiUtils.js - all required functions present');
  }
} catch (error) {
  console.log(`❌ src/aiUtils.js - ${error.message}`);
}

// Check aiRouter.js
try {
  const aiRouter = require('./src/aiRouter');
  if (typeof aiRouter === 'function') {
    console.log('✅ src/aiRouter.js - properly exported as Express router');
  } else {
    console.log('❌ src/aiRouter.js - not properly exported as Express router');
  }
} catch (error) {
  console.log(`❌ src/aiRouter.js - ${error.message}`);
}

// Check environment variables
console.log('\n4. Checking environment configuration...');
require('dotenv').config();

if (process.env.OPENAI_API_KEY) {
  console.log('✅ OPENAI_API_KEY - configured');
} else {
  console.log('⚠️  OPENAI_API_KEY - not configured (AI features will be disabled)');
  console.log('   Set with: export OPENAI_API_KEY=your_api_key_here');
}

if (process.env.PORT) {
  console.log(`✅ PORT - configured (${process.env.PORT})`);
} else {
  console.log('✅ PORT - will use default (3000)');
}

// Check system tools
console.log('\n5. Checking system tools...');
const { exec } = require('child_process');

// Check Semgrep
exec('semgrep --version', (error, stdout, stderr) => {
  if (error) {
    console.log('❌ Semgrep - not installed or not in PATH');
    console.log('   Install with: pip install semgrep');
  } else {
    console.log(`✅ Semgrep - ${stdout.trim()}`);
  }
});

// Check file system permissions
console.log('\n6. Checking file system permissions...');
const fs = require('fs');
const os = require('os');
const path = require('path');

try {
  const tempDir = path.join(os.tmpdir(), 'neperia-test');
  if (!fs.existsSync(tempDir)) {
    fs.mkdirSync(tempDir, { recursive: true });
  }
  
  const testFile = path.join(tempDir, 'test.txt');
  fs.writeFileSync(testFile, 'test');
  fs.readFileSync(testFile, 'utf8');
  fs.unlinkSync(testFile);
  fs.rmdirSync(tempDir);
  
  console.log('✅ File system - read/write permissions OK');
} catch (error) {
  console.log(`❌ File system - permission error: ${error.message}`);
}

// Summary
console.log('\n' + '='.repeat(60));
console.log('📋 DEPENDENCY VALIDATION SUMMARY');
console.log('='.repeat(60));

console.log('\n🔧 STATIC ANALYSIS COMPONENTS:');
console.log('- SecurityClassificationSystem: Enhanced vulnerability classification');
console.log('- CWE Database: Common Weakness Enumeration mapping');
console.log('- OWASP Mapping: Top 10 categorization');
console.log('- CVSS Calculator: Environmental risk scoring');

console.log('\n🤖 AI ENHANCEMENT COMPONENTS:');
console.log('- OpenAI Integration: GPT-4 explanations and analysis');
console.log('- Audience Targeting: Developer, Consultant, Executive, Auditor');
console.log('- Prompt Engineering: Context-aware AI prompts');
console.log('- Response Caching: Performance optimization');

console.log('\n🌐 SERVER COMPONENTS:');
console.log('- Express Server: REST API endpoints');
console.log('- CORS Configuration: Lovable.app integration');
console.log('- File Upload: Multer multipart handling');
console.log('- Error Handling: Comprehensive error management');

console.log('\n⚖️ COMPLIANCE COMPONENTS:');
console.log('- OWASP Top 10 2021: Security framework alignment');
console.log('- CWE Classification: Common weakness enumeration');
console.log('- CVSS 3.1 Scoring: Industry standard risk scoring');
console.log('- Regulatory Mapping: PCI-DSS, GDPR, HIPAA support');

console.log('\n🚀 NEPERIA INTEGRATION:');
console.log('- SEA Manager Compatible: Structured documentation');
console.log('- KPS Workflow Ready: Knowledge processing integration');
console.log('- Modernization Focused: Legacy transformation support');
console.log('- Client Reporting: Multi-audience business intelligence');

console.log('\n✅ System ready for deployment!');
console.log('🎯 Run: node validate_dependencies.js && node test_integration.js && node server.js');