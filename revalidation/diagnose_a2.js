#!/usr/bin/env node
// =============================================================================
// DIAGNOSTIC: Why does A2 still show internetFacing=true?
// Save as: revalidation/diagnose_a2.js
// Run:     node revalidation/diagnose_a2.js
// =============================================================================

const ContextInferenceSystem = require('../src/contextInference');

const A2_CODE = `const express = require("express");
const path = require("path");
const app = express();

function requireAuth(req, res, next) {
  if (req.headers.authorization) {
    next();
  } else {
    res.status(401).json({ error: "Unauthorized" });
  }
}

app.use(requireAuth);

app.get("/admin/logs/:file", (req, res) => {
  const logFile = req.params.file;
  const filePath = path.join("/var/log", logFile);
  res.sendFile(filePath);
});

app.listen(8080);`;

async function diagnose() {
  console.log('=== A2 CONTEXT INFERENCE DIAGNOSTIC ===\n');

  // Check 1: Is the post-processing block present in index.js?
  console.log('-- Check 1: Post-processing block present? --');
  const indexSource = require('fs').readFileSync(
    require('path').join(__dirname, '../src/contextInference/index.js'), 'utf8'
  );
  const hasPostProcessing = indexSource.includes('authenticatedInternal');
  const hasAuthAware = indexSource.includes('Auth-aware internetFacing');
  console.log('  Contains "authenticatedInternal":', hasPostProcessing);
  console.log('  Contains "Auth-aware internetFacing":', hasAuthAware);
  if (!hasPostProcessing) {
    console.log('\n  POST-PROCESSING BLOCK IS MISSING FROM YOUR LOCAL CODE');
    console.log('  -> git pull and restart the server');
    return;
  }
  console.log('  OK: Post-processing block exists in source file');

  // Check 2: Test detectAuth directly
  console.log('\n-- Check 2: JSContextDetector.detectAuth() --');
  const JSContextDetector = require('../src/contextInference/detectors/jsDetector');
  const detector = new JSContextDetector();
  
  let authResult;
  try {
    authResult = await detector.detectAuth(A2_CODE, { file: 'internalAdmin.js' });
    console.log('  Result:', JSON.stringify(authResult));
    console.log('  missing=' + authResult.missing + ' (false=auth found, true=no auth)');
    if (authResult.missing) {
      console.log('  WARNING: detectAuth thinks NO auth is present!');
      console.log('  -> noAuth will be SET -> post-processing condition fails');
    } else {
      console.log('  OK: Auth was detected (likely via regex fallback)');
    }
  } catch (e) {
    console.log('  ERROR:', e.message);
  }

  // Check 3: Test detectRoutes directly
  console.log('\n-- Check 3: JSContextDetector.detectRoutes() --');
  try {
    const routeResult = await detector.detectRoutes(A2_CODE, { file: 'internalAdmin.js' });
    console.log('  Result:', JSON.stringify(routeResult));
  } catch (e) {
    console.log('  ERROR:', e.message);
  }

  // Check 4: Full inferFindingContext
  console.log('\n-- Check 4: Full inferFindingContext() --');
  const ci = new ContextInferenceSystem();
  
  try {
    const result = await ci.inferFindingContext(
      { file: 'internalAdmin.js', ruleId: 'test', severity: 'HIGH', cwe: 'CWE-22' },
      A2_CODE,
      null,
      {}
    );
    
    console.log('  Full result:', JSON.stringify(result, null, 2));
    console.log('\n  -- Factor Summary --');
    console.log('  internetFacing:       ', result.internetFacing ? 'SET (should be deleted by post-processing)' : 'NOT SET (good)');
    console.log('  authenticatedInternal:', result.authenticatedInternal ? 'SET (post-processing worked!)' : 'NOT SET');
    console.log('  noAuth:               ', result.noAuth ? 'SET (auth NOT detected - this blocks post-processing)' : 'NOT SET (auth detected)');
    
    if (result.internetFacing && !result.authenticatedInternal) {
      console.log('\n  PROBLEM: internetFacing persists, authenticatedInternal missing');
      if (result.noAuth) {
        console.log('  ROOT CAUSE: detectAuth did NOT find requireAuth');
        console.log('  -> noAuth was set -> condition !result.noAuth is FALSE -> post-processing skipped');
      } else {
        console.log('  -> noAuth NOT set, so condition should fire');
        console.log('  -> If running via API and seeing P0, RESTART THE SERVER');
        console.log('     Node.js caches modules - old code is still in memory');
      }
    }
    
    if (result.authenticatedInternal && !result.internetFacing) {
      console.log('\n  SUCCESS: Post-processing works correctly!');
      console.log('  If the API still shows P0, you need to RESTART the server:');
      console.log('    Ctrl+C -> node src/server.js');
    }
    
  } catch (e) {
    console.log('  ERROR:', e.message);
    console.log('  Stack:', e.stack);
  }

  console.log('\n=== DIAGNOSTIC COMPLETE ===');
}

diagnose().catch(e => {
  console.error('Fatal:', e);
  process.exit(1);
});