#!/usr/bin/env node
// calculate-svr.js - Calculate Seeded Vulnerability Retention rate

const fs = require('fs');

function calculateSVR(baselinePath, filteredPath, manifestPath, outputPath) {
  console.log('Calculating SVR...\n');
  
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  const expected = manifest.vulnerabilities;
  
  const baseline = JSON.parse(fs.readFileSync(baselinePath, 'utf8'));
  const baselineFindings = baseline.findings || baseline.results || [];
  
  const filtered = JSON.parse(fs.readFileSync(filteredPath, 'utf8'));
  const filteredFindings = filtered.findings || filtered.results || [];
  
  const details = [];
  let detectedBaseline = 0;
  let detectedFiltered = 0;
  
  expected.forEach(vuln => {
    const baselineFound = baselineFindings.find(f => {
      const fFile = (f.file || f.path || '').replace(/\\/g, '/');
      const vFile = vuln.file.replace(/\\/g, '/');
      const fileMatch = fFile.includes(vFile) || vFile.includes(fFile);
      const lineMatch = Math.abs((f.line || f.startLine || 0) - vuln.line) <= 5;
      return fileMatch && lineMatch;
    });
    
    const filteredFound = filteredFindings.find(f => {
      const fFile = (f.file || f.path || '').replace(/\\/g, '/');
      const vFile = vuln.file.replace(/\\/g, '/');
      const fileMatch = fFile.includes(vFile) || vFile.includes(fFile);
      const lineMatch = Math.abs((f.line || f.startLine || 0) - vuln.line) <= 5;
      return fileMatch && lineMatch;
    });
    
    if (baselineFound) detectedBaseline++;
    if (filteredFound) detectedFiltered++;
    
    const status = !baselineFound ? 'NOT_DETECTED' :
                   filteredFound ? 'RETAINED' : 'FILTERED';
    
    details.push({
      id: vuln.id,
      file: vuln.file,
      type: vuln.type,
      severity: vuln.severity,
      status
    });
    
    const symbol = status === 'RETAINED' ? '✅' : status === 'FILTERED' ? '🚨' : '⚠️';
    console.log(`${symbol} ${vuln.id}: ${status}`);
  });
  
  const svr = detectedBaseline > 0 ? (detectedFiltered / detectedBaseline) : 0;
  const report = {
    svr,
    detectedBaseline,
    detectedFiltered,
    filtered: detectedBaseline - detectedFiltered,
    status: svr === 1.0 ? 'PASS' : 'FAIL',
    details
  };
  
  if (outputPath) fs.writeFileSync(outputPath, JSON.stringify(report, null, 2));
  
  console.log(`\nSVR: ${(svr*100).toFixed(1)}% - ${report.status}`);
  return report;
}

if (require.main === module) {
  const [,, baseline, filtered, manifest, ...rest] = process.argv;
  const output = rest.find(a => a.startsWith('--output='))?.split('=')[1];
  calculateSVR(baseline, filtered, manifest, output);
}

module.exports = { calculateSVR };
