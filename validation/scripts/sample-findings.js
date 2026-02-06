#!/usr/bin/env node
const fs = require('fs');

const args = process.argv.slice(2).reduce((acc, arg) => {
  const [key, val] = arg.replace('--', '').split('=');
  acc[key] = val;
  return acc;
}, {});

const removed = JSON.parse(fs.readFileSync(args.removed)).findings;
const retained = JSON.parse(fs.readFileSync(args.retained)).findings || JSON.parse(fs.readFileSync(args.retained)).results || [];

const sampleSize = parseInt(args['sample-size']);
const removedSample = removed.sort(() => 0.5 - Math.random()).slice(0, sampleSize);
const retainedSample = retained.sort(() => 0.5 - Math.random()).slice(0, sampleSize);

const csv = ['file,line,ruleId,severity,message,status,label'];

removedSample.forEach(f => {
  csv.push(`"${f.file}",${f.line || f.startLine},"${f.ruleId || f.checkId}","${f.severity}","${(f.message || '').replace(/"/g, '""')}",removed,`);
});

retainedSample.forEach(f => {
  csv.push(`"${f.file}",${f.line || f.startLine},"${f.ruleId || f.checkId}","${f.severity}","${(f.message || '').replace(/"/g, '""')}",retained,`);
});

fs.writeFileSync(args.output, csv.join('\n'));
console.log(`✓ Generated ${csv.length - 1} samples`);
