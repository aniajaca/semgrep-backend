/**
 * FARS and PRS Aggregation
 * Implements Literature Review §6.3 formulas exactly.
 *
 * FARS = Σ(CRS_i × w(CRS_i)) / Σ(w(CRS_i))
 * PRS  = P90({FARS_file})
 */

function getCRSWeight(crs) {
  if (crs >= 80) return 1.0;  // P0
  if (crs >= 65) return 0.7;  // P1
  if (crs >= 50) return 0.4;  // P2
  return 0.2;                  // P3
}

function getBand(crs) {
  if (crs >= 80) return 'P0';
  if (crs >= 65) return 'P1';
  if (crs >= 50) return 'P2';
  return 'P3';
}

/** Calculate FARS for one file's findings */
function calculateFARS(findings) {
  if (!findings || findings.length === 0) {
    return { farsScore: 0, maxBand: null, avgCRS: 0, findingCount: 0, findingRefs: [], severityDistribution: { P0: 0, P1: 0, P2: 0, P3: 0 } };
  }
  let weightedSum = 0, weightSum = 0, maxCRS = 0;
  const dist = { P0: 0, P1: 0, P2: 0, P3: 0 };

  findings.forEach(f => {
    const crs = f.crs || f.adjustedScore || 0;
    const w = getCRSWeight(crs);
    weightedSum += crs * w;
    weightSum += w;
    maxCRS = Math.max(maxCRS, crs);
    dist[getBand(crs)]++;
  });

  const farsScore = weightSum > 0 ? Math.round((weightedSum / weightSum) * 10) / 10 : 0;
  const sorted = [...findings].sort((a, b) => (b.crs || b.adjustedScore || 0) - (a.crs || a.adjustedScore || 0));
  const totalCRS = findings.reduce((s, f) => s + (f.crs || f.adjustedScore || 0), 0);

  return {
    farsScore,
    maxBand: getBand(maxCRS),
    avgCRS: Math.round((totalCRS / findings.length) * 10) / 10,
    findingCount: findings.length,
    findingRefs: sorted.slice(0, 5).map(f => f.id || f.ruleId || `${f.file}:${f.startLine || f.line}`),
    severityDistribution: dist
  };
}

/** Group findings by file and calculate FARS for each */
function calculateAllFARS(allFindings) {
  const groups = new Map();
  allFindings.forEach(f => {
    const file = f.file || 'unknown';
    if (!groups.has(file)) groups.set(file, []);
    groups.get(file).push(f);
  });
  const results = [];
  groups.forEach((findings, filename) => results.push({ filename, ...calculateFARS(findings) }));
  results.sort((a, b) => b.farsScore - a.farsScore);
  return results;
}

/** P90 percentile (linear interpolation) */
function percentile(sorted, k) {
  if (!sorted || sorted.length === 0) return 0;
  if (sorted.length === 1) return sorted[0];
  const i = (k / 100) * (sorted.length - 1);
  const lo = Math.floor(i), hi = Math.ceil(i), w = i - lo;
  return sorted[lo] * (1 - w) + sorted[Math.min(hi, sorted.length - 1)] * w;
}

/** Calculate PRS = P90 of FARS scores */
function calculatePRS(farsResults) {
  if (!farsResults || farsResults.length === 0) {
    return { overallScore: 0, band: 'P3', distribution: { P0: 0, P1: 0, P2: 0, P3: 0 }, topRiskFiles: [], estimatedRemediationDays: 0 };
  }
  const scores = farsResults.map(r => r.farsScore).sort((a, b) => a - b);
  const prs = Math.round(percentile(scores, 90) * 10) / 10;
  const dist = { P0: 0, P1: 0, P2: 0, P3: 0 };
  farsResults.forEach(r => { Object.keys(dist).forEach(b => { dist[b] += (r.severityDistribution?.[b] || 0); }); });
  const top10 = Math.max(1, Math.ceil(farsResults.length * 0.1));
  const slaMap = { P0: 7, P1: 14, P2: 30, P3: 90 };
  const total = Object.values(dist).reduce((s, v) => s + v, 0);
  let estDays = 0;
  if (total > 0) Object.entries(dist).forEach(([b, c]) => { estDays += (c / total) * slaMap[b]; });

  return {
    overallScore: prs,
    band: getBand(prs),
    distribution: dist,
    topRiskFiles: farsResults.slice(0, top10).map(r => ({ filename: r.filename, farsScore: r.farsScore, maxBand: r.maxBand, findingCount: r.findingCount })),
    estimatedRemediationDays: Math.round(estDays)
  };
}

module.exports = { calculateFARS, calculateAllFARS, calculatePRS, getCRSWeight, getBand, percentile };