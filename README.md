# Neperia Security Scanner

A privacy-by-design, stateless vulnerability assessment tool combining SAST, SCA, and DAST with context-aware risk scoring. Developed in partnership with Neperia Group as part of an MSc thesis on automated vulnerability prioritization.

## Features

- **Hybrid SAST**: Semgrep as primary engine (OWASP Top 10 + security-audit rulesets) with a custom Babel-based AST fallback scanner
- **Dependency Analysis (SCA)**: Scans for vulnerable packages via the OSV API
- **Dynamic Analysis (DAST)**: Tier 1 Puppeteer-based web crawler with SQLi/XSS probes
- **Context-Aware Risk Scoring**: Five-stage pipeline (BTS → CRS → BPS → FARS → PRS) adjusting severity based on inferred deployment context
- **Stateless & Privacy-by-Design**: Zero data persistence; code processed in ephemeral memory only, wiped on completion
- **SARIF 2.1.0 Output**: Standard-compliant reporting for CI/CD integration

## Installation

### Prerequisites

1. **Node.js** (v16 or higher)
```bash
node --version  # Should be >= 16.0.0
```

2. **Semgrep** (recommended for full coverage)
```bash
pip install semgrep
semgrep --version
```

### Setup

1. Clone the repository
```bash
git clone https://github.com/aniajaca/semgrep-backend
cd semgrep-backend
```

2. Install dependencies
```bash
npm install
```

3. Configure settings (optional)  
Edit `config/scanner.config.json` to adjust default context flags, severity mappings, and scan limits.

## Usage

### Start the API Server

```bash
npm start
# Server runs on http://localhost:3000
```

### API Endpoints

#### 1. Scan Code (SAST)
```bash
curl -X POST http://localhost:3000/scan-code \
  -H "Content-Type: application/json" \
  -d '{
    "path": "./sample/vulnerable-app",
    "context": {
      "internetFacing": true,
      "production": true,
      "handlesPI": false
    }
  }'
```

#### 2. Scan Dependencies (SCA)
```bash
curl -X POST http://localhost:3000/scan-dependencies \
  -H "Content-Type: application/json" \
  -d '{
    "path": "./sample/vulnerable-app",
    "context": {
      "production": true
    }
  }'
```

#### 3. Combined Scan
```bash
curl -X POST http://localhost:3000/scan \
  -H "Content-Type: application/json" \
  -d '{
    "path": "./sample/vulnerable-app",
    "context": {
      "internetFacing": true,
      "production": true
    }
  }'
```

#### 4. Dynamic Scan (DAST)
```bash
curl -X POST http://localhost:3000/scan-dast \
  -H "Content-Type: application/json" \
  -d '{
    "targetUrl": "http://localhost:8080",
    "crawlDepth": 3
  }'
```

### Environmental Context Flags

Context flags are inferred automatically from code artifacts (routes, config files, PII patterns) or can be supplied manually. Each flag carries a confidence score (0.0–1.0) that weights its contribution to the final CRS.

| Flag | Uplift | Description |
|------|--------|-------------|
| `internetFacing` | +0.20 | Component is exposed to the public internet |
| `production` | +0.15 | Running in a production environment |
| `handlesPI` | +0.15 | Processes personal/sensitive data |
| `noAuth` | +0.20 | Missing authentication or authorization |

Uplifts are weighted by inference confidence and capped at **+70%** of the base score.

### Risk Scoring Pipeline

Scores pass through five stages:

| Stage | Description |
|-------|-------------|
| **BTS** | Base Technical Severity mapped from Semgrep severity (Critical=9.0, High=7.5, Medium=5.0, Low=2.5) |
| **CRS** | Context Risk Score: `min(100, BTS × 10 × (1 + Σ(uplift × confidence)))`, capped at +70% |
| **BPS** | Business Priority Score *(optional, requires profile)*: `0.72×CRS + 0.18×criticality − 0.06×fixEffort − 0.04×controls` |
| **FARS** | File Aggregate Risk Score: per-file aggregation of CRS values with finding density |
| **PRS** | Project Risk Score: project-wide summary with risk heatmap and top-10% risk files |

### Priority Bands & SLAs

| Band | CRS Threshold | SLA |
|------|--------------|-----|
| P0 | ≥ 80 | Fix within 7 days |
| P1 | 65–79 | Fix within 14 days |
| P2 | 50–64 | Fix within 30 days |
| P3 | < 50 | Fix within 90 days |

### Response Format

```json
{
  "success": true,
  "findings": [
    {
      "engine": "semgrep",
      "ruleId": "sql-injection",
      "severity": "CRITICAL",
      "message": "SQL injection vulnerability detected",
      "cwe": ["CWE-89"],
      "owasp": ["A03:2021"],
      "file": "controllers/user.js",
      "startLine": 42,
      "bts": 9.0,
      "crs": 100,
      "priority": "P0",
      "contextFactors": {
        "internetFacing": { "value": true, "confidence": 0.95 },
        "production": { "value": true, "confidence": 0.85 }
      },
      "remediation": {
        "priority": { "priority": "P0", "action": "Fix immediately", "sla": "7 days" },
        "approach": "Use parameterized queries"
      }
    }
  ],
  "summary": {
    "totalFindings": 15,
    "countsBySeverity": { "critical": 2, "high": 5, "medium": 6, "low": 2 },
    "prs": {
      "overallScore": 72,
      "distribution": { "P0": 2, "P1": 5, "P2": 6, "P3": 2 },
      "topRiskFiles": ["controllers/user.js"]
    }
  }
}
```

## Testing

```bash
# Run all tests
npm test

# Run with coverage
npm run test:coverage
```

Test suite: 550+ tests, ~72% coverage. OWASP Benchmark v1.2 validation achieved **90.39% TPR** across 2,740 Java test cases.

## Configuration

### Scanner Configuration
Edit `config/scanner.config.json`:

```json
{
  "semgrepBinary": "semgrep",
  "rulesPath": "./rules",
  "runCustomScanner": true,
  "defaultContext": {
    "internetFacing": false,
    "production": false
  }
}
```

### Custom Semgrep Rules
Add custom rules to `rules/` in YAML format. The default rulesets are `p/owasp-top-ten` and `p/security-audit`.

## Architecture

```
┌──────────────┐     ┌──────────────────────────────┐     ┌──────────────────────┐
│   API Layer  │────▶│         Scan Engines          │────▶│  Context Inference   │
└──────────────┘     └──────────────────────────────┘     └──────────────────────┘
                        │          │           │                       │
                   ┌────▼───┐ ┌───▼──┐ ┌─────▼────┐      ┌──────────▼──────────┐
                   │Semgrep │ │ OSV  │ │Puppeteer │      │  Risk Pipeline       │
                   │  SAST  │ │ SCA  │ │   DAST   │      │  BTS→CRS→BPS→FARS   │
                   └────────┘ └──────┘ └──────────┘      │        →PRS          │
                   ┌─────────────────┐                    └──────────────────────┘
                   │  Custom Babel   │
                   │   AST Scanner   │
                   └─────────────────┘
```

**Privacy-by-Design:** All scan operations are stateless. Submitted code is held in ephemeral tmpfs memory only for the duration of the scan and is securely wiped on completion. No code or findings are persisted server-side.

## Troubleshooting

### Semgrep Not Found
If you see "Semgrep not found":
1. Install via pip: `pip install semgrep`
2. The tool will automatically fall back to the custom Babel AST scanner

### OWASP Benchmark Mode
When running against the OWASP Benchmark, disable path-based filtering — the default patterns (matching `test`/`example`) will otherwise filter all benchmark files.

### Large Codebases
- Use path filtering in the scan request to limit scope
- Adjust `maxFilesPerScan` in config
- Consider scanning modules separately for repositories >50K LOC

## License

Proprietary — Neperia Group
