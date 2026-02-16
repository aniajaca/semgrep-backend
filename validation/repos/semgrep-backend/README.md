# Neperia Vulnerability Assessment Tool

A security-focused vulnerability assessment tool that combines static application security testing (SAST) and software composition analysis (SCA) with contextual risk scoring.

## Features

- **Hybrid SAST**: Uses Semgrep as primary engine with custom fallback scanner
- **Dependency Analysis**: Scans for vulnerable packages and outdated dependencies
- **Contextual Risk Scoring**: Adjusts severity based on environmental factors (production, internet-facing, etc.)
- **Unified Reporting**: Combines code and dependency findings into prioritized remediation lists
- **Offline Operation**: Works without internet access using cached vulnerability data

## Installation

### Prerequisites

1. **Node.js** (v16 or higher)
```bash
node --version  # Should be >= 16.0.0
```

2. **Semgrep** (recommended for full coverage)
```bash
# Install via pip (recommended)
pip install semgrep

# Or via npm
npm install -g @returntocorp/semgrep

# Verify installation
semgrep --version
```

### Setup

1. Clone the repository
```bash
git clone <repository-url>
cd neperia-assessment
```

2. Install dependencies
```bash
npm install
```

3. Configure settings (optional)
Edit `config/scanner.config.json` to adjust:
- Default context flags
- Severity mappings
- Scanning limits

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

### Environmental Context Flags

Adjust risk scores based on deployment context:

- `internetFacing`: Component exposed to internet (+0.6 score)
- `production`: Running in production environment (+0.4 score)
- `handlesPI`: Processes personal information (+0.4 score)
- `exploitAvailable`: Known exploit exists (+0.6 score)
- `legacyCode`: Legacy system with technical debt (+0.2 score)

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
      "cvssBase": 9.0,
      "adjustedScore": 10.0,
      "adjustedSeverity": "critical",
      "priority": "P0",
      "remediation": {
        "priority": {
          "priority": "P0",
          "action": "Fix immediately",
          "sla": "4 hours"
        },
        "approach": "Use parameterized queries",
        "validation": "Test with injection payloads"
      }
    }
  ],
  "summary": {
    "totalFindings": 15,
    "countsBySeverity": {
      "critical": 2,
      "high": 5,
      "medium": 6,
      "low": 2
    },
    "top5": [...],
    "adjustedRiskIndex": 72.5
  }
}
```

## CLI Scripts

### Run Code Scan
```bash
npm run scan:code -- --path ./target --context production,internet-facing
```

### Run Dependency Scan
```bash
npm run scan:deps -- --path ./target
```

## Testing

```bash
# Run all tests
npm test

# Run with coverage
npm run test:coverage

# Watch mode for development
npm run test:watch
```

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
Add custom rules to `rules/` directory in YAML format. See `rules/javascript-security.yml` for examples.

## Architecture

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   API Layer  │────▶│   Scanners   │────▶│ Risk Scoring │
└──────────────┘     └──────────────┘     └──────────────┘
                            │                      │
                     ┌──────▼──────┐      ┌───────▼──────┐
                     │   Semgrep   │      │  Calculator  │
                     └─────────────┘      └──────────────┘
                            │                      │
                     ┌──────▼──────┐      ┌───────▼──────┐
                     │ Custom AST  │      │ Environmental│
                     └─────────────┘      │   Factors    │
                                          └──────────────┘
```

## Troubleshooting

### Semgrep Not Found
If you see "Semgrep not found" error:
1. Install Semgrep: `pip install semgrep`
2. Or adjust config to use custom scanner only
3. The tool will fallback to custom AST scanner automatically

### Large Codebases
For repositories with millions of lines:
- Use path filtering in scan request
- Adjust `maxFilesPerScan` in config
- Consider scanning modules separately

### Performance
- First scan may be slower due to parsing
- Subsequent scans use caching (5min TTL)
- Exclude test/build directories in config

## License

Proprietary - Neperia Group

## Support

For issues or questions, contact the development team.