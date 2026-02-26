#!/bin/bash
# ============================================================
# NEPERIA SCANNER RETEST - February 2026
# Run this from your semgrep-backend directory
# ============================================================

# STEP 0: Set your scanner URL
# Uncomment the one you're using:
BASE_URL="http://localhost:3000/v1"
# BASE_URL="https://scanner.neperia.dev/api/v1"

# If you need auth token:
# TOKEN="your-jwt-token"
# AUTH_HEADER="-H \"Authorization: Bearer $TOKEN\""

# Output directory
mkdir -p retest_results_feb2026

echo "============================================"
echo "STEP 1: Health check"
echo "============================================"
curl -s "$BASE_URL/health" | python3 -m json.tool
echo ""

echo "============================================"
echo "STEP 2: Check version"  
echo "============================================"
curl -s "$BASE_URL/version" | python3 -m json.tool
echo ""

# ============================================================
# EXPERIMENT 4A: PATH TRAVERSAL (CWE-22) - 3 contexts
# ============================================================

echo "============================================"
echo "EXPERIMENT 4A: Path Traversal - File 1 (Internet+Prod+PII)"
echo "============================================"

curl -s -X POST "$BASE_URL/scan-code" \
  -H "Content-Type: application/json" \
  -d '{
  "code": "// Production API - Internet-facing file download\n// Context: internet_facing=TRUE, production=TRUE, handles_pii=TRUE\n\nconst express = require(\"express\");\nconst router = express.Router();\nconst path = require(\"path\");\nconst fs = require(\"fs\");\n\n// Public API endpoint - serves user documents\nrouter.get(\"/api/v1/files/:filename\", async (req, res) => {\n  const baseDir = \"/data/user_documents\";\n  \n  // VULNERABILITY: Path Traversal (CWE-22)\n  const filePath = path.join(baseDir, req.params.filename);\n  \n  if (fs.existsSync(filePath)) {\n    res.sendFile(filePath);\n  } else {\n    res.status(404).json({ error: \"File not found\" });\n  }\n});\n\n// Another endpoint with same vulnerability\nrouter.post(\"/api/v1/download\", async (req, res) => {\n  const { folder, file } = req.body;\n  \n  // VULNERABILITY: Path Traversal (CWE-22)\n  const downloadPath = path.resolve(\"/uploads\", folder, file);\n  res.download(downloadPath);\n});\n\n// User profile photo endpoint\nrouter.get(\"/api/v1/users/:id/photo\", async (req, res) => {\n  const photoName = req.query.name;\n  \n  // VULNERABILITY: Path Traversal (CWE-22)\n  const photoPath = path.join(\"/data/photos\", photoName);\n  res.sendFile(photoPath);\n});\n\nmodule.exports = router;",
  "filename": "production_api_download.js",
  "language": "javascript"
}' | python3 -m json.tool > retest_results_feb2026/pathtraver_file1_internet_prod_pii.json

echo "Saved to retest_results_feb2026/pathtraver_file1_internet_prod_pii.json"
echo ""

echo "============================================"
echo "EXPERIMENT 4A: Path Traversal - File 2 (Internal+Prod)"
echo "============================================"

curl -s -X POST "$BASE_URL/scan-code" \
  -H "Content-Type: application/json" \
  -d '{
  "code": "// Internal Admin Tool - Behind corporate SSO\n// Context: internet_facing=FALSE, production=TRUE, handles_pii=FALSE\n\nconst express = require(\"express\");\nconst router = express.Router();\nconst path = require(\"path\");\nconst fs = require(\"fs\");\n\n// Internal log viewer - requires SSO authentication\nrouter.get(\"/internal/logs/:file\", async (req, res) => {\n  const logDir = \"/var/log/application\";\n  \n  // VULNERABILITY: Path Traversal (CWE-22)\n  const logPath = path.join(logDir, req.params.file);\n  \n  const content = fs.readFileSync(logPath, \"utf8\");\n  res.json({ content });\n});\n\n// Admin config viewer\nrouter.get(\"/admin/config/:name\", async (req, res) => {\n  // VULNERABILITY: Path Traversal (CWE-22)\n  const configPath = path.resolve(\"/etc/app\", req.params.name);\n  res.sendFile(configPath);\n});\n\nmodule.exports = router;",
  "filename": "internal_admin_logs.js",
  "language": "javascript"
}' | python3 -m json.tool > retest_results_feb2026/pathtraver_file2_internal_prod.json

echo "Saved to retest_results_feb2026/pathtraver_file2_internal_prod.json"
echo ""

echo "============================================"
echo "EXPERIMENT 4A: Path Traversal - File 3 (Dev/Test)"
echo "============================================"

curl -s -X POST "$BASE_URL/scan-code" \
  -H "Content-Type: application/json" \
  -d '{
  "code": "// Development utility - Local testing only\n// Context: internet_facing=FALSE, production=FALSE, handles_pii=FALSE\n\nconst path = require(\"path\");\nconst fs = require(\"fs\");\n\n// Test fixture loader - reads mock data files\nfunction loadTestFixture(req) {\n  const fixtureName = req.params.fixture || \"default\";\n  \n  // VULNERABILITY: Path Traversal (CWE-22)\n  const fixturePath = path.join(__dirname, \"fixtures\", fixtureName);\n  return fs.readFileSync(fixturePath, \"utf8\");\n}\n\n// Dev file browser\nfunction browseDevFiles(req) {\n  const dir = req.query.dir || \".\";\n  \n  // VULNERABILITY: Path Traversal (CWE-22)\n  const targetPath = path.resolve(\"./test_data\", dir);\n  return fs.readdirSync(targetPath);\n}\n\n// Mock data reader\nfunction readMockData(req) {\n  // VULNERABILITY: Path Traversal (CWE-22)\n  const mockFile = path.join(\"./mocks\", req.body.filename);\n  return JSON.parse(fs.readFileSync(mockFile));\n}\n\n// Another dev helper\nfunction loadSnapshot(req) {\n  // VULNERABILITY: Path Traversal (CWE-22)\n  const snapshotPath = path.join(\"./snapshots\", req.query.name);\n  return fs.readFileSync(snapshotPath);\n}\n\nmodule.exports = { loadTestFixture, browseDevFiles, readMockData, loadSnapshot };",
  "filename": "dev_file_reader.js",
  "language": "javascript"
}' | python3 -m json.tool > retest_results_feb2026/pathtraver_file3_dev.json

echo "Saved to retest_results_feb2026/pathtraver_file3_dev.json"
echo ""

# ============================================================
# EXPERIMENT 4C: COMMAND INJECTION (CWE-78) - 3 contexts
# ============================================================

echo "============================================"
echo "EXPERIMENT 4C: Command Injection - File 1 (Internet+Prod+PII)"
echo "============================================"

curl -s -X POST "$BASE_URL/scan-code" \
  -H "Content-Type: application/json" \
  -d '{
  "code": "// Production API - Internet-facing backup endpoint\n// Context: internet_facing=TRUE, production=TRUE, handles_pii=TRUE\n\nconst express = require(\"express\");\nconst router = express.Router();\nconst { exec } = require(\"child_process\");\n\n// Public API endpoint - authenticated users can trigger backups\nrouter.post(\"/api/v1/backup\", async (req, res) => {\n  const filename = req.body.filename;\n  const backupPath = req.body.path || \"/backups\";\n  \n  // VULNERABILITY: Command Injection (CWE-78)\n  const command = \"tar -czf \" + backupPath + \"/\" + filename + \".tar.gz /data/user_profiles\";\n  \n  exec(command, (error, stdout, stderr) => {\n    if (error) {\n      res.status(500).json({ error: error.message });\n    } else {\n      res.json({ \n        success: true, \n        backup: filename,\n        message: \"User data backup created\"\n      });\n    }\n  });\n});\n\nmodule.exports = router;",
  "filename": "production_api_backup.js",
  "language": "javascript"
}' | python3 -m json.tool > retest_results_feb2026/cmdinj_file1_internet_prod_pii.json

echo "Saved to retest_results_feb2026/cmdinj_file1_internet_prod_pii.json"
echo ""

echo "============================================"
echo "EXPERIMENT 4C: Command Injection - File 2 (Internal+Prod)"
echo "============================================"

curl -s -X POST "$BASE_URL/scan-code" \
  -H "Content-Type: application/json" \
  -d '{
  "code": "// Internal Admin Tool - VPN access only\n// Context: internet_facing=FALSE, production=TRUE, handles_pii=FALSE\n\nconst express = require(\"express\");\nconst router = express.Router();\nconst { exec } = require(\"child_process\");\n\n// Admin cleanup endpoint - requires VPN + admin auth\nrouter.post(\"/internal/admin/cleanup\", async (req, res) => {\n  const directory = req.body.directory;\n  \n  // VULNERABILITY: Command Injection (CWE-78)\n  const command = \"find /tmp/\" + directory + \" -type f -mtime +7 -delete\";\n  \n  exec(command, (error, stdout, stderr) => {\n    if (error) {\n      res.status(500).json({ error: error.message });\n    } else {\n      res.json({ success: true, cleaned: directory });\n    }\n  });\n});\n\nmodule.exports = router;",
  "filename": "internal_admin_maintenance.js",
  "language": "javascript"
}' | python3 -m json.tool > retest_results_feb2026/cmdinj_file2_internal_prod.json

echo "Saved to retest_results_feb2026/cmdinj_file2_internal_prod.json"
echo ""

echo "============================================"
echo "EXPERIMENT 4C: Command Injection - File 3 (Dev)"
echo "============================================"

curl -s -X POST "$BASE_URL/scan-code" \
  -H "Content-Type: application/json" \
  -d '{
  "code": "// Development Script - Local environment only\n// Context: internet_facing=FALSE, production=FALSE, handles_pii=FALSE\n\nconst { exec } = require(\"child_process\");\n\n// Dev helper - wraps git commands for convenience\nfunction runGitCommand(req) {\n  const branch = req.body.branch || \"main\";\n  \n  // VULNERABILITY: Command Injection (CWE-78)\n  const command = \"git checkout \" + branch;\n  \n  exec(command, (error, stdout, stderr) => {\n    if (error) {\n      console.error(\"Git error:\", error.message);\n    } else {\n      console.log(\"Switched to:\", branch);\n    }\n  });\n}\n\n// Simulated request for local dev\nconst mockReq = { body: { branch: process.argv[2] || \"main\" } };\nrunGitCommand(mockReq);\n\nmodule.exports = { runGitCommand };",
  "filename": "dev_git_helper.js",
  "language": "javascript"
}' | python3 -m json.tool > retest_results_feb2026/cmdinj_file3_dev.json

echo "Saved to retest_results_feb2026/cmdinj_file3_dev.json"
echo ""

# ============================================================
# QUICK COMPARISON
# ============================================================

echo "============================================"
echo "QUICK RESULTS EXTRACTION"
echo "============================================"

echo ""
echo "--- PATH TRAVERSAL ---"
for f in retest_results_feb2026/pathtraver_*.json; do
  echo ""
  echo "=== $(basename $f) ==="
  python3 -c "
import json, sys
try:
    with open('$f') as fh:
        d = json.load(fh)
    # Finding-level
    if 'findings' in d and len(d['findings']) > 0:
        for i, f in enumerate(d['findings']):
            print(f'  Finding {i+1}: CRS={f.get(\"crs\",\"?\")}, Priority={f.get(\"priority\",{}).get(\"priority\",\"?\")}, Context={f.get(\"context\",{})}')
    # File-level
    if 'overallRisk' in d:
        score = d['overallRisk'].get('score', {})
        priority = d['overallRisk'].get('priority', {})
        print(f'  File-level: raw={score.get(\"raw\",\"?\")}, mult={score.get(\"multiplier\",\"?\")}, final={score.get(\"final\",\"?\")}, priority={priority.get(\"level\",\"?\")}')
    if 'summary' in d:
        print(f'  Total findings: {d[\"summary\"].get(\"totalFindings\",\"?\")}')
except Exception as e:
    print(f'  ERROR: {e}')
" 2>&1
done

echo ""
echo "--- COMMAND INJECTION ---"
for f in retest_results_feb2026/cmdinj_*.json; do
  echo ""
  echo "=== $(basename $f) ==="
  python3 -c "
import json, sys
try:
    with open('$f') as fh:
        d = json.load(fh)
    # Finding-level
    if 'findings' in d and len(d['findings']) > 0:
        for i, f in enumerate(d['findings']):
            print(f'  Finding {i+1}: BTS={f.get(\"bts\",\"?\")}, CRS={f.get(\"crs\",\"?\")}, Priority={f.get(\"priority\",{}).get(\"priority\",\"?\")}, Context={f.get(\"context\",{})}')
    # File-level
    if 'overallRisk' in d:
        score = d['overallRisk'].get('score', {})
        priority = d['overallRisk'].get('priority', {})
        print(f'  File-level: raw={score.get(\"raw\",\"?\")}, mult={score.get(\"multiplier\",\"?\")}, final={score.get(\"final\",\"?\")}, priority={priority.get(\"level\",\"?\")}')
    if 'summary' in d:
        print(f'  Total findings: {d[\"summary\"].get(\"totalFindings\",\"?\")}')
except Exception as e:
    print(f'  ERROR: {e}')
" 2>&1
done

echo ""
echo "============================================"
echo "DONE! Check retest_results_feb2026/ for full JSON outputs"
echo "============================================"
echo ""
echo "OLD RESULTS (for comparison):"
echo "  Path Trav: File1=100/P0(mult 2.73), File2=78/P1(mult 1.30), File3=53/P2(mult 1.00)"
echo "  Cmd Inj finding-level: File1=CRS100/P0, File2=CRS98/P0, File3=CRS90/P0"
echo "  Cmd Inj file-level: File1=68.2/P1, File2=32.5/P3, File3=25.0/P3"