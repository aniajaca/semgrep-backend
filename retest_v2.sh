#!/bin/bash
# ============================================================
# NEPERIA SCANNER RETEST - February 2026 (FIXED)
# Run from your semgreg-backend-local directory
# ============================================================

BASE_URL="http://localhost:3000"

mkdir -p retest_results_feb2026
mkdir -p /tmp/neperia_test_files

echo "============================================"
echo "STEP 1: Creating test files on disk"
echo "============================================"

cat > /tmp/neperia_test_files/production_api_download.js << 'EOF'
const express = require("express");
const router = express.Router();
const path = require("path");
const fs = require("fs");
router.get("/api/v1/files/:filename", async (req, res) => {
  const baseDir = "/data/user_documents";
  const filePath = path.join(baseDir, req.params.filename);
  if (fs.existsSync(filePath)) { res.sendFile(filePath); }
  else { res.status(404).json({ error: "File not found" }); }
});
router.post("/api/v1/download", async (req, res) => {
  const { folder, file } = req.body;
  const downloadPath = path.resolve("/uploads", folder, file);
  res.download(downloadPath);
});
router.get("/api/v1/users/:id/photo", async (req, res) => {
  const photoName = req.query.name;
  const photoPath = path.join("/data/photos", photoName);
  res.sendFile(photoPath);
});
module.exports = router;
EOF

cat > /tmp/neperia_test_files/internal_admin_logs.js << 'EOF'
const express = require("express");
const router = express.Router();
const path = require("path");
const fs = require("fs");
router.get("/internal/logs/:file", async (req, res) => {
  const logDir = "/var/log/application";
  const logPath = path.join(logDir, req.params.file);
  const content = fs.readFileSync(logPath, "utf8");
  res.json({ content });
});
router.get("/admin/config/:name", async (req, res) => {
  const configPath = path.resolve("/etc/app", req.params.name);
  res.sendFile(configPath);
});
module.exports = router;
EOF

cat > /tmp/neperia_test_files/dev_file_reader.js << 'EOF'
const path = require("path");
const fs = require("fs");
function loadTestFixture(req) {
  const fixtureName = req.params.fixture || "default";
  const fixturePath = path.join(__dirname, "fixtures", fixtureName);
  return fs.readFileSync(fixturePath, "utf8");
}
function browseDevFiles(req) {
  const dir = req.query.dir || ".";
  const targetPath = path.resolve("./test_data", dir);
  return fs.readdirSync(targetPath);
}
function readMockData(req) {
  const mockFile = path.join("./mocks", req.body.filename);
  return JSON.parse(fs.readFileSync(mockFile));
}
function loadSnapshot(req) {
  const snapshotPath = path.join("./snapshots", req.query.name);
  return fs.readFileSync(snapshotPath);
}
module.exports = { loadTestFixture, browseDevFiles, readMockData, loadSnapshot };
EOF

cat > /tmp/neperia_test_files/production_api_backup.js << 'EOF'
const express = require("express");
const router = express.Router();
const { exec } = require("child_process");
router.post("/api/v1/backup", async (req, res) => {
  const filename = req.body.filename;
  const backupPath = req.body.path || "/backups";
  const command = "tar -czf " + backupPath + "/" + filename + ".tar.gz /data/user_profiles";
  exec(command, (error, stdout, stderr) => {
    if (error) { res.status(500).json({ error: error.message }); }
    else { res.json({ success: true, backup: filename, message: "User data backup created" }); }
  });
});
module.exports = router;
EOF

cat > /tmp/neperia_test_files/internal_admin_maintenance.js << 'EOF'
const express = require("express");
const router = express.Router();
const { exec } = require("child_process");
router.post("/internal/admin/cleanup", async (req, res) => {
  const directory = req.body.directory;
  const command = "find /tmp/" + directory + " -type f -mtime +7 -delete";
  exec(command, (error, stdout, stderr) => {
    if (error) { res.status(500).json({ error: error.message }); }
    else { res.json({ success: true, cleaned: directory }); }
  });
});
module.exports = router;
EOF

cat > /tmp/neperia_test_files/dev_git_helper.js << 'EOF'
const { exec } = require("child_process");
function runGitCommand(req) {
  const branch = req.body.branch || "main";
  const command = "git checkout " + branch;
  exec(command, (error, stdout, stderr) => {
    if (error) { console.error("Git error:", error.message); }
    else { console.log("Switched to:", branch); }
  });
}
const mockReq = { body: { branch: process.argv[2] || "main" } };
runGitCommand(mockReq);
module.exports = { runGitCommand };
EOF

echo "Created 6 test files in /tmp/neperia_test_files/"
ls -la /tmp/neperia_test_files/
echo ""

echo "============================================"
echo "STEP 2: Health check"
echo "============================================"
curl -s "$BASE_URL/health" | python3 -m json.tool
echo ""

echo "============================================"
echo "STEP 3: Scanning"
echo "============================================"

FILES=(
  "production_api_download.js:pathtraver_file1_internet_prod_pii"
  "internal_admin_logs.js:pathtraver_file2_internal_prod"
  "dev_file_reader.js:pathtraver_file3_dev"
  "production_api_backup.js:cmdinj_file1_internet_prod_pii"
  "internal_admin_maintenance.js:cmdinj_file2_internal_prod"
  "dev_git_helper.js:cmdinj_file3_dev"
)

for entry in "${FILES[@]}"; do
  IFS=":" read -r filename output <<< "$entry"
  echo ""
  echo "--- Scanning: $filename ---"
  curl -s -X POST "$BASE_URL/scan-code" \
    -H "Content-Type: application/json" \
    -d "{\"path\": \"/tmp/neperia_test_files/$filename\", \"language\": \"javascript\"}" \
    > "retest_results_feb2026/${output}.json" 2>&1
  if [ -s "retest_results_feb2026/${output}.json" ]; then
    echo "  saved"
  else
    echo "  EMPTY - check server"
  fi
done

echo ""
echo "============================================"
echo "STEP 4: Results"
echo "============================================"

echo ""
echo "--- PATH TRAVERSAL ---"
for f in retest_results_feb2026/pathtraver_*.json; do
  echo ""
  echo "=== $(basename $f) ==="
  python3 -c "
import json
try:
    with open('$f') as fh:
        d = json.load(fh)
    if d.get('status') == 'error':
        print('  ERROR:', d.get('message','unknown'))
    else:
        findings = d.get('findings', [])
        print(f'  Findings: {len(findings)}')
        for i, finding in enumerate(findings):
            ctx = finding.get('context', {})
            print(f'  #{i+1}: CRS={finding.get(\"crs\",\"?\")}, Pri={finding.get(\"priority\",{}).get(\"priority\",\"?\")}, Ctx={ctx}')
        o = d.get('overallRisk', {})
        if o:
            s = o.get('score', {})
            p = o.get('priority', {})
            print(f'  FILE: raw={s.get(\"raw\",\"?\")}, mult={s.get(\"multiplier\",\"?\")}, final={s.get(\"final\",\"?\")}, pri={p.get(\"level\",\"?\")}')
except Exception as e:
    print(f'  PARSE ERROR: {e}')
"
done

echo ""
echo "--- COMMAND INJECTION ---"
for f in retest_results_feb2026/cmdinj_*.json; do
  echo ""
  echo "=== $(basename $f) ==="
  python3 -c "
import json
try:
    with open('$f') as fh:
        d = json.load(fh)
    if d.get('status') == 'error':
        print('  ERROR:', d.get('message','unknown'))
    else:
        findings = d.get('findings', [])
        print(f'  Findings: {len(findings)}')
        for i, finding in enumerate(findings):
            ctx = finding.get('context', {})
            print(f'  #{i+1}: BTS={finding.get(\"bts\",\"?\")}, CRS={finding.get(\"crs\",\"?\")}, Pri={finding.get(\"priority\",{}).get(\"priority\",\"?\")}, Ctx={ctx}')
        o = d.get('overallRisk', {})
        if o:
            s = o.get('score', {})
            p = o.get('priority', {})
            print(f'  FILE: raw={s.get(\"raw\",\"?\")}, mult={s.get(\"multiplier\",\"?\")}, final={s.get(\"final\",\"?\")}, pri={p.get(\"level\",\"?\")}')
except Exception as e:
    print(f'  PARSE ERROR: {e}')
"
done

echo ""
echo "============================================"
echo "OLD RESULTS (compare against these):"
echo "============================================"
echo "PathTrav: F1=100/P0(x2.73) F2=78/P1(x1.30) F3=53/P2(x1.00)"
echo "CmdInj finding: F1=CRS100/P0 F2=CRS98/P0 F3=CRS90/P0"
echo "CmdInj file:    F1=68.2/P1   F2=32.5/P3  F3=25.0/P3"
echo ""
echo "DONE - paste everything above to Claude"
