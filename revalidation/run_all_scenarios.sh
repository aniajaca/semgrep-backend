#!/bin/bash
# =============================================================================
# EXPERT VALIDATION — REVALIDATION SCRIPT (Post-Fix #6)
# macOS-compatible (bash 3.2+, no scipy needed)
# =============================================================================
# Usage:
#   1. Start server: node src/server.js
#   2. Run: chmod +x revalidation/run_all_scenarios.sh && ./revalidation/run_all_scenarios.sh
# =============================================================================

BASE="${SCANNER_URL:-http://localhost:3000}"
OUT_DIR="revalidation/results"
mkdir -p "$OUT_DIR"

green() { printf "\033[32m  ✓ %s\033[0m\n" "$1"; }
red()   { printf "\033[31m  ✗ %s\033[0m\n" "$1"; }
blue()  { printf "\033[34m\n━━━ %s ━━━\033[0m\n" "$1"; }

# A1: Internet-facing production + PII (expect P0)
A1_CODE='const express = require("express");
const path = require("path");
const app = express();

app.get("/api/files/:name", (req, res) => {
  const filePath = path.join("/uploads", req.params.name);
  res.sendFile(filePath);
});

app.get("/api/users/:id", (req, res) => {
  res.json({ email: req.query.email, firstName: req.query.name });
});

app.listen(3000);'

# A2: Internal admin + requireAuth + port 8080 (expect P1)
A2_CODE='const express = require("express");
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

app.listen(8080);'

# A3: Test helper (expect P3)
A3_CODE='const path = require("path");
const fs = require("fs");

function loadFixture(name) {
  const fixturePath = path.join(__dirname, "test/fixtures", name);
  return fs.readFileSync(fixturePath, "utf8");
}

module.exports = { loadFixture };'

# B1: Internet-facing prod cmd injection (expect P0)
B1_CODE='const express = require("express");
const { exec } = require("child_process");
const app = express();

app.post("/api/deploy", (req, res) => {
  const branch = req.body.branch;
  exec("git checkout " + branch, (error, stdout) => {
    res.json({ output: stdout, email: req.body.userEmail });
  });
});

app.listen(3000);'

# B2: Internal admin cmd injection + requireAuth + port 8080 (expect P1)
B2_CODE='const express = require("express");
const { exec } = require("child_process");
const app = express();

function requireAuth(req, res, next) {
  const token = req.headers["x-admin-token"];
  if (token && token === process.env.ADMIN_TOKEN) {
    next();
  } else {
    res.status(403).json({ error: "Forbidden" });
  }
}

app.use(requireAuth);

app.post("/admin/maintenance/restart", (req, res) => {
  const service = req.body.service;
  exec("systemctl restart " + service, (error, stdout) => {
    res.json({ status: "restarted", output: stdout });
  });
});

app.listen(8080);'

# B3: Dev script (expect P2/P3 boundary)
B3_CODE='const { exec } = require("child_process");

function gitStatus(repoPath) {
  exec("git -C " + repoPath + " status", (error, stdout) => {
    console.log(stdout);
  });
}

if (require.main === module) {
  gitStatus(process.argv[2] || ".");
}'

# =============================================================================
run_scenario() {
  local NAME=$1
  local CODE=$2
  local PROFILE=${3:-default}
  local FILENAME=${4:-code.js}
  
  blue "Scenario $NAME (profile: $PROFILE)"
  
  CODE_JSON=$(echo "$CODE" | jq -Rs .)
  
  RESULT=$(curl -s -X POST "$BASE/scan-code" \
    -H "Content-Type: application/json" \
    -d "{
      \"code\": $CODE_JSON,
      \"language\": \"javascript\",
      \"filename\": \"$FILENAME\",
      \"profileId\": \"$PROFILE\"
    }")
  
  echo "$RESULT" | jq . > "$OUT_DIR/${NAME}.json" 2>/dev/null
  
  if echo "$RESULT" | jq -e '.findings[0]' > /dev/null 2>&1; then
    CRS=$(echo "$RESULT" | jq '.findings[0].crs')
    PRIORITY=$(echo "$RESULT" | jq -r '.findings[0].priority.priority')
    FACTORS=$(echo "$RESULT" | jq -c '.findings[0].appliedFactors // []')
    CONTEXT=$(echo "$RESULT" | jq -c '.findings[0].context // {}')
    
    green "$NAME: CRS=$CRS, Priority=$PRIORITY, Factors=$FACTORS"
    echo "    Context: $CONTEXT"
  else
    red "$NAME: No findings or error"
  fi
}

# =============================================================================
echo ""
echo "============================================"
echo " EXPERT VALIDATION — REVALIDATION"
echo " Server: $BASE"
echo "============================================"

HEALTH=$(curl -s "$BASE/health" 2>/dev/null)
if [ $? -ne 0 ] || [ -z "$HEALTH" ]; then
  red "Server not reachable at $BASE"
  exit 1
fi
green "Server healthy"

run_scenario "A1" "$A1_CODE" "default" "publicServer.js"
run_scenario "A2" "$A2_CODE" "default" "internalAdmin.js"
run_scenario "A3" "$A3_CODE" "default" "test/helpers/fixtureLoader.js"
run_scenario "B1" "$B1_CODE" "default" "deployService.js"
run_scenario "B2" "$B2_CODE" "default" "adminMaintenance.js"
run_scenario "B3" "$B3_CODE" "default" "scripts/dev/gitHelper.js"
run_scenario "C1" "$A1_CODE" "compliance" "publicServer.js"
run_scenario "C2" "$A1_CODE" "default" "publicServer.js"
run_scenario "C3" "$A1_CODE" "startup" "publicServer.js"

# =============================================================================
blue "RESULTS SUMMARY"

echo ""
printf "%-10s %-8s %-10s %-10s %-8s\n" "Scenario" "CRS" "Scanner" "Tom" "Match"
echo "────────────────────────────────────────────────"

# Tom's answers (macOS bash 3.x compatible - no associative arrays)
TOM_A1="P0"; TOM_A2="P1"; TOM_A3="P3"
TOM_B1="P0"; TOM_B2="P1"; TOM_B3="P3"
TOM_C1="P0"; TOM_C2="P0"; TOM_C3="P0"

MATCHES=0

for SCENARIO in A1 A2 A3 B1 B2 B3 C1 C2 C3; do
  FILE="$OUT_DIR/${SCENARIO}.json"
  eval "TOM=\$TOM_${SCENARIO}"
  
  if [ -f "$FILE" ] && jq -e '.findings[0]' "$FILE" > /dev/null 2>&1; then
    CRS=$(jq '.findings[0].crs' "$FILE")
    PRI=$(jq -r '.findings[0].priority.priority' "$FILE")
    
    if [ "$PRI" = "$TOM" ]; then
      MATCH="✅"
      MATCHES=$((MATCHES + 1))
    else
      MATCH="❌"
    fi
    
    printf "%-10s %-8s %-10s %-10s %-8s\n" "$SCENARIO" "$CRS" "$PRI" "$TOM" "$MATCH"
  else
    printf "%-10s %-8s %-10s %-10s %-8s\n" "$SCENARIO" "ERR" "-" "$TOM" "❌"
  fi
done

echo ""
echo "Exact match: $MATCHES/9"

# =============================================================================
blue "COMPUTING SPEARMAN ρ"

python3 - <<'PYEOF'
import json, os, math

results_dir = "revalidation/results"
priority_map = {"P0": 1, "P1": 2, "P2": 3, "P3": 4}
tom = {"A1":"P0","A2":"P1","A3":"P3","B1":"P0","B2":"P1","B3":"P3","C1":"P0","C2":"P0","C3":"P0"}

sv, tv = [], []
for s in ["A1","A2","A3","B1","B2","B3","C1","C2","C3"]:
    fp = os.path.join(results_dir, f"{s}.json")
    if not os.path.exists(fp): continue
    with open(fp) as f: data = json.load(f)
    if not data.get("findings"): continue
    pri = data["findings"][0].get("priority",{}).get("priority","P3")
    sv.append(priority_map.get(pri,4))
    tv.append(priority_map.get(tom[s],4))
    m = "✅" if pri==tom[s] else "❌"
    print(f"  {s}: Scanner={pri}, Tom={tom[s]} {m}")

def rank(vals):
    n=len(vals); idx=sorted(range(n),key=lambda i:vals[i]); r=[0.0]*n
    i=0
    while i<n:
        j=i
        while j<n-1 and vals[idx[j+1]]==vals[idx[j]]: j+=1
        avg=(i+j)/2.0+1
        for k in range(i,j+1): r[idx[k]]=avg
        i=j+1
    return r

if len(sv)>=3:
    n=len(sv); sr=rank(sv); tr=rank(tv)
    d2=sum((sr[i]-tr[i])**2 for i in range(n))
    rho=1-(6*d2)/(n*(n**2-1))
    if abs(rho)<1: t=rho*math.sqrt((n-2)/(1-rho**2))
    else: t=float('inf')
    print(f"\n  Spearman ρ = {rho:.4f}")
    print(f"  Target ρ ≥ 0.90: {'✅ MET' if rho>=0.90 else '❌ NOT MET'}")
PYEOF

echo ""
echo "Results saved to: $OUT_DIR/"
echo ""
echo "If A2/B2 still show P0, run the diagnostic:"
echo "  node revalidation/diagnose_a2.js"