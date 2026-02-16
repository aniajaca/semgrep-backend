#!/bin/bash
# =============================================================================
# NEPERIA SECURITY SCANNER - MODULAR DEMO SCRIPT
# =============================================================================
#
# HOW TO SET UP (one time only):
#   1. Open terminal, cd to your project root:
#        cd ~/path/to/semgreg-backend-local
#   2. Create the file:
#        nano demo.sh       (paste this whole script, save with Ctrl+X)
#   3. Make it executable:
#        chmod +x demo.sh
#
# HOW TO USE (every time):
#   1. Start your server in one terminal:
#        node src/server.js
#   2. In a second terminal:
#        ./demo.sh           ← runs ALL tests
#        ./demo.sh 5         ← runs only test 5
#        ./demo.sh 3 6       ← runs tests 3 through 6
#
# WHAT EACH TEST COVERS:
#   Test 1  - Health check         (is the server alive?)
#   Test 2  - Profile loading      (do all profiles exist and load?)
#   Test 3  - BTS scoring          (does scanning find vulns + assign base scores?)
#   Test 4  - CRS context scoring  (do context factors change scores?)
#   Test 5  - Profile comparison   (same vuln → different SLAs per profile?)
#   Test 6  - Priority bands       (P0/P1/P2/P3 correctly assigned?)
#   Test 7  - Risk aggregation     (overall project risk score computed?)
#   Test 8  - Provenance           (audit trail with profile hash recorded?)
#   Test 9  - Dependency scan      (SCA via OSV finds known-vulnerable packages?)
#   Test 10 - Contextual filter    (noise reduction: filtered vs raw count?)
#   Test 11 - Profile validation   (bad profile rejected, good profile accepted?)
#
# =============================================================================

BASE="http://localhost:3000"

# --- Pretty output helpers ---
green() { echo -e "\033[32m  ✓ $1\033[0m"; }
red()   { echo -e "\033[31m  ✗ $1\033[0m"; }
blue()  { echo -e "\033[34m\n━━━ $1 ━━━\033[0m"; }
dim()   { echo -e "\033[90m    $1\033[0m"; }


# =============================================================================
# VULNERABLE CODE SAMPLE (used by tests 3-8 and 10)
# =============================================================================
# This code has 4 intentional vulnerabilities:
#   1. SQL Injection (CWE-89)  — string interpolation in SQL query
#   2. Eval Injection (CWE-95) — eval() called on user input
#   3. Hardcoded Secret (CWE-798) — API key in source code
#   4. Weak Crypto (CWE-327)  — MD5 hash
#
# You can replace this with ANY code to test different scenarios.
# =============================================================================

VULN_CODE='const db = require("./db");
const express = require("express");
const app = express();

// SQL Injection - CWE-89
app.get("/api/users/:id", async (req, res) => {
  const query = `SELECT * FROM users WHERE id = ${req.params.id}`;
  const result = await db.query(query);
  res.json(result);
});

// Eval injection - CWE-95
app.post("/api/run", (req, res) => {
  const result = eval(req.body.expression);
  res.json({ result });
});

// Hardcoded secret - CWE-798
const API_KEY = "sk_live_abcdef1234567890abcdef";

// Weak crypto - CWE-327
const crypto = require("crypto");
const hash = crypto.createHash("md5").update("data").digest("hex");

app.listen(3001);'

# Pre-encode as JSON (reused by all scan tests)
CODE_JSON=$(echo "$VULN_CODE" | jq -Rs .)


# =============================================================================
# TEST 1: HEALTH CHECK
# =============================================================================
# Simply: is the server running and are all services ready?
# If this fails, nothing else will work.
# =============================================================================
test_1_health() {
  blue "TEST 1: Health Check"

  HEALTH=$(curl -s "$BASE/health")
  STATUS=$(echo "$HEALTH" | jq -r '.status')
  AST=$(echo "$HEALTH" | jq -r '.services.ast')
  SEMGREP=$(echo "$HEALTH" | jq -r '.services.semgrep')
  RISK=$(echo "$HEALTH" | jq -r '.services.riskCalculator')

  [ "$STATUS" = "healthy" ] && green "Server: healthy" || red "Server: $STATUS"
  [ "$AST" = "ready" ]      && green "AST engine: ready" || red "AST engine: not ready"
  [ "$RISK" = "ready" ]     && green "Risk calculator: ready" || red "Risk calculator: not ready"

  if [ "$SEMGREP" = "available" ]; then
    green "Semgrep: available"
  else
    dim "Semgrep: not installed (AST-only mode, still fine)"
  fi
}


# =============================================================================
# TEST 2: PROFILE SYSTEM
# =============================================================================
# Checks: do all profile JSON files load correctly?
# You should see: default, startup, enterprise, compliance (+ neperia-internal)
#
# WHY THIS MATTERS FOR THESIS:
# Profiles are how different organisations customise risk tolerance.
# If these don't load, the whole "configurable scoring" claim falls apart.
# =============================================================================
test_2_profiles() {
  blue "TEST 2: Profile System"

  PROFILES=$(curl -s "$BASE/profiles")
  COUNT=$(echo "$PROFILES" | jq '.profiles | length')
  NAMES=$(echo "$PROFILES" | jq -r '.profiles[].id' | tr '\n' ', ' | sed 's/,$//')

  [ "$COUNT" -ge 4 ] \
    && green "Found $COUNT profiles: $NAMES" \
    || red "Expected 4+ profiles, found $COUNT"

  for P in default startup enterprise compliance; do
    RESP=$(curl -s "$BASE/profiles/$P")
    NAME=$(echo "$RESP" | jq -r '.profile.name // .name // empty')
    if [ -n "$NAME" ]; then
      green "'$P' loads OK (name: $NAME)"
    else
      red "'$P' failed to load"
    fi
  done
}


# =============================================================================
# TEST 3: BTS — BASE TECHNICAL SEVERITY (Stage 1)
# =============================================================================
# What happens: Code goes into Semgrep/AST → raw findings come out →
#   each finding gets a BTS score (0-10 CVSS-like scale).
#
# What to look for:
#   - Findings detected (count > 0)
#   - Each finding has a .bts value
#   - Critical vulns should have BTS ~9.0, medium ~5.0
#
# This stage is profile-INDEPENDENT. Same BTS regardless of profile.
# =============================================================================
test_3_bts() {
  blue "TEST 3: Stage 1 — BTS (Base Technical Severity)"

  SCAN=$(curl -s -X POST "$BASE/scan-code" \
    -H "Content-Type: application/json" \
    -d "{
      \"code\": $CODE_JSON,
      \"language\": \"javascript\",
      \"profileId\": \"default\"
    }")

  COUNT=$(echo "$SCAN" | jq '.summary.totalFindings')
  ENGINE=$(echo "$SCAN" | jq -r '.engine')

  [ "$COUNT" -gt 0 ] \
    && green "Found $COUNT vulnerabilities (engine: $ENGINE)" \
    || red "No vulnerabilities found"

  echo ""
  echo "  Findings:"
  echo "$SCAN" | jq -r '.findings[] | "    \(.cwe) │ BTS: \(.bts) │ \(.severity) │ \(.message[0:60])"'
}


# =============================================================================
# TEST 4: CRS — CONTEXTUAL RISK SCORE (Stage 2)
# =============================================================================
# What happens: Same finding gets rescored based on WHERE it runs.
#   An SQL injection in an internet-facing production app handling PII
#   is far more dangerous than the same bug in an internal dev tool.
#
# How: We scan the SAME code twice:
#   1. Without context (bare scan)
#   2. With manualContext: internetFacing=true, production=true, handlesPI=true
#
# What to look for:
#   - CRS with context should be >= CRS without context
#   - .appliedFactors shows which multipliers kicked in
#
# THIS IS THE CORE THESIS INNOVATION. If CRS doesn't change with context,
# something is broken.
# =============================================================================
test_4_crs() {
  blue "TEST 4: Stage 2 — CRS (Context Changes Scores)"

  # Scan 1: no context
  BARE=$(curl -s -X POST "$BASE/scan-code" \
    -H "Content-Type: application/json" \
    -d "{
      \"code\": $CODE_JSON,
      \"language\": \"javascript\",
      \"profileId\": \"default\"
    }")

  # Scan 2: internet-facing production with PII
  CTX=$(curl -s -X POST "$BASE/scan-code" \
    -H "Content-Type: application/json" \
    -d "{
      \"code\": $CODE_JSON,
      \"language\": \"javascript\",
      \"profileId\": \"default\",
      \"manualContext\": {
        \"internetFacing\": true,
        \"production\": true,
        \"handlesPI\": true
      }
    }")

  CRS_BARE=$(echo "$BARE" | jq '[.findings[].crs] | max')
  CRS_CTX=$(echo "$CTX" | jq '[.findings[].crs] | max')
  FACTORS=$(echo "$CTX" | jq -r '.findings[0].appliedFactors // [] | join(", ")')

  echo ""
  echo "  Highest CRS without context: $CRS_BARE"
  echo "  Highest CRS with context:    $CRS_CTX"
  echo ""

  [ -n "$FACTORS" ] && [ "$FACTORS" != "" ] \
    && green "Applied factors: $FACTORS" \
    || dim "No factors applied (normal for inline code snippets)"

  # Per-finding table
  echo ""
  echo "  Per-finding comparison:"
  CWES=$(echo "$BARE" | jq -r '.findings[].cwe')
  for CWE in $CWES; do
    B=$(echo "$BARE" | jq "[.findings[] | select(.cwe==\"$CWE\")] | .[0].crs")
    C=$(echo "$CTX" | jq "[.findings[] | select(.cwe==\"$CWE\")] | .[0].crs")
    printf "    %s → bare: %s, context: %s\n" "$CWE" "$B" "$C"
  done
}


# =============================================================================
# TEST 5: PROFILE DIFFERENTIATION (THE MONEY SHOT)
# =============================================================================
# What happens: Identical code scanned with 4 different profiles.
#   Each profile represents a different organisation type.
#
# What to look for:
#   - SLA DECREASES from startup → compliance (stricter = shorter deadline)
#   - Profile hash is DIFFERENT for each (proves different config was used)
#   - CRS may vary if profiles have different weights/lift caps
#
# THIS IS YOUR DEFENCE DEMO. If an examiner says "show me it works",
# run ./demo.sh 5 and point at this table.
# =============================================================================
test_5_differentiation() {
  blue "TEST 5: Profile Differentiation (THESIS KEY DEMO)"

  echo ""
  echo "  Same code, same vulnerabilities, four organisations:"
  echo ""
  printf "  %-12s │ %3s │ %-8s │ %8s │ %s\n" "Profile" "CRS" "Priority" "SLA days" "Hash"
  echo "  ─────────────┼─────┼──────────┼──────────┼─────────────"

  for PROFILE in startup default enterprise compliance; do
    R=$(curl -s -X POST "$BASE/scan-code" \
      -H "Content-Type: application/json" \
      -d "{
        \"code\": $CODE_JSON,
        \"language\": \"javascript\",
        \"profileId\": \"$PROFILE\"
      }")

    CRS=$(echo "$R" | jq '[.findings[].crs] | max')
    PRI=$(echo "$R" | jq -r '.findings[0].priority.priority')
    SLA=$(echo "$R" | jq '.findings[0].sla')
    HASH=$(echo "$R" | jq -r '.provenance.profileHash')

    printf "  %-12s │ %3s │ %-8s │ %8s │ %s\n" "$PROFILE" "$CRS" "$PRI" "$SLA" "$HASH"
  done

  echo ""
  dim "startup = relaxed SLAs (move fast)"
  dim "compliance = strict SLAs (regulatory pressure)"
  dim "Same bug, different urgency. That is the thesis."
}


# =============================================================================
# TEST 6: PRIORITY BANDS (Stage 4)
# =============================================================================
# What happens: CRS score maps to P0/P1/P2/P3 with action + SLA.
# What to look for: every finding has a priority and SLA attached.
# =============================================================================
test_6_priority() {
  blue "TEST 6: Priority Bands"

  SCAN=$(curl -s -X POST "$BASE/scan-code" \
    -H "Content-Type: application/json" \
    -d "{
      \"code\": $CODE_JSON,
      \"language\": \"javascript\",
      \"profileId\": \"default\"
    }")

  TOTAL=$(echo "$SCAN" | jq '.findings | length')
  WITH_PRI=$(echo "$SCAN" | jq '[.findings[] | select(.priority.priority != null)] | length')

  [ "$WITH_PRI" -eq "$TOTAL" ] \
    && green "All $TOTAL findings have priority bands" \
    || red "$WITH_PRI of $TOTAL findings have priorities"

  echo ""
  echo "$SCAN" | jq -r '.findings[] | "    \(.cwe) │ CRS \(.crs) → \(.priority.priority) │ SLA: \(.sla) days"'
}


# =============================================================================
# TEST 7: RISK AGGREGATION (File/Project Level)
# =============================================================================
# What happens: All findings roll up into one overall risk score + level.
# What to look for: overallRisk with a score (0-100) and level label.
# =============================================================================
test_7_aggregation() {
  blue "TEST 7: Risk Aggregation"

  SCAN=$(curl -s -X POST "$BASE/scan-code" \
    -H "Content-Type: application/json" \
    -d "{
      \"code\": $CODE_JSON,
      \"language\": \"javascript\",
      \"profileId\": \"default\"
    }")

  SCORE=$(echo "$SCAN" | jq '.overallRisk.score.final // .overallRisk.score // "N/A"')
  LEVEL=$(echo "$SCAN" | jq -r '.overallRisk.level // .overallRisk.risk.level // "unknown"')

  [ "$SCORE" != "N/A" ] && [ "$SCORE" != "null" ] \
    && green "Overall risk: $SCORE ($LEVEL)" \
    || red "Overall risk score missing"

  echo ""
  echo "  Severity distribution:"
  echo "$SCAN" | jq '.summary.severityDistribution'
}


# =============================================================================
# TEST 8: PROVENANCE (Audit Trail)
# =============================================================================
# What happens: Every scan response includes metadata about HOW it was scored.
# What to look for: profileId, profileHash, timestamp, scanDuration.
#
# WHY THIS MATTERS: For ISO 27001 / SOC 2 compliance, you need to prove
# that a scan result was produced with a specific, versioned configuration.
# The profileHash is a SHA-256 of the profile config — if anyone changes
# the profile, the hash changes, and old results are no longer comparable.
# =============================================================================
test_8_provenance() {
  blue "TEST 8: Provenance & Audit Trail"

  SCAN=$(curl -s -X POST "$BASE/scan-code" \
    -H "Content-Type: application/json" \
    -d "{
      \"code\": $CODE_JSON,
      \"language\": \"javascript\",
      \"profileId\": \"enterprise\"
    }")

  PID=$(echo "$SCAN" | jq -r '.provenance.profileId')
  HASH=$(echo "$SCAN" | jq -r '.provenance.profileHash')
  TS=$(echo "$SCAN" | jq -r '.provenance.timestamp')
  DUR=$(echo "$SCAN" | jq -r '.provenance.scanDuration')

  [ "$PID" = "enterprise" ] && green "Profile: $PID" || red "Wrong profile: $PID"
  [ "$HASH" != "null" ]     && green "Hash: $HASH"    || red "Hash missing"
  [ "$TS" != "null" ]       && green "Time: $TS"      || red "Timestamp missing"
  dim "Duration: $DUR"
}


# =============================================================================
# TEST 9: DEPENDENCY SCANNING (SCA)
# =============================================================================
# What happens: A package.json is sent to the scanner. It queries the OSV API
#   to check if any dependencies have known CVEs.
# What to look for: vulnerabilities array with package names and scores.
# NOTE: Needs internet access (calls osv.dev).
# =============================================================================
test_9_dependencies() {
  blue "TEST 9: Dependency Scanning (SCA)"

  DEP=$(curl -s -X POST "$BASE/scan-dependencies" \
    -H "Content-Type: application/json" \
    -d '{
      "packageJson": {
        "name": "demo-app",
        "version": "1.0.0",
        "dependencies": {
          "express": "4.17.1",
          "lodash": "4.17.15",
          "jsonwebtoken": "8.5.1"
        }
      }
    }')

  STATUS=$(echo "$DEP" | jq -r '.status')
  VULNS=$(echo "$DEP" | jq '.vulnerabilities | length')

  [ "$STATUS" = "success" ] \
    && green "SCA scan completed" \
    || red "SCA scan failed: $STATUS"

  echo "  Found $VULNS vulnerable dependencies"

  if [ "$VULNS" -gt 0 ]; then
    echo ""
    echo "$DEP" | jq -r '.vulnerabilities[:5][] | "    \(.package) → \(.adjustedSeverity // .severity)"'
  fi
}


# =============================================================================
# TEST 10: CONTEXTUAL FILTER (Noise Reduction)
# =============================================================================
# What happens: The filter removes findings that aren't real risks
#   (test files, example code, dead code paths, constants).
# How: Same code scanned with skipFilter=false vs skipFilter=true.
# What to look for: filtered count <= unfiltered count.
# =============================================================================
test_10_filter() {
  blue "TEST 10: Contextual Filter"

  F=$(curl -s -X POST "$BASE/scan-code" \
    -H "Content-Type: application/json" \
    -d "{\"code\": $CODE_JSON, \"language\": \"javascript\", \"profileId\": \"default\", \"skipFilter\": false}")

  U=$(curl -s -X POST "$BASE/scan-code" \
    -H "Content-Type: application/json" \
    -d "{\"code\": $CODE_JSON, \"language\": \"javascript\", \"profileId\": \"default\", \"skipFilter\": true}")

  CF=$(echo "$F" | jq '.summary.totalFindings')
  CU=$(echo "$U" | jq '.summary.totalFindings')

  echo "  Raw (unfiltered):  $CU findings"
  echo "  Smart (filtered):  $CF findings"

  if [ "$CU" -gt "$CF" ]; then
    green "Filter removed $((CU - CF)) noise findings"
  else
    dim "All findings were actionable (no noise to remove)"
  fi
}


# =============================================================================
# TEST 11: PROFILE VALIDATION
# =============================================================================
# What happens: The system validates profile configs before accepting them.
# How: We send a bad profile (weight=5.0, out of 0-1 range) and a good one.
# What to look for: bad → rejected, good → accepted.
# =============================================================================
test_11_validation() {
  blue "TEST 11: Profile Validation"

  BAD=$(curl -s -X POST "$BASE/profiles/validate" \
    -H "Content-Type: application/json" \
    -d '{"profile":{"version":"1.0.0","contextFactors":{"weights":{"internetFacing":5.0}}}}')

  GOOD=$(curl -s -X POST "$BASE/profiles/validate" \
    -H "Content-Type: application/json" \
    -d '{"profile":{"version":"1.0.0","contextFactors":{"weights":{"internetFacing":0.20}}}}')

  BS=$(echo "$BAD" | jq -r '.status')
  GS=$(echo "$GOOD" | jq -r '.status')

  [ "$BS" = "error" ]   && green "Bad profile rejected (weight 5.0 out of range)" || red "Bad profile accepted!"
  [ "$GS" = "success" ] && green "Good profile accepted" || red "Good profile rejected!"
}


# =============================================================================
# RUNNER — handles ./demo.sh, ./demo.sh 5, ./demo.sh 3 6
# =============================================================================
run_test() {
  case $1 in
    1)  test_1_health ;;
    2)  test_2_profiles ;;
    3)  test_3_bts ;;
    4)  test_4_crs ;;
    5)  test_5_differentiation ;;
    6)  test_6_priority ;;
    7)  test_7_aggregation ;;
    8)  test_8_provenance ;;
    9)  test_9_dependencies ;;
    10) test_10_filter ;;
    11) test_11_validation ;;
    *)  echo "Unknown test: $1 (valid: 1-11)" ;;
  esac
}

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║        NEPERIA SECURITY SCANNER - PIPELINE DEMO            ║"
echo "╚══════════════════════════════════════════════════════════════╝"

if [ $# -eq 0 ]; then
  for i in $(seq 1 11); do run_test $i; done
elif [ $# -eq 1 ]; then
  run_test $1
elif [ $# -eq 2 ]; then
  for i in $(seq $1 $2); do run_test $i; done
fi

echo ""
echo "━━━ Done ━━━"
echo ""
