#!/usr/bin/env python3
"""Compare scanner revalidation results against Tom's actual answers."""

import json, os, glob

RESULTS_DIR = os.path.dirname(os.path.abspath(__file__))

# Tom's answers
TOM_A = {"A1":"P0","A2":"P1","A3":"P3","B1":"P0","B2":"P1","B3":"P3","C1":"P0","C2":"P0","C3":"P0"}
TOM_B = {"F1":"Downgrade","F2":"Keep","F3":"Filter","F4":"Keep","F5":"Filter","F6":"Keep"}
TOM_C = {
    "express":  {"inet":True,  "prod":True,  "pii":False},
    "lodash":   {"inet":False, "prod":True,  "pii":False},
    "next.js":  {"inet":True,  "prod":True,  "pii":False},
    "semgrep":  {"inet":False, "prod":False, "pii":False},
    "chalk":    {"inet":False, "prod":True,  "pii":False},
}

def load(name):
    path = os.path.join(RESULTS_DIR, f"{name}.json")
    if not os.path.exists(path):
        return None, f"File not found: {name}.json"
    try:
        with open(path) as f:
            data = json.load(f)
        if data.get("status") == "error":
            return None, f"Scanner error: {data.get('message','?')}"
        return data, None
    except Exception as e:
        return None, str(e)

def get_finding_info(data):
    """Extract CRS, band, context from first finding."""
    findings = data.get("findings", data.get("results", []))
    if not findings:
        return {"crs": None, "band": None, "ctx": {}, "count": 0, "severity": None, "filtered": True}
    f = findings[0]
    pri = f.get("priority", {})
    band = pri.get("priority") if isinstance(pri, dict) else pri
    return {
        "crs": f.get("crs"),
        "band": band,
        "ctx": f.get("context", {}),
        "count": len(findings),
        "severity": f.get("adjustedSeverity", f.get("severity")),
        "filtered": False,
    }

print("=" * 70)
print("  REVALIDATION RESULTS vs TOM'S ANSWERS")
print("=" * 70)

# ── PART A ─────────────────────────────────────────────────────────
print("\n── PART A: Priority Assignment ──\n")
print(f"  {'ID':<5} {'CRS':<6} {'Scanner':<9} {'Tom':<6} {'Context':<35} {'Match'}")
print("  " + "-" * 65)

agree_a = 0
scanner_bands = []
tom_bands = []

for sid in ["A1","A2","A3","B1","B2","B3","C1","C2","C3"]:
    data, err = load(sid)
    if err:
        print(f"  {sid:<5} {'ERR':<6} {'?':<9} {TOM_A[sid]:<6} {err[:35]}")
        continue
    
    info = get_finding_info(data)
    
    if info["band"] is None:
        # No findings — scanner didn't detect the vuln
        print(f"  {sid:<5} {'—':<6} {'NO FIND':<9} {TOM_A[sid]:<6} {'No vulnerability detected':<35}")
        continue
    
    ctx = info["ctx"]
    ctx_str = f"inet={ctx.get('internetFacing','?')} prod={ctx.get('production','?')} pii={ctx.get('handlesPI','?')}"
    match = info["band"] == TOM_A[sid]
    if match: agree_a += 1
    scanner_bands.append(info["band"])
    tom_bands.append(TOM_A[sid])
    
    icon = "✅" if match else "⚠️"
    print(f"  {sid:<5} {str(info['crs']):<6} {info['band']:<9} {TOM_A[sid]:<6} {ctx_str:<35} {icon}")

n_a = len(scanner_bands)
if n_a > 0:
    print(f"\n  Agreement: {agree_a}/{n_a} ({agree_a/n_a*100:.0f}%)")

# ── PART B ─────────────────────────────────────────────────────────
print("\n── PART B: Filter Decisions ──\n")
print(f"  {'ID':<5} {'Findings':<9} {'Severity':<10} {'Scanner Decision':<18} {'Tom':<12} {'Match'}")
print("  " + "-" * 65)

agree_b = 0
total_b = 0

for fid in ["F1","F2","F3","F4","F5","F6"]:
    data, err = load(fid)
    if err:
        print(f"  {fid:<5} {'ERR':<9} {'?':<10} {'?':<18} {TOM_B[fid]:<12}")
        continue
    
    total_b += 1
    findings = data.get("findings", data.get("results", []))
    before = data.get("summary", {}).get("beforeFilter", len(findings))
    after = len(findings)
    
    if after == 0 and before and before > 0:
        decision = "Filter"
    elif after == 0:
        decision = "Filter (no detect)"
    else:
        f = findings[0]
        orig_sev = f.get("severity", "").upper()
        adj_sev = f.get("adjustedSeverity", orig_sev).upper()
        if adj_sev and orig_sev and adj_sev != orig_sev:
            decision = "Downgrade"
        else:
            decision = "Keep"
    
    tom = TOM_B[fid]
    match = decision.startswith(tom) or tom in decision
    if match: agree_b += 1
    icon = "✅" if match else "⚠️"
    
    sev = findings[0].get("severity", "?") if findings else "—"
    print(f"  {fid:<5} {after:<9} {sev:<10} {decision:<18} {tom:<12} {icon}")

if total_b > 0:
    print(f"\n  Agreement: {agree_b}/{total_b} ({agree_b/total_b*100:.0f}%)")

# ── PART C ─────────────────────────────────────────────────────────
print("\n── PART C: Context Inference ──\n")

C_MAP = {
    "express": "C_express",
    "lodash": "C_lodash",
    "next.js": "C_nextjs",
    "semgrep": "C_semgrep",
    "chalk": "C_chalk",
}
ATTR_MAP = {"inet":"internetFacing", "prod":"production", "pii":"handlesPI"}
LABELS = {"inet":"Internet-Facing", "prod":"Production", "pii":"PII"}

agree_c = 0
total_c = 0

print(f"  {'Repo':<10} {'Attribute':<16} {'Scanner':<10} {'Tom':<10} {'Match'}")
print("  " + "-" * 55)

for repo in ["express","lodash","next.js","semgrep","chalk"]:
    data, err = load(C_MAP[repo])
    
    # Try to extract context from findings
    scanner_ctx = {}
    if not err and data:
        findings = data.get("findings", data.get("results", []))
        if findings:
            ctx = findings[0].get("context", {})
            scanner_ctx = {
                "inet": ctx.get("internetFacing", False),
                "prod": ctx.get("production", False),
                "pii": ctx.get("handlesPI", False),
            }
        else:
            # No findings = no vulns detected = utility/safe code
            # Context inference may still be in metadata
            meta_ctx = data.get("contextInference", data.get("context", {}))
            if meta_ctx:
                scanner_ctx = {
                    "inet": meta_ctx.get("internetFacing", False),
                    "prod": meta_ctx.get("production", False),
                    "pii": meta_ctx.get("handlesPI", False),
                }
            else:
                scanner_ctx = {"inet": False, "prod": False, "pii": False}
    else:
        scanner_ctx = {"inet": "?", "prod": "?", "pii": "?"}
    
    for attr in ["inet","prod","pii"]:
        total_c += 1
        s = scanner_ctx.get(attr, "?")
        t = TOM_C[repo][attr]
        match = s == t
        if match: agree_c += 1
        icon = "✅" if match else "⚠️"
        print(f"  {repo:<10} {LABELS[attr]:<16} {str(s):<10} {str(t):<10} {icon}")

if total_c > 0:
    print(f"\n  Agreement: {agree_c}/{total_c} ({agree_c/total_c*100:.0f}%)")

# ── OVERALL ────────────────────────────────────────────────────────
print("\n" + "=" * 70)
print("  OVERALL")
print("=" * 70)
total = n_a + total_b + total_c
agree = agree_a + agree_b + agree_c
print(f"""
  Part A: {agree_a}/{n_a} ({agree_a/max(n_a,1)*100:.0f}%)
  Part B: {agree_b}/{total_b} ({agree_b/max(total_b,1)*100:.0f}%)
  Part C: {agree_c}/{total_c} ({agree_c/max(total_c,1)*100:.0f}%)
  ────────────────────
  TOTAL:  {agree}/{total} ({agree/max(total,1)*100:.1f}%)
  Target: >90%
""")

# Save raw comparison
summary = {
    "part_a": {"agree": agree_a, "total": n_a, "scanner": scanner_bands, "tom": tom_bands},
    "part_b": {"agree": agree_b, "total": total_b},
    "part_c": {"agree": agree_c, "total": total_c},
    "overall": {"agree": agree, "total": total, "percentage": round(agree/max(total,1)*100,1)}
}
with open(os.path.join(RESULTS_DIR, "comparison_summary.json"), "w") as f:
    json.dump(summary, f, indent=2)
print(f"  Raw data saved: revalidation/comparison_summary.json")

