#!/usr/bin/env python3
"""End-to-end smoke test for ThreatGenix copilot mode via live API."""
import json
import sys
import requests

BASE = "http://localhost:8000/api"
PASS = 0
FAIL = 0

def check(label, condition, detail=""):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  PASS: {label}")
    else:
        FAIL += 1
        print(f"  FAIL: {label} — {detail}")

def auth():
    r = requests.post(f"{BASE}/auth/login", json={"email": "analyst@example.test", "password": "password123"})
    if r.status_code != 200:
        # Register first
        requests.post(f"{BASE}/auth/register", json={"email": "analyst@example.test", "password": "password123", "full_name": "Priya Sharma"})
        r = requests.post(f"{BASE}/auth/login", json={"email": "analyst@example.test", "password": "password123"})
    return {"Authorization": f"Bearer {r.json()['access_token']}"}

headers = auth()
print("Authenticated as analyst@example.test\n")

# 1. Create threat model
print("=== 1. Create Threat Model ===")
r = requests.post(f"{BASE}/threat-models", json={
    "system_name": "Payment Gateway Smoke Test",
    "description": "E2E test of full copilot flow",
    "data_classification": "Restricted"
}, headers=headers)
check("Create threat model", r.status_code == 201, f"status={r.status_code} body={r.text[:100]}")
tm = r.json()
tm_id = tm["id"]
print(f"  ID: {tm_id}\n")

# 2. Add DFD nodes
print("=== 2. Add DFD Nodes ===")
ee = requests.post(f"{BASE}/threat-models/{tm_id}/dfd/nodes", json={
    "node_type": "external_entity", "name": "Customer Browser", "position_x": 50, "position_y": 200
}, headers=headers).json()
proc = requests.post(f"{BASE}/threat-models/{tm_id}/dfd/nodes", json={
    "node_type": "process", "name": "API Gateway", "position_x": 300, "position_y": 200
}, headers=headers).json()
ds = requests.post(f"{BASE}/threat-models/{tm_id}/dfd/nodes", json={
    "node_type": "data_store", "name": "Transaction DB", "position_x": 550, "position_y": 200
}, headers=headers).json()
check("3 nodes created", all("id" in n for n in [ee, proc, ds]))
print(f"  Nodes: {ee['name']}, {proc['name']}, {ds['name']}\n")

# 3. Add edges
print("=== 3. Add Edges ===")
e1 = requests.post(f"{BASE}/threat-models/{tm_id}/dfd/edges", json={
    "source_node_id": ee["id"], "target_node_id": proc["id"], "label": "HTTPS Request"
}, headers=headers)
e2 = requests.post(f"{BASE}/threat-models/{tm_id}/dfd/edges", json={
    "source_node_id": proc["id"], "target_node_id": ds["id"], "label": "SQL Query"
}, headers=headers)
check("2 edges created", e1.status_code == 201 and e2.status_code == 201)

# 4. Add trust boundary
print("\n=== 4. Add Trust Boundary ===")
b = requests.post(f"{BASE}/threat-models/{tm_id}/dfd/boundaries", json={
    "name": "Internal Network", "node_ids": [proc["id"], ds["id"]]
}, headers=headers)
check("Trust boundary created", b.status_code == 201)

# 5. Generate threats (rules only)
print("\n=== 5. Generate Threats (rules only) ===")
r = requests.post(f"{BASE}/threat-models/{tm_id}/analyze?rules_only=true", headers=headers)
check("Analyze endpoint works", r.status_code == 200, f"status={r.status_code}")
threats = r.json()["threats"]
threat_count = len(threats)
check(f"Threats generated ({threat_count})", threat_count > 0)
for t in threats[:5]:
    print(f"  {t['display_id']} [{t['severity']}] {t['stride_category']}: {t['description'][:60]}...")
if threat_count > 5:
    print(f"  ... ({threat_count} total)")

# 6. Threat diff (baseline should exist now)
print("\n=== 6. Threat Diff (baseline exists) ===")
diff = requests.post(f"{BASE}/threat-models/{tm_id}/threat-diff", headers=headers).json()
check("has_baseline is True", diff["has_baseline"] is True)
check("No changes (same DFD)", diff["counts"]["added"] == 0 and diff["counts"]["removed"] == 0)

# 7. Set properties to mitigate threats
print("\n=== 7. Set Properties (mitigate threats) ===")
requests.patch(f"{BASE}/threat-models/{tm_id}/dfd/nodes/{ee['id']}", json={
    "properties": {"authenticated": True, "trusted": True}
}, headers=headers)
requests.patch(f"{BASE}/threat-models/{tm_id}/dfd/nodes/{proc['id']}", json={
    "properties": {"uses_auth": True, "validates_input": True, "uses_encryption": True}
}, headers=headers)
print("  Set authenticated, uses_auth, validates_input, uses_encryption")

# 8. Threat diff after property changes
print("\n=== 8. Threat Diff After Properties ===")
diff2 = requests.post(f"{BASE}/threat-models/{tm_id}/threat-diff", headers=headers).json()
check("Threats removed (mitigated)", diff2["counts"]["removed"] > 0, f"removed={diff2['counts']['removed']}")
for t in diff2.get("removed", []):
    print(f"  MITIGATED: {t['rule_id']} [{t['severity']}] {t['description'][:60]}")

# 9. Triage a structural threat (R-01/E-02 — not suppressible), then re-analyze
print("\n=== 9. Triage Preservation ===")
# Get current threats AFTER properties were set (re-analyze to get fresh list)
r_fresh = requests.post(f"{BASE}/threat-models/{tm_id}/analyze?rules_only=true", headers=headers)
fresh_threats = r_fresh.json()["threats"]
# Find a structural threat that won't be mitigated
structural = next((t for t in fresh_threats if t["rule_id"] in ("R-01", "R-02", "R-03", "E-02", "D-02")), fresh_threats[0])
structural_id = structural["id"]
requests.patch(f"{BASE}/threat-models/{tm_id}/threats/{structural_id}/triage", json={
    "status": "Accepted", "dismiss_reason": None
}, headers=headers)
print(f"  Triaged {structural['display_id']} ({structural['rule_id']}) as Accepted")

# Re-analyze again — this structural threat should still be Accepted
r2 = requests.post(f"{BASE}/threat-models/{tm_id}/analyze?rules_only=true", headers=headers)
new_threats = r2.json()["threats"]
accepted_count = sum(1 for t in new_threats if t["status"] == "Accepted")
check("Triage preserved after re-analyze", accepted_count >= 1, f"accepted={accepted_count}")
print(f"  {len(new_threats)} threats, {accepted_count} still Accepted")

# 10. Compliance controls (multi-framework)
print("\n=== 10. Compliance Controls ===")
r3 = requests.get(f"{BASE}/threat-models/{tm_id}/threats", headers=headers)
all_threats = r3.json()
threats_with_controls = [t for t in all_threats if t.get("compliance_controls")]
check("Threats have compliance controls", len(threats_with_controls) > 0)
if threats_with_controls:
    t = threats_with_controls[0]
    frameworks = set(c["framework"] for c in t["compliance_controls"])
    print(f"  {t['display_id']}: {len(t['compliance_controls'])} controls across {frameworks}")
    for c in t["compliance_controls"][:4]:
        print(f"    [{c['framework']}] {c['control_id']} — {c['control_name']}")

# 11. Threat catalog search
print("\n=== 11. Threat Catalog ===")
catalog = requests.get(f"{BASE}/threat-catalog?q=encryption", headers=headers).json()
check("Catalog search works", len(catalog) > 0, f"found={len(catalog)}")
for c in catalog:
    print(f"  {c['rule_id']} [{c['severity']}] {c['threat_subtype']}")

# 12. Add manual threat
print("\n=== 12. Manual Threat ===")
manual = requests.post(f"{BASE}/threat-models/{tm_id}/threats/manual", json={
    "rule_id": "T-01", "description": "Custom: Unencrypted PII in payment flow"
}, headers=headers)
check("Manual threat created", manual.status_code in (200, 201), f"status={manual.status_code} body={manual.text[:100]}")
if manual.status_code in (200, 201):
    mt = manual.json()
    print(f"  {mt['display_id']} [{mt['source']}] {mt['description']}")

# 13. Audit history (use the structural threat we triaged in step 9)
print("\n=== 13. Audit History ===")
# Find the triaged threat's NEW id after re-analyze
triaged_threats = [t for t in new_threats if t["status"] == "Accepted"]
if triaged_threats:
    triaged_id = triaged_threats[0]["id"]
    history = requests.get(f"{BASE}/threat-models/{tm_id}/threats/{triaged_id}/history", headers=headers)
    check("Audit history endpoint works", history.status_code == 200)
    entries = history.json()
    check("Audit entries exist", len(entries) > 0, f"got {len(entries)} entries")
    if isinstance(entries, list):
        for e in entries:
            if isinstance(e, dict):
                old = e.get("old_status", "-")
                print(f"  {e['action']}: {old} -> {e['new_status']} by {e['changed_by']}")
else:
    check("Audit history endpoint works", False, "no triaged threats to check")
    check("Audit entries exist", False, "skipped")

# 14. Dashboard
print("\n=== 14. Dashboard ===")
dash = requests.get(f"{BASE}/dashboard/summary", headers=headers).json()
check("Dashboard shows models", dash["total_models"] > 0)
check("Dashboard shows threats", dash["total_threats"] > 0)
print(f"  Models: {dash['total_models']}, Threats: {dash['total_threats']}")
print(f"  By severity: {dash['threats_by_severity']}")

# 15. Export CSV
print("\n=== 15. Export CSV ===")
csv_r = requests.get(f"{BASE}/threat-models/{tm_id}/threats/export.csv", headers=headers)
check("CSV export works", csv_r.status_code == 200 and "text/csv" in csv_r.headers.get("content-type", ""))
lines = csv_r.text.strip().split("\n")
check("CSV has header + data rows", len(lines) > 1, f"lines={len(lines)}")
print(f"  {len(lines)} rows (including header)")
print(f"  Header: {lines[0][:80]}...")

# Summary
print(f"\n{'='*50}")
print(f"RESULTS: {PASS} passed, {FAIL} failed out of {PASS+FAIL} checks")
if FAIL > 0:
    sys.exit(1)
print("ALL CHECKS PASSED")
