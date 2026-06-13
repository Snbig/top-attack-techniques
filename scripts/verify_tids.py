"""Verify all hardcoded technique IDs exist in v19."""
import json

with open(r"C:\Users\Administrator\AppData\Local\Temp\top-attack\enterprise-attack-v19.1.json") as f:
    data = json.load(f)

# Build TID -> info map
tid_map = {}
for obj in data["objects"]:
    if obj.get("type") != "attack-pattern":
        continue
    for ref in obj.get("external_references", []):
        eid = ref.get("external_id", "")
        if eid.startswith("T"):
            tid_map[eid] = {
                "name": obj.get("name"),
                "revoked": obj.get("revoked", False),
                "deprecated": obj.get("x_mitre_deprecated", False),
            }
            break

# Ransomware Top 10 TIDs
ransomware_tids = ["T1059", "T1078", "T1021.001", "T1047", "T1490", "T1105", "T1083", "T1486", "T1190", "T1489"]

print("=== RANSOMWARE TOP 10 TID VERIFICATION ===")
for tid in ransomware_tids:
    if tid in tid_map:
        info = tid_map[tid]
        status = "OK"
        if info["revoked"]:
            status = "REVOKED!"
        if info["deprecated"]:
            status = "DEPRECATED!"
        print(f"  {tid}: {info['name']} - {status}")
    else:
        print(f"  {tid}: *** NOT FOUND IN v19 ***")

# Hardcoded methodology TIDs
methodology_tids = ["T1014", "T1055", "T1491"]
print("\n=== METHODOLOGY HARDCODED TID VERIFICATION ===")
for tid in methodology_tids:
    if tid in tid_map:
        info = tid_map[tid]
        status = "OK"
        if info["revoked"]:
            status = "REVOKED!"
        if info["deprecated"]:
            status = "DEPRECATED!"
        print(f"  {tid}: {info['name']} - {status}")
    else:
        print(f"  {tid}: *** NOT FOUND IN v19 ***")

# Check T1021.001 (ransomware TID with sub-technique)
print("\n=== SUBTECHNIQUE VERIFICATION ===")
for tid in ["T1021.001", "T1055.011"]:
    if tid in tid_map:
        print(f"  {tid}: {tid_map[tid]['name']} - OK")
    else:
        print(f"  {tid}: NOT FOUND")
