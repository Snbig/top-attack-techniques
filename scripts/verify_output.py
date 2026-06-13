"""Verify the generated Techniques.json"""
import json

with open(r"C:\Users\Administrator\AppData\Local\Temp\top-attack\src\data\Techniques.json", encoding="utf-8") as f:
    techniques = json.load(f)

print(f"Total techniques: {len(techniques)}")

parents = [t for t in techniques if not t.get("is_subtechnique")]
subs = [t for t in techniques if t.get("is_subtechnique")]
print(f"Parent techniques: {len(parents)}")
print(f"Sub-techniques: {len(subs)}")

# Check top-level techniques have subtechniques array
with_subtech = sum(1 for t in parents if t.get("subtechniques"))
print(f"Parents with sub-techniques: {with_subtech}")

# Check scores
scored = sum(1 for t in techniques if t.get("cumulative_score") is not None)
unscored = sum(1 for t in techniques if t.get("cumulative_score") is None)
print(f"Scored techniques: {scored}")
print(f"Unscored techniques: {unscored}")

# Check for specific v19 techniques
v19_tids = ["T1685", "T1686", "T1687", "T1688", "T1689", "T1690", "T1683", "T1684", "T1682"]
print("\n=== V19 NEW TECHNIQUES ===")
for tid in v19_tids:
    found = [t for t in techniques if t["tid"] == tid]
    if found:
        t = found[0]
        print(f"  {tid}: {t['name']} - score={t.get('cumulative_score')}")
    else:
        print(f"  {tid}: NOT FOUND")

# Check ransomware TIDs still have data
print("\n=== RANSOMWARE TIDS ===")
for tid in ["T1059", "T1078", "T1021.001", "T1047", "T1490", "T1105", "T1083", "T1486", "T1190", "T1489"]:
    found = [t for t in techniques if t["tid"] == tid]
    if found:
        t = found[0]
        print(f"  {tid}: {t['name']} - mitigations={len(t.get('mitigations', []))}")
    else:
        print(f"  {tid}: NOT FOUND")

# Check platforms
all_platforms = set()
for t in techniques:
    for p in t.get("platforms", []):
        all_platforms.add(p)
print(f"\n=== ALL PLATFORMS ({len(all_platforms)}) ===")
for p in sorted(all_platforms):
    print(f"  {p}")

print(f"\nFile size: {len(json.dumps(techniques)):,} bytes")
