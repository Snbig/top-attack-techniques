"""Check remaining flat 0.01 techniques for any other signals."""
import json

# Load original Techniques.json
with open(r'C:\Users\Administrator\AppData\Local\Temp\top-attack\src\data\Techniques.json', encoding='utf-8') as f:
    techs = json.load(f)

# Load external counts
with open(r'C:\Users\Administrator\AppData\Local\Temp\top-attack\scripts\external_detection_counts.json') as f:
    ext_counts = json.load(f)

# Find the 81 remaining flat techniques (original flat ones without external data)
flat_01_tids = {t['tid'] for t in techs if t.get('actionability_score', {}).get('detection_score') == 0.01}

no_data = []
for tid in sorted(flat_01_tids):
    ext = ext_counts.get(tid, {})
    if ext.get('total_detections', 0) == 0 and ext.get('sightings', 0) == 0:
        no_data.append(tid)

print(f'Flat techniques without external data: {len(no_data)}')

# Categorize them
import re
v19_tids = [t for t in no_data if t.startswith('T16') and int(re.search(r'T(\d+)', t).group(1)) >= 1665]
print(f'  v19 techniques (T1665+): {len(v19_tids)} -> {v19_tids}')

# Check which have STIX detects
# Load STIX data
with open(r'C:\Users\Administrator\AppData\Local\Temp\top-attack\enterprise-attack-v19.1.json', encoding='utf-8') as f:
    stix = json.load(f)

# Map STIX IDs to TIDs
id_to_tid = {}
for obj in stix['objects']:
    if obj.get('type') != 'attack-pattern':
        continue
    for ref in obj.get('external_references', []):
        eid = ref.get('external_id', '')
        if eid.startswith('T'):
            id_to_tid[obj['id']] = eid
            break

# Count detects per technique
detects = {}
for obj in stix['objects']:
    if obj.get('type') != 'relationship' or obj.get('relationship_type') != 'detects':
        continue
    target_tid = id_to_tid.get(obj.get('target_ref', ''))
    if target_tid:
        detects[target_tid] = detects.get(target_tid, 0) + 1

no_data_with_detects = [t for t in no_data if t in detects]
print(f'  With STIX detects: {len(no_data_with_detects)}')

# Check detection field length
for t in techs:
    if t['tid'] in no_data:
        det = t.get('detection') or ''
        if len(det) > 50:
            print(f'  {t["tid"]}: detection field length={len(det)}, platforms={t.get("platforms", [])}')
            
print(f'\nFirst 20 no-data TIDs: {no_data[:20]}')
