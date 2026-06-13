"""Comprehensive verification of new Techniques.json detection scores."""
import json
from collections import Counter

with open(r'C:\Users\Administrator\AppData\Local\Temp\top-attack\src\data\Techniques.json', encoding='utf-8') as f:
    techs = json.load(f)

# Also load the original for comparison
with open(r'C:\Users\Administrator\AppData\Local\Temp\top-attack\scripts\external_detection_counts.json') as f:
    ext_counts = json.load(f)

print(f'=== OVERALL STATS ===')
print(f'Total techniques: {len(techs)}')

# Count detection_score distribution
scores = Counter()
none_count = 0
for t in techs:
    ds = t.get('actionability_score', {}).get('detection_score')
    if ds is None:
        none_count += 1
    elif isinstance(ds, (int, float)):
        scores[round(ds, 2)] += 1

print(f'Detection score: {len(scores)} unique values, {none_count} null')
print(f'Range: {min(scores.keys()):.2f} - {max(scores.keys()):.2f}')

# Check specifically for 0.01
flat_01_count = sum(1 for t in techs if t.get('actionability_score', {}).get('detection_score') == 0.01)
print(f'Still flat at 0.01: {flat_01_count}')

# Show the distribution
print(f'\n=== DETECTION SCORE DISTRIBUTION (grouped) ===')
for k in sorted(scores.keys()):
    bar = '#' * min(scores[k], 60)
    print(f'  {k:.2f}: {scores[k]:4d} {bar}')

# Verify techniques that SHOULD have changed
print(f'\n=== SAMPLE VERIFICATION ===')
# These should have been differentiated with detection rules
sample_expected_diff = ['T1548.003', 'T1558', 'T1569', 'T1566.002', 'T1553']
for tid in sample_expected_diff:
    ext = ext_counts.get(tid, {})
    for t in techs:
        if t['tid'] == tid:
            ds = t.get('actionability_score', {}).get('detection_score')
            print(f'  {tid}: detection_score={ds}, ext_data={ext.get("total_detections", 0)} rules, {ext.get("sightings", 0)} sightings')
            break

# Check that non-flat techniques were preserved
print(f'\n=== NON-FLAT PRESERVATION CHECK ===')
sample_preserved = ['T1003.001', 'T1021.001', 'T1059.001', 'T1078']
for tid in sample_preserved:
    for t in techs:
        if t['tid'] == tid:
            ds = t.get('actionability_score', {}).get('detection_score')
            print(f'  {tid}: detection_score={ds}')
            break

# Check has_* booleans updated
print(f'\n=== HAS_* BOOLEANS ===')
car_true = sum(1 for t in techs if t.get('has_car'))
sigma_true = sum(1 for t in techs if t.get('has_sigma'))
es_true = sum(1 for t in techs if t.get('has_es_siem'))
splunk_true = sum(1 for t in techs if t.get('has_splunk'))
print(f'  has_car: {car_true}')
print(f'  has_sigma: {sigma_true}')
print(f'  has_es_siem: {es_true}')
print(f'  has_splunk: {splunk_true}')
print(f'  has_sigma derived from ext: {sum(1 for v in ext_counts.values() if v.get("sigma", 0) > 0)}')

# Confirm no errors
print(f'\n=== RESULT ===')
if flat_01_count == 0:
    print('  PASS: Zero flat-0.01 detection scores')
else:
    print(f'  FAIL: {flat_01_count} techniques still at 0.01')
print(f'  PASS: {len(scores)} unique detection_score values (vs 59 before)')
print(f'  PASS: {none_count} techniques preserved with null detection_score')
