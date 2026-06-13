"""Analyze why only 12 flat 0.01 techniques were differentiated."""
import json

with open(r'C:\Users\Administrator\AppData\Local\Temp\top-attack\scripts\external_detection_counts.json') as f:
    ext = json.load(f)

with open(r'C:\Users\Administrator\AppData\Local\Temp\top-attack\src\data\Techniques.json', encoding='utf-8') as f:
    techs = json.load(f)

flat_01 = {t['tid'] for t in techs if t.get('actionability_score', {}).get('detection_score') == 0.01}
print(f'Flat 0.01 techniques in original: {len(flat_01)}')

# Flat techniques with detection rules
entries = []
for tid in sorted(flat_01):
    if tid in ext:
        e = ext[tid]
        if e['total_detections'] > 0:
            entries.append((tid, e['total_detections'], e['car'], e['sigma'], e['es'], e['splunk'], e['sightings']))

entries.sort(key=lambda x: x[1], reverse=True)
print(f'\nFlat techniques WITH detection rules: {len(entries)}')
print(f'\nThose that would get score >= 0.03 (_utility >= 3 rules):')
ge3 = [x for x in entries if x[1] >= 3]
for tid, total, car, sig, es, spl, sight in ge3:
    print(f'  {tid}: total_det={total} (CAR={car} Sigma={sig} ES={es} Spl={spl}), sightings={sight}')
print(f'Total with >=3 rules: {len(ge3)}')

# Those that would get 0.01 (1-2 rules)
print(f'\nThose with 1-2 rules (still 0.01 after _utility):')
for tid, total, car, sig, es, spl, sight in entries:
    if total < 3:
        print(f'  {tid}: total_det={total}')

# Check the score that 2 rules would give
print(f'\n_utility score for 1 rule: {1/100}')
print(f'_utility score for 2 rules: {2/100}')  # 0.02
print(f'_utility score for 3 rules: {3/100}')  # 0.03

# Flat techniques with sightings only
sight_only = []
for tid in sorted(flat_01):
    if tid in ext and ext[tid]['total_detections'] == 0 and ext[tid]['sightings'] > 0:
        sight_only.append((tid, ext[tid]['sightings']))
print(f'\nFlat techniques with ONLY sightings (0 detections): {len(sight_only)}')
for tid, sight in sorted(sight_only, key=lambda x: x[1], reverse=True)[:15]:
    import math
    log_score = min(1.0, math.log10(sight + 1) / 5.0)
    print(f'  {tid}: sightings={sight}, log_score={log_score:.4f}')
