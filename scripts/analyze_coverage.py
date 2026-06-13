"""Analyze CAR coverage CSV detection counts."""
import csv

with open(r'C:\Users\Administrator\AppData\Local\Temp\top-attack\scripts\car_coverage.csv', encoding='utf-8') as f:
    reader = csv.DictReader(f)
    # Strip leading whitespace from fieldnames
    reader.fieldnames = [fn.strip() for fn in reader.fieldnames]
    rows = list(reader)

print(f'Total rows: {len(rows)}')

by_tid = {}
for r in rows:
    tid = r['Technique (ID)'].strip()
    car = int(r['Num. CAR'])
    sigma = int(r['Num. Sigma'])
    es = int(r['Num. ES SIEM'])
    splunk = int(r['Num. Splunk'])
    by_tid[tid] = {'car': car, 'sigma': sigma, 'es': es, 'splunk': splunk, 'total': car+sigma+es+splunk}

totals = {'CAR': sum(v['car'] for v in by_tid.values()),
          'Sigma': sum(v['sigma'] for v in by_tid.values()),
          'ES': sum(v['es'] for v in by_tid.values()),
          'Splunk': sum(v['splunk'] for v in by_tid.values())}
print(f'Totals: {totals}')

with_coverage = sum(1 for v in by_tid.values() if v['total'] > 0)
print(f'Techniques with any detection rule: {with_coverage}/{len(by_tid)}')
print(f'Zero coverage: {len(by_tid) - with_coverage}')

for src in ['car', 'sigma', 'es', 'splunk']:
    n = sum(1 for v in by_tid.values() if v[src] > 0)
    print(f'  {src}: {n} techniques with >0 rules')

# Compare which techniques in CAR CSV overlap with existing detection_score=0.01
# Load Techniques.json
import json
with open(r'C:\Users\Administrator\AppData\Local\Temp\top-attack\src\data\Techniques.json', encoding='utf-8') as f:
    techs = json.load(f)

zero_01_tids = {t['tid'] for t in techs if t.get('actionability_score', {}).get('detection_score') == 0.01}
print(f'\nTechniques with detection_score=0.01: {len(zero_01_tids)}')

# Check how many of these have >0 total in CAR CSV
match = 0
for tid in zero_01_tids:
    if tid in by_tid and by_tid[tid]['total'] > 0:
        match += 1
        print(f'  {tid}: CAR={by_tid[tid]["car"]} Sigma={by_tid[tid]["sigma"]} ES={by_tid[tid]["es"]} Splunk={by_tid[tid]["splunk"]} Total={by_tid[tid]["total"]}')
print(f'\nOf {len(zero_01_tids)} flat-score techniques, {match} have detection rules in CAR CSV')

# How many 0.01 techniques are NOT in CAR CSV at all?
not_in_csv = [tid for tid in zero_01_tids if tid not in by_tid]
print(f'Not in CAR CSV: {len(not_in_csv)}')
print(f'Sample: {not_in_csv[:20]}')
