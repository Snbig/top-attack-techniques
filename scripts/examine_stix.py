import json

with open(r"C:\Users\Administrator\AppData\Local\Temp\top-attack\enterprise-attack-v19.1.json") as f:
    data = json.load(f)

objects = data['objects']

# Show parent technique
for obj in objects:
    if obj.get('type') == 'attack-pattern' and not obj.get('x_mitre_is_subtechnique'):
        print('=== PARENT TECHNIQUE ===')
        for k, v in sorted(obj.items()):
            if k != 'description':
                print(f'  {k}: {v}')
        desc = obj.get('description', '')
        print(f'  description: {desc[:200]}...')
        break

# Show subtechnique
print()
for obj in objects:
    if obj.get('type') == 'attack-pattern' and obj.get('x_mitre_is_subtechnique'):
        print('=== SUBTECHNIQUE ===')
        for k, v in sorted(obj.items()):
            if k != 'description':
                print(f'  {k}: {v}')
        desc = obj.get('description', '')
        print(f'  description: {desc[:200]}...')
        break

# Show mitigation
print()
for obj in objects:
    if obj.get('type') == 'course-of-action':
        print('=== MITIGATION ===')
        for k, v in sorted(obj.items()):
            if k != 'description':
                print(f'  {k}: {v}')
        desc = obj.get('description', '')
        print(f'  description: {desc[:200]}...')
        break

# Show external refs
print()
print('=== External references sample ===')
for obj in objects:
    if obj.get('type') == 'attack-pattern':
        if obj.get('external_references'):
            ref = obj['external_references'][0]
            print(json.dumps(ref, indent=2))
        break

# Show all tactics
print()
print('=== TACTICS ===')
for obj in objects:
    if obj.get('type') == 'x-mitre-tactic':
        tid = None
        name = obj['name']
        if obj.get('external_references'):
            tid = obj['external_references'][0].get('external_id')
        print(f'  {name} ({tid})')
