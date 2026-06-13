import json

with open(r"C:\Users\Administrator\AppData\Local\Temp\top-attack\enterprise-attack-v19.1.json") as f:
    data = json.load(f)

objects = data['objects']

# Find a mitigation with M-prefix ID
print("=== MITIGATIONS WITH M-PREFIX IDs ===")
for obj in objects:
    if obj.get('type') == 'course-of-action':
        for ref in obj.get('external_references', []):
            if ref.get('external_id', '').startswith('M'):
                print(f"ID: {ref['external_id']}")
                print(f"Name: {obj['name']}")
                print(f"URL: {ref.get('url', '')}")
                desc = obj.get('description', '')
                print(f"Description: {desc[:200]}...")
                print(f"Deprecated: {obj.get('x_mitre_deprecated', False)}")
                print()
                break

# Count
count = 0
for obj in objects:
    if obj.get('type') == 'course-of-action':
        for ref in obj.get('external_references', []):
            if ref.get('external_id', '').startswith('M'):
                count += 1
                break
print(f"Total mitigations with M-prefix: {count}")

# Count total course-of-action
total = sum(1 for obj in objects if obj.get('type') == 'course-of-action')
print(f"Total course-of-action objects: {total}")

# Check relationship format for mitigation -> technique
print("\n=== RELATIONSHIPS (mitigation->technique) ===")
count = 0
for obj in objects:
    if obj.get('type') == 'relationship':
        if 'course-of-action' in obj.get('source_ref', '') and 'attack-pattern' in obj.get('target_ref', ''):
            if count < 3:
                print(f"  Source: {obj['source_ref']}")
                print(f"  Target: {obj['target_ref']}")
                print(f"  Relationship: {obj.get('relationship_type', '')}")
                print(f"  Description: {obj.get('description', '')[:100]}")
                print()
                count += 1
        elif count == 0 and 'attack-pattern' in obj.get('source_ref', '') and 'course-of-action' in obj.get('target_ref', ''):
            if count < 3:
                print(f"  Source: {obj['source_ref']}")
                print(f"  Target: {obj['target_ref']}")
                print(f"  Relationship: {obj.get('relationship_type', '')}")
                print(f"  Description: {obj.get('description', '')[:100]}")
                print()
                count += 1

# Count total relationships
rel_count = sum(1 for obj in objects if obj.get('type') == 'relationship')
print(f"Total relationships: {rel_count}")
