"""
Fetch detection rule counts from external repos (CAR, Sigma, Elastic, Splunk)
for all ATT&CK techniques. Builds scripts/detection_counts.json.

Usage: python scripts/fetch_detection_counts.py
"""
import json
import os
import re
import sys
import urllib.request
import time
from collections import defaultdict

REPO_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT_PATH = os.path.join(REPO_DIR, "scripts", "detection_counts.json")

# === CAR (MITRE Cyber Analytics Repository) ===
CAR_API_TREE = "https://api.github.com/repos/mitre-attack/car/git/trees/master?recursive=1"
CAR_RAW_BASE = "https://raw.githubusercontent.com/mitre-attack/car/master/analytics/"

def fetch_json(url, retries=3):
    """Fetch JSON from URL with retries."""
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "top-attack/1.0", "Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except Exception as e:
            if attempt < retries - 1:
                time.sleep(1)
            else:
                print(f"  FAILED to fetch {url}: {e}")
                return None

def fetch_text(url, retries=3):
    """Fetch text content from URL with retries."""
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "top-attack/1.0"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.read().decode("utf-8")
        except Exception as e:
            if attempt < retries - 1:
                time.sleep(1)
            else:
                print(f"  FAILED to fetch {url}: {e}")
                return None

def fetch_car_counts():
    """Parse CAR analytics and count rules per technique."""
    print("\n=== CAR ===")
    tree = fetch_json(CAR_API_TREE)
    if not tree:
        print("  Could not fetch CAR tree")
        return {}

    # Find all analytics YAML files
    analytics = [item for item in tree.get("tree", [])
                 if item["path"].startswith("analytics/") and item["path"].endswith(".yaml")]
    print(f"  Found {len(analytics)} analytics")

    # Fetch each analytics file and extract technique coverage
    car_counts = defaultdict(int)
    for item in analytics:
        filename = item["path"].split("/")[-1]
        yaml_text = fetch_text(CAR_RAW_BASE + filename)
        if not yaml_text:
            continue

        # Parse technique IDs from YAML coverage section
        # Pattern: technique: TXXXX or technique: TXXXX (optional .XXX)
        techniques_found = set()
        for match in re.finditer(r'^\s*technique:\s*(T\d+(?:\.\d+)?)', yaml_text, re.MULTILINE):
            tid = match.group(1)
            techniques_found.add(tid)
            # Also add parent technique for sub-techniques
            if "." in tid:
                parent = tid.split(".")[0]
                techniques_found.add(parent)

        for tid in techniques_found:
            car_counts[tid] += 1

    print(f"  Found coverage for {len(car_counts)} unique techniques")
    return dict(car_counts)


def fetch_elastic_counts():
    """Search Elastic detection-rules repo for technique references."""
    print("\n=== ELASTIC ===")
    # Try to fetch the rules_build_rules.json or similar consolidated file
    # First check if there's a list of TOML files we can fetch
    tree = fetch_json("https://api.github.com/repos/elastic/detection-rules/git/trees/main?recursive=1")
    if not tree:
        print("  Could not fetch Elastic tree")
        return {}

    # Find all TOML rule files
    toml_files = [item for item in tree.get("tree", [])
                  if item["path"].startswith("rules/") and item["path"].endswith(".toml") and item["type"] == "blob"]
    print(f"  Found {len(toml_files)} TOML rule files")

    # Fetch each file (sampling since there are many)
    elastic_counts = defaultdict(int)
    # Limit to first 500 files to be practical
    batch = toml_files[:500]
    for item in batch:
        # Use raw URL: rules/windows/foo.toml -> raw content
        raw_url = f"https://raw.githubusercontent.com/elastic/detection-rules/main/{item['path']}"
        toml_text = fetch_text(raw_url)
        if not toml_text:
            continue

        # Extract technique IDs from TOML
        # Pattern: id = "TXXXX" or id = "TXXXX.XXX"
        techniques_found = set()
        for match in re.finditer(r'^\s*id\s*=\s*"(T\d+(?:\.\d+)?)"', toml_text, re.MULTILINE):
            tid = match.group(1)
            techniques_found.add(tid)

        for tid in techniques_found:
            elastic_counts[tid] += 1

    print(f"  Found coverage for {len(elastic_counts)} unique techniques (sampled {len(batch)} files)")
    return dict(elastic_counts)


def fetch_splunk_counts():
    """Search Splunk security_content repo for technique references."""
    print("\n=== SPLUNK ===")
    tree = fetch_json("https://api.github.com/repos/splunk/security_content/git/trees/develop?recursive=1")
    if not tree:
        print("  Could not fetch Splunk tree")
        return {}

    # Find all detection YAML files (excluding deprecated)
    yaml_files = [item for item in tree.get("tree", [])
                  if item["path"].startswith("detections/")
                  and item["path"].endswith((".yml", ".yaml"))
                  and "deprecated" not in item["path"]
                  and item["type"] == "blob"]
    print(f"  Found {len(yaml_files)} detection YAML files")

    # Fetch each file (sampling since there are many)
    splunk_counts = defaultdict(int)
    batch = yaml_files[:500]
    for item in batch:
        raw_url = f"https://raw.githubusercontent.com/splunk/security_content/develop/{item['path']}"
        yaml_text = fetch_text(raw_url)
        if not yaml_text:
            continue

        # Extract mitre_attack_id field from YAML
        # Pattern: mitre_attack_id:\n    - TXXXX or mitre_attack_id:\n    - TXXXX.XXX
        in_mitre_block = False
        techniques_found = set()
        for line in yaml_text.split("\n"):
            stripped = line.strip()
            if stripped.startswith("mitre_attack_id:"):
                in_mitre_block = True
                continue
            if in_mitre_block:
                if stripped.startswith("- "):
                    # Extract TXXXX or TXXXX.XXX
                    m = re.match(r'- (T\d+(?:\.\d+)?)', stripped)
                    if m:
                        techniques_found.add(m.group(1))
                else:
                    # Block ended (next top-level key)
                    if not stripped.startswith("-") and stripped:
                        in_mitre_block = False

        for tid in techniques_found:
            splunk_counts[tid] += 1

    print(f"  Found coverage for {len(splunk_counts)} unique techniques (sampled {len(batch)} files)")
    return dict(splunk_counts)


def main():
    print("Fetching detection rule counts from external repos...")
    print("=" * 60)

    # Load existing Sigma data
    sigma_path = os.path.join(REPO_DIR, "scripts", "sigma_counts.json")
    if os.path.exists(sigma_path):
        with open(sigma_path) as f:
            sigma_data = json.load(f)
        sigma_counts = sigma_data.get("sigma", {})
        print(f"\n=== SIGMA ===")
        print(f"  Loaded {len(sigma_counts)} techniques from sigma_counts.json")
    else:
        sigma_counts = {}
        print("  No sigma_counts.json found (run separately)")

    # Fetch CAR
    car_counts = fetch_car_counts()

    # Fetch Elastic
    elastic_counts = fetch_elastic_counts()

    # Fetch Splunk
    splunk_counts = fetch_splunk_counts()

    # Merge all counts
    all_tids = set(sigma_counts.keys()) | set(car_counts.keys()) | set(elastic_counts.keys()) | set(splunk_counts.keys())
    merged = {}
    for tid in sorted(all_tids):
        merged[tid] = {
            "sigma": sigma_counts.get(tid, 0),
            "car": car_counts.get(tid, 0),
            "elastic": elastic_counts.get(tid, 0),
            "splunk": splunk_counts.get(tid, 0),
        }
        # Sum for total detection count
        merged[tid]["total"] = sum(merged[tid].values())

    # Save
    output = {
        "metadata": {
            "sigma_repo": "SigmaHQ/sigma (other/sigma_attack_nav_coverage.json)",
            "car_repo": "mitre-attack/car (analytics/*.yaml)",
            "elastic_repo": "elastic/detection-rules (rules/**/*.toml, sampled 500)",
            "splunk_repo": "splunk/security_content (detections/**/*.yml, sampled 500)",
            "attack_version": "v19.1",
        },
        "counts": merged,
    }
    with open(OUTPUT_PATH, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\n{'='*60}")
    print(f"Saved detection counts to {OUTPUT_PATH}")
    print(f"  Total techniques: {len(merged)}")
    print(f"  Techniques with >0 total: {sum(1 for v in merged.values() if v['total'] > 0)}")

    # Show blank techniques (zero across all sources)
    blank = [tid for tid, v in sorted(merged.items()) if v['total'] == 0]
    print(f"  Techniques with 0 detection rules across all sources: {len(blank)}")


if __name__ == "__main__":
    main()
