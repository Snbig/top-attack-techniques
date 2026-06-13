"""
Build external_detection_counts.json from CAR coverage CSV and optionally CTID Sightings CSV.

Output: { TID: {car, sigma, es, splunk, total_detections, sightings} }
"""

import ast
import csv
import io
import json
import os
import urllib.request
from collections import Counter

REPO_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT_PATH = os.path.join(REPO_DIR, "scripts", "external_detection_counts.json")


def parse_car_csv() -> dict:
    """Parse car_coverage.csv into per-technique detection counts."""
    csv_path = os.path.join(REPO_DIR, "scripts", "car_coverage.csv")
    result = {}

    with open(csv_path, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        # Strip leading whitespace from fieldnames
        reader.fieldnames = [fn.strip() for fn in reader.fieldnames]
        for row in reader:
            tid = row["Technique (ID)"].strip()
            car = int(row["Num. CAR"])
            sigma = int(row["Num. Sigma"])
            es = int(row["Num. ES SIEM"])
            splunk = int(row["Num. Splunk"])
            total = car + sigma + es + splunk

            result[tid] = {
                "car": car,
                "sigma": sigma,
                "es": es,
                "splunk": splunk,
                "total_detections": total,
                "sightings": 0,  # placeholder, will be filled from CTID
            }

    print(f"CAR CSV: {len(result)} techniques parsed")
    print(f"  Techniques with >0 total detections: {sum(1 for v in result.values() if v['total_detections'] > 0)}")
    print(f"  Total detection rules: {sum(v['total_detections'] for v in result.values())}")
    return result


def download_and_parse_ctid_csv(url: str) -> dict:
    """Download CTID Sightings CSV, explode techniques, count per TID."""
    print(f"\nDownloading CTID Sightings CSV from: {url}")
    print("  (25.7 MiB — this may take a moment...)")

    technique_counts = Counter()
    row_count = 0
    parse_errors = 0

    try:
        with urllib.request.urlopen(url, timeout=300) as response:
            # Read in chunks to show progress
            raw_data = response.read()
        print(f"  Downloaded {len(raw_data):,} bytes")

        # Decode (strip BOM) and parse
        text = raw_data.decode("utf-8-sig")
        reader = csv.DictReader(io.StringIO(text))
        for row in reader:
            row_count += 1
            tid_raw = row.get("tid", "")
            if not tid_raw:
                continue
            try:
                # Parse the Python list syntax: "['T1059', 'T1564.003']"
                # The CSV reader strips outer double quotes, giving us ['T1059', 'T1564.003']
                tids = ast.literal_eval(tid_raw)
                if isinstance(tids, list):
                    for tid in tids:
                        if isinstance(tid, str) and tid.startswith("T"):
                            technique_counts[tid] += 1
                elif isinstance(tids, str) and tids.startswith("T"):
                    technique_counts[tids] += 1
            except (ValueError, SyntaxError, TypeError):
                parse_errors += 1
                pass

            if row_count % 200000 == 0:
                print(f"    Parsed {row_count:,} rows...")

    except Exception as e:
        print(f"  ERROR downloading/parsing CTID CSV: {e}")
        print("  Will continue without CTID sightings data.")
        return {}

    print(f"\nCTID CSV parsed: {row_count:,} rows, {parse_errors} parse errors")
    print(f"  Unique techniques found: {len(technique_counts)}")
    print(f"  Total sighting-technique pairs: {sum(technique_counts.values()):,}")
    top5 = technique_counts.most_common(5)
    print(f"  Top 5: {top5}")
    return dict(technique_counts)


def merge_sightings(external: dict, sightings: dict) -> dict:
    """Merge CTID sighting counts into external counts dict."""
    # Add any techniques from sightings not already in external
    for tid, count in sightings.items():
        if tid in external:
            external[tid]["sightings"] = count
        else:
            # Technique exists in sightings but not in CAR CSV
            external[tid] = {
                "car": 0,
                "sigma": 0,
                "es": 0,
                "splunk": 0,
                "total_detections": 0,
                "sightings": count,
            }

    print(f"\nMerge complete: {len(external)} total techniques")
    with_sightings = sum(1 for v in external.values() if v["sightings"] > 0)
    with_detections = sum(1 for v in external.values() if v["total_detections"] > 0)
    with_both = sum(1 for v in external.values() if v["sightings"] > 0 and v["total_detections"] > 0)
    print(f"  With CTID sightings: {with_sightings}")
    print(f"  With detection rules: {with_detections}")
    print(f"  With both sources: {with_both}")
    return external


def main():
    external = parse_car_csv()

    # CTID Sightings CSV URL
    ctid_url = "https://ctidpublic.blob.core.windows.net/sightings/sightings_v2_public.csv"
    sightings = download_and_parse_ctid_csv(ctid_url)

    external = merge_sightings(external, sightings)

    # Write output
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(external, f, indent=2, sort_keys=True)

    print(f"\nSaved to: {OUTPUT_PATH}")
    print(f"File size: {os.path.getsize(OUTPUT_PATH):,} bytes")


if __name__ == "__main__":
    main()
