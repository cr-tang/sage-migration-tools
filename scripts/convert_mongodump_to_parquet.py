#!/usr/bin/env python3
"""Convert MongoDB-dumped file_rep NDJSON.gz files to Parquet format.

Produces Parquet files with the same schema as VT export parquets, so they
can be imported into TiDB using the existing import_parquet_loaddata.py script.

Records missing broccoli_classification are enriched from a supplementary CSV,
then falls back to inference from detection names / positives count.

Usage:
    python3 convert_mongodump_to_parquet.py \
        --input-dir ~/Downloads/file_rep_import/ \
        --broccoli-csv ~/Downloads/broccoli_classification_results.csv \
        --output-dir ~/Downloads/mongodump_parquet/
"""

import argparse
import csv
import gzip
import json
import os
import sys
import time
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq


# ─────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────
VALID_IMPORT_CLASSIFICATIONS = {
    "ransomware", "maltool", "hacktool", "unwanted", "malware",
    "suspicious", "blacklist", "av_detected",
}

SKIP_CLASSIFICATIONS = {"indifferent", "unknown", "whitelist"}


# ─────────────────────────────────────────────────
# Broccoli CSV loader
# ─────────────────────────────────────────────────
def load_broccoli_csv(csv_path: str) -> dict:
    """Load broccoli_classification_results.csv into {sha1_lower: classification}."""
    lookup = {}
    with open(csv_path, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            sha1 = (row.get("sha1") or "").strip().lower()
            cls = (row.get("broccoli_classification") or "").strip().lower()
            if sha1 and cls and cls not in SKIP_CLASSIFICATIONS:
                lookup[sha1] = cls
    print(f"  Loaded {len(lookup):,} enrichment records from broccoli CSV")
    return lookup


# ─────────────────────────────────────────────────
# Classification logic
# ─────────────────────────────────────────────────
def extract_detection_names(record: dict) -> str | None:
    """Extract 'engine:result;...' from scans dict."""
    if record.get("detections"):
        return record["detections"]

    scans = record.get("scans")
    if not scans or not isinstance(scans, dict):
        return None

    detections = []
    for engine, result in scans.items():
        if isinstance(result, dict) and result.get("detected") and result.get("result"):
            detections.append(f"{engine}:{result['result']}")

    return ";".join(detections) if detections else None


def resolve_classification(record: dict, broccoli_lookup: dict) -> str | None:
    """
    Resolve classification from explicit sources only (no inference):
      1. broccoli_classification from record itself
      2. Look up sha1 in broccoli CSV
    Returns lowercase classification string or None (skip).
    """
    bc = (record.get("broccoli_classification") or "").strip().lower()
    if bc:
        if bc in SKIP_CLASSIFICATIONS:
            return None
        if bc in VALID_IMPORT_CLASSIFICATIONS:
            return bc

    sha1 = (record.get("sha1") or "").strip().lower()
    if sha1 and sha1 in broccoli_lookup:
        bc2 = broccoli_lookup[sha1]
        if bc2 in VALID_IMPORT_CLASSIFICATIONS:
            return bc2

    return None


# ─────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Convert MongoDB dump NDJSON.gz → single Parquet (same schema as VT export)",
    )
    parser.add_argument("--input-dir", required=True,
                        help="Directory with file_rep_*.ndjson.gz files")
    parser.add_argument("--broccoli-csv", required=True,
                        help="Path to broccoli_classification_results.csv")
    parser.add_argument("--output", required=True,
                        help="Output parquet file path (e.g. ~/Downloads/mongodump_parquet/mongodump_all.parquet)")
    args = parser.parse_args()

    input_dir = Path(args.input_dir)
    output_path = Path(args.output)

    if not input_dir.is_dir():
        print(f"❌ Input dir not found: {input_dir}")
        sys.exit(1)

    output_path.parent.mkdir(parents=True, exist_ok=True)

    input_files = sorted(input_dir.glob("file_rep_*.ndjson.gz"))
    if not input_files:
        print(f"❌ No file_rep_*.ndjson.gz found in {input_dir}")
        sys.exit(1)

    print("=" * 60)
    print("MongoDB Dump → Single Parquet Converter")
    print("=" * 60)
    print(f"Input dir:    {input_dir}")
    print(f"Output:       {output_path}")
    print(f"Broccoli CSV: {args.broccoli_csv}")
    print(f"Input files:  {len(input_files)}")
    print("=" * 60)

    # Load broccoli enrichment
    print(f"\nLoading broccoli classification enrichment...")
    broccoli_lookup = load_broccoli_csv(args.broccoli_csv)

    # Accumulate all rows across all files
    rows = {
        "sha256": [], "sha1": [], "md5": [],
        "positives": [], "total": [], "scan_date": [],
        "detection_names": [], "classification": [], "date": [],
    }
    grand_total_lines = 0
    grand_skipped = 0
    grand_enriched = 0

    total_start = time.time()

    for i, f in enumerate(input_files, 1):
        basename = f.name
        print(f"\n[{i}/{len(input_files)}] Reading: {basename}")
        t0 = time.time()

        file_lines = 0
        file_skipped = 0
        file_enriched = 0

        with gzip.open(str(f), "rt", encoding="utf-8") as fh:
            for line in fh:
                file_lines += 1
                try:
                    record = json.loads(line.strip())
                except json.JSONDecodeError:
                    file_skipped += 1
                    continue

                sha256 = (record.get("sha256") or "").strip().lower()
                if not sha256 or len(sha256) != 64:
                    file_skipped += 1
                    continue

                orig_bc = (record.get("broccoli_classification") or "").strip().lower()
                classification = resolve_classification(record, broccoli_lookup)
                if not classification:
                    file_skipped += 1
                    continue

                if not orig_bc or orig_bc in SKIP_CLASSIFICATIONS:
                    file_enriched += 1

                sha1 = (record.get("sha1") or "").strip().lower()
                md5 = (record.get("md5") or "").strip().lower()

                positives = record.get("positives", 0)
                total = record.get("total", 0)
                if isinstance(positives, float):
                    positives = int(positives)
                if isinstance(total, float):
                    total = int(total)
                positives = max(0, min(positives or 0, 255))
                total = max(0, min(total or 0, 255))

                scan_date = record.get("scan_date", "")
                sd = str(scan_date).strip() if scan_date else ""

                date_str = ""
                if sd and len(sd) >= 10 and sd[4] == "-":
                    date_str = sd[:10].replace("-", "")

                detection_names = extract_detection_names(record) or ""

                rows["sha256"].append(sha256)
                rows["sha1"].append(sha1)
                rows["md5"].append(md5)
                rows["positives"].append(positives)
                rows["total"].append(total)
                rows["scan_date"].append(sd)
                rows["detection_names"].append(detection_names)
                rows["classification"].append(classification)
                rows["date"].append(date_str)

        valid = file_lines - file_skipped
        elapsed = time.time() - t0
        print(f"  Lines: {file_lines:,}  Valid: {valid:,}  Skipped: {file_skipped:,}  "
              f"Enriched(broccoli): {file_enriched:,}  Time: {elapsed:.1f}s")

        grand_total_lines += file_lines
        grand_skipped += file_skipped
        grand_enriched += file_enriched

    grand_valid = len(rows["sha256"])

    # Write single merged parquet
    print(f"\nWriting merged parquet → {output_path.name}...")
    t1 = time.time()

    table = pa.table({
        "sha256": pa.array(rows["sha256"], type=pa.string()),
        "sha1": pa.array(rows["sha1"], type=pa.string()),
        "md5": pa.array(rows["md5"], type=pa.string()),
        "positives": pa.array(rows["positives"], type=pa.int32()),
        "total": pa.array(rows["total"], type=pa.int32()),
        "scan_date": pa.array(rows["scan_date"], type=pa.string()),
        "detection_names": pa.array(rows["detection_names"], type=pa.string()),
        "classification": pa.array(rows["classification"], type=pa.string()),
        "date": pa.array(rows["date"], type=pa.string()),
    })

    pq.write_table(table, str(output_path), compression="snappy")
    write_time = time.time() - t1
    file_size = os.path.getsize(str(output_path)) / (1024 * 1024)

    total_elapsed = time.time() - total_start

    print(f"\n{'='*60}")
    print(f"CONVERSION COMPLETE")
    print(f"{'='*60}")
    print(f"Input files:            {len(input_files)}")
    print(f"Total lines:            {grand_total_lines:,}")
    print(f"Valid rows:             {grand_valid:,}")
    print(f"Skipped (no class):     {grand_skipped:,}")
    print(f"Enriched (broccoli):    {grand_enriched:,}")
    print(f"Output:                 {output_path} ({file_size:.1f} MB)")
    print(f"Write time:             {write_time:.1f}s")
    print(f"Total time:             {total_elapsed:.1f}s")
    print(f"\nImport with:")
    print(f"  python3 import_parquet_loaddata.py {output_path} --password <pwd>")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
