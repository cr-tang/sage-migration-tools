#!/usr/bin/env python3
"""
Simple Parquet Filter with Auto-Resume
Filters parquet files by classification, only processing files that have completed backfill.
Automatically skips already filtered files.

Usage:
    python3 filter_parquet.py
"""

import sys
from pathlib import Path
import pyarrow.parquet as pq
import pyarrow as pa


def get_completed_backfill(export_dir: Path) -> set:
    """Read .backfill_progress to get completed files."""
    progress_file = export_dir / ".backfill_progress"
    if not progress_file.exists():
        print(f"⚠️  No .backfill_progress found, will process all files")
        return set()
    
    with open(progress_file, "r") as f:
        completed = set(line.strip() for line in f if line.strip())
    
    print(f"✓ Found {len(completed):,} completed backfill files")
    return completed


def get_already_filtered(output_dir: Path) -> set:
    """Get list of already filtered files."""
    if not output_dir.exists():
        return set()
    
    filtered = set()
    for f in output_dir.glob("part_*_filtered.parquet"):
        # Extract original name: part_0001_filtered.parquet -> part_0001.parquet
        original_name = f.stem.replace("_filtered", "") + ".parquet"
        filtered.add(original_name)
    
    print(f"✓ Found {len(filtered):,} already filtered files")
    return filtered


def filter_one_file(input_file: Path, output_dir: Path):
    """Filter a single parquet file."""
    basename = input_file.stem  # e.g., "part_0001"
    output_file = output_dir / f"{basename}_filtered.parquet"
    null_file = output_dir / f"{basename}_null.parquet"
    
    # Read
    try:
        table = pq.read_table(input_file)
    except Exception as e:
        print(f"  ❌ Failed to read {input_file.name}: {e}")
        return False
    
    total = len(table)
    
    # Filter: keep malware/ransomware/unwanted/hacktool
    keep_set = {'malware', 'ransomware', 'unwanted', 'hacktool'}
    cls = table.column('classification')
    
    keep_mask = pa.compute.is_in(cls, value_set=pa.array(list(keep_set)))
    keep_table = table.filter(keep_mask)
    keep_count = len(keep_table)
    
    # NULL - only keep SHA1 and scan_date columns for review
    null_mask = pa.compute.is_null(cls)
    null_table = table.filter(null_mask)
    null_count = len(null_table)
    
    # Write
    try:
        pq.write_table(keep_table, output_file, compression='zstd', compression_level=3)
        
        # Write NULL file with only SHA1 and scan_date (lightweight)
        if null_count > 0:
            null_minimal = null_table.select(['sha1', 'scan_date'])
            pq.write_table(null_minimal, null_file, compression='zstd', compression_level=3)
        
        keep_pct = keep_count / total * 100 if total > 0 else 0
        null_pct = null_count / total * 100 if total > 0 else 0
        print(f"  ✓ {input_file.name}: kept {keep_count:,}/{total:,} ({keep_pct:.1f}%), null {null_count:,} ({null_pct:.1f}%)")
        return True
    except Exception as e:
        print(f"  ❌ Failed to write {output_file.name}: {e}")
        return False


def main():
    # Hard-coded paths - no arguments needed
    input_dir = Path("/data/vt_export")
    output_dir = Path("/data/vt_export/filtered")
    
    if not input_dir.exists():
        print(f"❌ Input directory not found: {input_dir}")
        sys.exit(1)
    
    output_dir.mkdir(exist_ok=True)
    
    print("=" * 70)
    print("Parquet Filter with Auto-Resume")
    print("=" * 70)
    print(f"Input:    {input_dir}")
    print(f"Output:   {output_dir}")
    print(f"Note:     NULL classifications saved as *_null.parquet (SHA1 + scan_date only)")
    print()
    
    # Get completed backfill files
    completed_backfill = get_completed_backfill(input_dir)
    
    # Get already filtered files
    already_filtered = get_already_filtered(output_dir)
    
    # Find all parquet files
    all_files = list(input_dir.glob("part_*.parquet"))
    total_files = len(all_files)
    
    if total_files == 0:
        print(f"❌ No part_*.parquet files found in {input_dir}")
        sys.exit(1)
    
    print(f"✓ Found {total_files:,} total parquet files")
    print()
    
    # Filter: only process files that are (1) completed backfill and (2) not already filtered
    to_process = []
    skipped_no_backfill = 0
    skipped_already_done = 0
    
    for f in sorted(all_files):
        if f.name in already_filtered:
            skipped_already_done += 1
            continue
        
        # If .backfill_progress exists, only process completed files
        if completed_backfill and f.name not in completed_backfill:
            skipped_no_backfill += 1
            continue
        
        to_process.append(f)
    
    print(f"Files to process:         {len(to_process):,}")
    print(f"Skipped (already filtered): {skipped_already_done:,}")
    print(f"Skipped (backfill pending): {skipped_no_backfill:,}")
    print()
    
    if len(to_process) == 0:
        print("✅ Nothing to do! All files are either filtered or waiting for backfill.")
        sys.exit(0)
    
    print(f"Processing {len(to_process):,} files...")
    print("=" * 70)
    
    # Process files
    success_count = 0
    for i, input_file in enumerate(to_process, 1):
        print(f"[{i}/{len(to_process)}]", end=" ")
        if filter_one_file(input_file, output_dir):
            success_count += 1
    
    print()
    print("=" * 70)
    print(f"Complete! {success_count}/{len(to_process)} files filtered successfully")
    print("=" * 70)
    
    if skipped_no_backfill > 0:
        print()
        print(f"Note: {skipped_no_backfill:,} files are waiting for backfill to complete.")
        print("      Run this script again after backfill finishes to process them.")


if __name__ == "__main__":
    main()
