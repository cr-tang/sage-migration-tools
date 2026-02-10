#!/usr/bin/env python3
"""Import Parquet files to TiDB via MySQL protocol with auto-resume.

Usage:
    # Import from directory (recommended)
    python3 import_parquet_to_tidb.py /tmp/parquet_files/ --password <pwd>
    
    # Import single file
    python3 import_parquet_to_tidb.py part_0000.parquet --password <pwd>

    # Import multiple files
    python3 import_parquet_to_tidb.py part_*.parquet --password <pwd>
"""

import argparse
import pyarrow.parquet as pq
import mysql.connector
from mysql.connector import Error
import sys
import time
import pandas as pd
from pathlib import Path
import fcntl


def mark_file_done(progress_file: Path, filename: str):
    """Mark a file as successfully imported (thread-safe with file locking)."""
    with open(progress_file, "a") as f:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        try:
            f.write(f"{filename}\n")
            f.flush()
        finally:
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)


def get_completed_files(progress_file: Path) -> set:
    """Read the progress file to get list of completed imports."""
    if not progress_file.exists():
        return set()
    
    with open(progress_file, "r") as f:
        return set(line.strip() for line in f if line.strip())


def import_parquet_to_tidb(
    parquet_file: str,
    host: str,
    port: int,
    user: str,
    password: str,
    database: str,
    batch_size: int = 5000,
):
    """Import a pre-filtered Parquet file to TiDB."""

    print(f"\n{'='*80}")
    print(f"Importing: {parquet_file}")
    print(f"{'='*80}")

    # Read Parquet
    print(f"[1/3] Reading Parquet file...")
    t0 = time.time()
    try:
        table = pq.read_table(parquet_file)
        df = table.to_pandas()
    except Exception as e:
        print(f"❌ Failed to read Parquet: {e}")
        return False

    read_time = time.time() - t0
    print(f"  ✓ Read {len(df):,} rows in {read_time:.1f}s")

    # Vectorized preprocessing (much faster than iterrows)
    print(f"[2/4] Preprocessing data (vectorized)...")
    t0_prep = time.time()
    
    # Convert hex strings to bytes (vectorized)
    df['sha256_bin'] = df['sha256'].apply(lambda x: bytes.fromhex(x) if pd.notna(x) and x else None)
    df['sha1_bin'] = df['sha1'].apply(lambda x: bytes.fromhex(x) if pd.notna(x) and x else None)
    df['md5_bin'] = df['md5'].apply(lambda x: bytes.fromhex(x) if pd.notna(x) and x else None)
    
    # Map classifications (vectorized)
    def map_classification(cls):
        if pd.isna(cls) or not cls:
            return "UNKNOWN"
        cls = str(cls).upper()
        if cls in ["PUA", "UNWANTED"]:
            return "UNWANTED"
        if cls in ["RANSOMWARE", "MALTOOL", "HACKTOOL", "MALWARE", "SUSPICIOUS", "BLACKLIST", "AV_DETECTED", "INDIFFERENT", "UNKNOWN"]:
            return cls
        return "UNKNOWN"
    
    df['classification_mapped'] = df['classification'].apply(map_classification)
    df['detection_names_clean'] = df['detection_names'].where(df['detection_names'].notna(), None)
    
    prep_time = time.time() - t0_prep
    print(f"  ✓ Preprocessed {len(df):,} rows in {prep_time:.1f}s")

    # Connect to TiDB
    print(f"[3/4] Connecting to TiDB at {host}:{port}...")
    try:
        conn = mysql.connector.connect(
            host=host,
            port=port,
            user=user,
            password=password,
            database=database,
            charset="utf8mb4",
            autocommit=False,
            ssl_disabled=True,  # Disable SSL for TiDB
        )
        cursor = conn.cursor()
        print(f"  ✓ Connected to database '{database}'")
    except Error as e:
        print(f"❌ Connection failed: {e}")
        return False

    # Prepare INSERT statement with IGNORE to skip duplicates silently
    # Note: Using INSERT IGNORE for safety in case of unexpected duplicates
    insert_sql = """
    INSERT IGNORE INTO ioc_file_hashes 
    (sha256, sha1, md5, classification, source, detection_names)
    VALUES (%s, %s, %s, %s, %s, %s)
    """

    # Batch insert with retry on transient errors
    print(f"[4/4] Inserting data (batch size: {batch_size:,})...")
    t0 = time.time()
    rows_inserted = 0
    rows_skipped = 0
    errors = 0
    max_retries = 3

    try:
        for i in range(0, len(df), batch_size):
            batch = df.iloc[i : i + batch_size]
            
            # Convert to list of tuples (FAST - no iterrows!)
            values = list(zip(
                batch['sha256_bin'],
                batch['sha1_bin'],
                batch['md5_bin'],
                batch['classification_mapped'],
                ['VIRUS_TOTAL'] * len(batch),  # source
                batch['detection_names_clean']
            ))

            # Retry logic for transient errors
            retry_count = 0
            while retry_count < max_retries:
                try:
                    cursor.executemany(insert_sql, values)
                    conn.commit()
                    
                    # Check affected rows (INSERT IGNORE may skip duplicates)
                    affected = cursor.rowcount
                    rows_inserted += affected
                    rows_skipped += len(values) - affected
                    break  # Success, exit retry loop
                    
                except Error as e:
                    retry_count += 1
                    if retry_count >= max_retries:
                        print(f"\n❌ Batch insert failed after {max_retries} retries: {e}")
                        errors += len(values)
                        conn.rollback()
                        break  # Give up on this batch
                    else:
                        print(f"\n⚠️  Retry {retry_count}/{max_retries} for batch at offset {i}: {e}")
                        time.sleep(1 * retry_count)  # Exponential backoff
                        conn.rollback()

            elapsed = time.time() - t0
            rate = rows_inserted / elapsed if elapsed > 0 else 0
            pct = (i + len(batch)) * 100 // len(df)

            print(
                f"  Progress: {rows_inserted:,}/{len(df):,} ({pct}%) | "
                f"{rate:.0f} rows/s | "
                f"{elapsed:.0f}s elapsed"
                + (f" | {rows_skipped:,} skipped" if rows_skipped > 0 else "")
                + (f" | {errors:,} errors" if errors > 0 else "")
            )

        insert_time = time.time() - t0
        print(f"\n✅ Successfully imported {rows_inserted:,} rows in {insert_time:.1f}s")
        print(f"   Average rate: {rows_inserted/insert_time:.0f} rows/s")
        if rows_skipped > 0:
            print(f"   Skipped (duplicates): {rows_skipped:,}")
        if errors > 0:
            print(f"   Failed rows: {errors:,}")

        cursor.close()
        conn.close()
        return True

    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        conn.rollback()
        cursor.close()
        conn.close()
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Import Parquet to TiDB with auto-resume",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Import from directory (auto-resume supported)
  python3 import_parquet_to_tidb.py /tmp/parquet_files/ --password mypass
  
  # Import single file
  python3 import_parquet_to_tidb.py part_0000.parquet --password mypass

  # Import with custom batch size
  python3 import_parquet_to_tidb.py /tmp/parquet_files/ --password mypass --batch-size 10000
  
  # Specify custom progress file location
  python3 import_parquet_to_tidb.py /tmp/parquet_files/ --password mypass --progress-file /tmp/.import_progress
        """,
    )
    parser.add_argument("paths", nargs="+", help="Parquet file(s) or directory to import")
    parser.add_argument("--host", default="localhost", help="TiDB host (default: localhost)")
    parser.add_argument("--port", type=int, default=4000, help="TiDB port (default: 4000)")
    parser.add_argument("--user", default="root", help="TiDB user (default: root)")
    parser.add_argument("--password", required=True, help="TiDB password")
    parser.add_argument(
        "--database", default="threat_intel", help="Database name (default: threat_intel)"
    )
    parser.add_argument(
        "--batch-size", type=int, default=5000, help="Batch size (default: 5000)"
    )
    parser.add_argument(
        "--progress-file", 
        type=str, 
        help="Progress file path (default: .import_progress in same directory as files)"
    )

    args = parser.parse_args()

    # Collect all Parquet files
    all_files = []
    base_dir = None
    
    for path_str in args.paths:
        path = Path(path_str)
        if path.is_dir():
            base_dir = path
            # Find all .parquet files in directory
            parquet_files = sorted(path.glob("*.parquet"))
            all_files.extend(parquet_files)
        elif path.exists():
            all_files.append(path)
            if base_dir is None:
                base_dir = path.parent
        else:
            print(f"❌ Path not found: {path}")
            sys.exit(1)

    if not all_files:
        print("❌ No Parquet files found")
        sys.exit(1)
    
    # Determine progress file location
    if args.progress_file:
        progress_file = Path(args.progress_file)
    else:
        progress_file = base_dir / ".import_progress"
    
    # Get completed files
    completed = get_completed_files(progress_file)
    
    # Filter out already completed files
    to_process = []
    skipped_count = 0
    for f in all_files:
        if f.name in completed:
            skipped_count += 1
        else:
            to_process.append(f)
    
    print("="*80)
    print(f"Import Parquet to TiDB - Auto Resume")
    print("="*80)
    print(f"Total files found:     {len(all_files):,}")
    print(f"Already imported:      {skipped_count:,}")
    print(f"To process:            {len(to_process):,}")
    print(f"Progress file:         {progress_file}")
    print(f"Target:                {args.host}:{args.port}/{args.database}")
    print("="*80)
    
    if not to_process:
        print("\n✅ All files already imported!")
        sys.exit(0)

    # Import each file
    success_count = 0
    for i, file in enumerate(to_process, 1):
        print(f"\n[{i}/{len(to_process)}] Processing: {file.name}")
        
        if import_parquet_to_tidb(
            str(file),
            args.host,
            args.port,
            args.user,
            args.password,
            args.database,
            args.batch_size,
        ):
            # Mark as done
            mark_file_done(progress_file, file.name)
            success_count += 1
            print(f"  ✓ Marked {file.name} as completed")
        else:
            print(f"  ❌ Failed to import {file.name}")
            # Don't mark as done, can retry later

    print(f"\n{'='*80}")
    print(f"Import complete: {success_count}/{len(to_process)} files succeeded")
    
    if success_count < len(to_process):
        failed = len(to_process) - success_count
        print(f"⚠️  {failed} file(s) failed - you can re-run to retry")
    else:
        print(f"✅ All files imported successfully!")
    
    print(f"{'='*80}")

    if success_count < len(to_process):
        sys.exit(1)


if __name__ == "__main__":
    main()
