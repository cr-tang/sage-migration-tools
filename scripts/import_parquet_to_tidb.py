#!/usr/bin/env python3
"""Import Parquet files to TiDB via MySQL protocol.

Usage:
    # Port-forward to TiDB first
    kubectl port-forward -n <namespace> svc/tidb 4000:4000

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


def import_parquet_to_tidb(
    parquet_file: str,
    host: str,
    port: int,
    user: str,
    password: str,
    database: str,
    batch_size: int = 5000,
    filter_classifications: bool = True,
):
    """Import a single Parquet file to TiDB."""

    print(f"\n{'='*80}")
    print(f"Importing: {parquet_file}")
    print(f"{'='*80}")

    # Read Parquet
    print(f"[1/4] Reading Parquet file...")
    t0 = time.time()
    try:
        table = pq.read_table(parquet_file)
        df = table.to_pandas()
    except Exception as e:
        print(f"❌ Failed to read Parquet: {e}")
        return False

    read_time = time.time() - t0
    original_count = len(df)
    print(f"  ✓ Read {original_count:,} rows in {read_time:.1f}s")

    # Filter classifications
    if filter_classifications:
        print(f"[2/4] Filtering classifications...")
        # Keep: malware, ransomware, unwanted (PUA), hacktool
        # Filter out: indifferent, unknown, whitelist, NULL
        filter_out = {'indifferent', 'unknown', 'whitelist'}
        before = len(df)
        df = df[
            df['classification'].notna() &
            ~df['classification'].isin(filter_out)
        ]
        after = len(df)
        filtered = before - after
        print(f"  ✓ Filtered out {filtered:,} rows ({filtered/before*100:.1f}%)")
        print(f"  ✓ Remaining: {after:,} rows ({after/before*100:.1f}%)")
    else:
        print(f"[2/4] Skipping classification filter (importing all rows)")

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

    # Prepare INSERT statement (now with scan_date, positives, total)
    insert_sql = """
    INSERT INTO ioc_file_hashes 
    (sha256, sha1, md5, classification, source, detection_names, scan_date, positives, total)
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
    ON DUPLICATE KEY UPDATE
        classification = VALUES(classification),
        detection_names = VALUES(detection_names),
        scan_date = VALUES(scan_date),
        positives = VALUES(positives),
        total = VALUES(total)
    """

    # Batch insert
    print(f"[4/4] Inserting data (batch size: {batch_size:,})...")
    t0 = time.time()
    rows_inserted = 0
    errors = 0

    try:
        for i in range(0, len(df), batch_size):
            batch = df.iloc[i : i + batch_size]
            values = []

            for _, row in batch.iterrows():
                # Convert hex string SHA to binary
                sha256_bin = bytes.fromhex(row["sha256"]) if row["sha256"] else None
                sha1_bin = bytes.fromhex(row["sha1"]) if row["sha1"] else None
                md5_bin = bytes.fromhex(row["md5"]) if row["md5"] else None
                
                # Map classification to TiDB enum values
                classification = row["classification"]
                if classification and not (isinstance(classification, float) and pd.isna(classification)):
                    classification = str(classification).upper()
                    # Map broccoli values to TiDB enum
                    if classification == "PUA" or classification == "UNWANTED":
                        classification = "UNWANTED"
                    elif classification not in ["RANSOMWARE", "MALTOOL", "HACKTOOL", "UNWANTED", "MALWARE", "SUSPICIOUS", "BLACKLIST", "AV_DETECTED", "INDIFFERENT", "UNKNOWN"]:
                        classification = "UNKNOWN"
                else:
                    classification = "UNKNOWN"
                
                # Parse scan_date (format: "2024-12-23" -> date)
                scan_date = None
                if "scan_date" in row and row["scan_date"] and not pd.isna(row["scan_date"]):
                    scan_date_str = str(row["scan_date"])[:10]  # Take YYYY-MM-DD part
                    scan_date = scan_date_str if scan_date_str else None
                
                # Get positives and total (capped at 255 for TINYINT UNSIGNED)
                positives = None
                total = None
                if "positives" in row and not pd.isna(row["positives"]):
                    positives = min(int(row["positives"]), 255)
                if "total" in row and not pd.isna(row["total"]):
                    total = min(int(row["total"]), 255)
                
                values.append(
                    (
                        sha256_bin,
                        sha1_bin,
                        md5_bin,
                        classification,
                        "VIRUS_TOTAL",  # source
                        row["detection_names"] if row["detection_names"] else None,
                        scan_date,
                        positives,
                        total,
                    )
                )

            cursor.executemany(insert_sql, values)
            conn.commit()

            rows_inserted += len(values)
            elapsed = time.time() - t0
            rate = rows_inserted / elapsed if elapsed > 0 else 0
            pct = rows_inserted * 100 // len(df)

            print(
                f"  Progress: {rows_inserted:,}/{len(df):,} ({pct}%) | "
                f"{rate:.0f} rows/s | "
                f"{elapsed:.0f}s elapsed"
            )

        insert_time = time.time() - t0
        print(f"\n✅ Successfully imported {rows_inserted:,} rows in {insert_time:.1f}s")
        print(f"   Average rate: {rows_inserted/insert_time:.0f} rows/s")

        cursor.close()
        conn.close()
        return True

    except Error as e:
        print(f"\n❌ Insert failed: {e}")
        conn.rollback()
        cursor.close()
        conn.close()
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Import Parquet to TiDB",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Port-forward to TiDB first
  kubectl port-forward -n prod svc/tidb 4000:4000

  # Import single file
  python3 import_parquet_to_tidb.py part_0000.parquet --password mypass

  # Import with custom batch size
  python3 import_parquet_to_tidb.py part_0000.parquet --password mypass --batch-size 10000
        """,
    )
    parser.add_argument("files", nargs="+", help="Parquet files to import")
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
        "--no-filter",
        action="store_true",
        help="Disable classification filtering (import all rows including indifferent/unknown)",
    )

    args = parser.parse_args()

    # Check files exist
    for file in args.files:
        if not Path(file).exists():
            print(f"❌ File not found: {file}")
            sys.exit(1)

    print(f"Found {len(args.files)} file(s) to import")

    # Import each file
    success_count = 0
    for file in args.files:
        if import_parquet_to_tidb(
            file,
            args.host,
            args.port,
            args.user,
            args.password,
            args.database,
            args.batch_size,
            filter_classifications=not args.no_filter,
        ):
            success_count += 1

    print(f"\n{'='*80}")
    print(f"Import complete: {success_count}/{len(args.files)} files succeeded")
    print(f"{'='*80}")

    if success_count < len(args.files):
        sys.exit(1)


if __name__ == "__main__":
    main()
