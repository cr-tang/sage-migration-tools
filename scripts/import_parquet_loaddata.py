#!/usr/bin/env python3
"""Fast Parquet to TiDB import using LOAD DATA LOCAL INFILE.

This is significantly faster than row-by-row INSERT because:
1. Bulk data transfer in a single statement
2. Server-side optimized parsing
3. Minimal round trips

Usage:
    python3 import_parquet_loaddata.py /path/to/files/ --password <pwd>
    python3 import_parquet_loaddata.py file.parquet --password <pwd>
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
import os
import tempfile


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


def map_classification(cls):
    """Map classification string to ENUM value."""
    if pd.isna(cls) or not cls:
        return "UNKNOWN"
    cls = str(cls).upper()
    if cls in ("PUA", "UNWANTED"):
        return "UNWANTED"
    if cls in ("RANSOMWARE", "MALTOOL", "HACKTOOL", "MALWARE",
               "SUSPICIOUS", "BLACKLIST", "AV_DETECTED", "INDIFFERENT", "UNKNOWN"):
        return cls
    return "UNKNOWN"


CHUNK_SIZE = 150_000  # rows per LOAD DATA chunk (~150MB with full detection_names)
MAX_RETRIES = 3


def load_data_chunk(csv_path, host, port, user, password, database):
    """Execute LOAD DATA for a single CSV chunk with retry."""
    load_sql = """
    LOAD DATA LOCAL INFILE %s
    IGNORE INTO TABLE ioc_file_hashes
    FIELDS TERMINATED BY '\t'
    LINES TERMINATED BY '\n'
    (@sha256_hex, @sha1_hex, @md5_hex, classification, source,
     detection_names, scan_date, positives, total)
    SET
        sha256 = UNHEX(@sha256_hex),
        sha1 = UNHEX(@sha1_hex),
        md5 = UNHEX(@md5_hex)
    """

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            conn = mysql.connector.connect(
                host=host, port=port, user=user, password=password,
                database=database, charset="utf8mb4", autocommit=False,
                ssl_disabled=True, connection_timeout=30,
                allow_local_infile=True,
            )
            cursor = conn.cursor()
            cursor.execute("SET @@session.tidb_constraint_check_in_place = 0")
            cursor.execute(load_sql, (csv_path,))
            conn.commit()
            affected = cursor.rowcount
            cursor.close()
            conn.close()
            return affected
        except Error as e:
            if attempt < MAX_RETRIES:
                wait = 5 * attempt
                print(f"    ⚠️  Chunk failed (attempt {attempt}/{MAX_RETRIES}): {e}")
                print(f"    Retrying in {wait}s...")
                time.sleep(wait)
                try:
                    conn.close()
                except:
                    pass
            else:
                print(f"    ❌ Chunk failed after {MAX_RETRIES} attempts: {e}")
                try:
                    conn.close()
                except:
                    pass
                raise


def import_parquet_loaddata(
    parquet_file: str,
    host: str,
    port: int,
    user: str,
    password: str,
    database: str,
    delete_after_import: bool = False,
):
    """Import a Parquet file to TiDB via chunked LOAD DATA LOCAL INFILE."""

    basename = os.path.basename(parquet_file)
    print(f"\n{'='*80}")
    print(f"Importing: {basename}")
    print(f"{'='*80}")

    # ── Step 1: Read Parquet ──
    print(f"[1/3] Reading Parquet file...")
    t0 = time.time()
    try:
        df = pq.read_table(parquet_file).to_pandas()
    except Exception as e:
        print(f"❌ Failed to read Parquet: {e}")
        return False

    total_rows = len(df)
    print(f"  ✓ Read {total_rows:,} rows in {time.time()-t0:.1f}s")

    # ── Step 2: Preprocess (vectorized, fast) ──
    print(f"[2/3] Preprocessing...")
    t1 = time.time()

    df['cls'] = df['classification'].map(lambda x: map_classification(x))

    def clean_detection(x):
        if pd.isna(x) or not x:
            return "\\N"
        s = str(x)
        return s.replace('\\', '\\\\').replace('\t', ' ').replace('\n', ' ').replace('\r', ' ')

    df['det'] = df['detection_names'].map(clean_detection)

    if 'scan_date' in df.columns:
        dates = pd.to_datetime(df['scan_date'], errors='coerce')
        df['sd'] = dates.dt.strftime('%Y-%m-%d').fillna("\\N")
    else:
        df['sd'] = "\\N"

    for col, out in [('positives', 'pos'), ('total', 'tot')]:
        if col in df.columns:
            df[out] = df[col].apply(
                lambda x: str(int(min(max(x, 0), 255))) if pd.notna(x) else "\\N"
            )
        else:
            df[out] = "\\N"

    for h in ('sha256', 'sha1', 'md5'):
        df[h] = df[h].fillna('')

    # Build output dataframe
    out_df = df[['sha256', 'sha1', 'md5', 'cls', 'det', 'sd', 'pos', 'tot']].copy()
    out_df.insert(3, 'source', 'VIRUS_TOTAL')

    print(f"  ✓ Preprocessed in {time.time()-t1:.1f}s")

    # ── Step 3: Chunked LOAD DATA ──
    num_chunks = (total_rows + CHUNK_SIZE - 1) // CHUNK_SIZE
    print(f"[3/3] LOAD DATA in {num_chunks} chunks ({CHUNK_SIZE:,} rows each) → {host}:{port}...")
    t3 = time.time()

    total_inserted = 0
    failed_chunks = 0

    for chunk_idx in range(num_chunks):
        start = chunk_idx * CHUNK_SIZE
        end = min(start + CHUNK_SIZE, total_rows)
        chunk_df = out_df.iloc[start:end]
        chunk_rows = len(chunk_df)

        # Write chunk to temp CSV
        csv_path = f"/tmp/tidb_chunk_{os.getpid()}_{chunk_idx}.csv"
        chunk_df.to_csv(csv_path, sep='\t', header=False, index=False,
                        na_rep='\\N', escapechar=None, quoting=3)

        try:
            affected = load_data_chunk(csv_path, host, port, user, password, database)
            total_inserted += affected
            elapsed = time.time() - t3
            rate = total_inserted / elapsed if elapsed > 0 else 0
            pct = end * 100 // total_rows
            print(f"  Chunk {chunk_idx+1}/{num_chunks}: {chunk_rows:,} rows | "
                  f"Total: {total_inserted:,}/{total_rows:,} ({pct}%) | "
                  f"{rate:,.0f} rows/s")
        except Error:
            failed_chunks += 1
            print(f"  ❌ Chunk {chunk_idx+1}/{num_chunks} permanently failed, skipping")
        finally:
            try:
                os.unlink(csv_path)
            except:
                pass

    load_time = time.time() - t3
    total_time = time.time() - t0

    if failed_chunks > 0:
        print(f"\n⚠️  Completed with {failed_chunks} failed chunks")
        print(f"   Rows inserted:    {total_inserted:,}/{total_rows:,}")
        print(f"   Load time:        {load_time:.1f}s")
        print(f"   Total time:       {total_time:.1f}s")
        return False  # Don't mark as done so it can be retried
    else:
        print(f"\n✅ LOAD DATA completed!")
        print(f"   Rows inserted:    {total_inserted:,}")
        print(f"   Load time:        {load_time:.1f}s ({total_rows/load_time:,.0f} rows/s)")
        print(f"   Total time:       {total_time:.1f}s")

    if delete_after_import:
        try:
            os.remove(parquet_file)
            print(f"  🗑️  Deleted {parquet_file}")
        except Exception as e:
            print(f"  ⚠️  Failed to delete {parquet_file}: {e}")

    return True


def main():
    parser = argparse.ArgumentParser(
        description="Fast Parquet → TiDB import via LOAD DATA LOCAL INFILE",
    )
    parser.add_argument("paths", nargs="+", help="Parquet file(s) or directory")
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--port", type=int, default=4000)
    parser.add_argument("--user", default="root")
    parser.add_argument("--password", required=True)
    parser.add_argument("--database", default="threat_intel")
    parser.add_argument("--progress-file", type=str)
    parser.add_argument("--delete-after-import", action="store_true")

    args = parser.parse_args()

    # Collect files
    all_files = []
    base_dir = None
    for path_str in args.paths:
        path = Path(path_str)
        if path.is_dir():
            base_dir = path
            all_files.extend(sorted(path.glob("*.parquet")))
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

    # Progress file
    progress_file = Path(args.progress_file) if args.progress_file else base_dir / ".import_progress_local"
    completed = get_completed_files(progress_file)

    to_process = [f for f in all_files if f.name not in completed]
    skipped_count = len(all_files) - len(to_process)

    print("=" * 80)
    print("Fast Import (LOAD DATA LOCAL INFILE)")
    print("=" * 80)
    print(f"Total files:      {len(all_files):,}")
    print(f"Already imported: {skipped_count:,}")
    print(f"To process:       {len(to_process):,}")
    print(f"Progress file:    {progress_file}")
    print(f"Target:           {args.host}:{args.port}/{args.database}")
    print("=" * 80)

    if not to_process:
        print("\n✅ All files already imported!")
        sys.exit(0)

    success_count = 0
    total_start = time.time()

    for i, file in enumerate(to_process, 1):
        print(f"\n[{i}/{len(to_process)}] Processing: {file.name}")

        if import_parquet_loaddata(
            str(file), args.host, args.port, args.user, args.password,
            args.database, args.delete_after_import,
        ):
            mark_file_done(progress_file, file.name)
            success_count += 1
            print(f"  ✓ Marked {file.name} as completed")
        else:
            print(f"  ❌ Failed: {file.name}")

    total_elapsed = time.time() - total_start
    hours = int(total_elapsed // 3600)
    minutes = int((total_elapsed % 3600) // 60)

    print(f"\n{'='*80}")
    print(f"Import complete: {success_count}/{len(to_process)} files")
    print(f"Total time: {hours}h {minutes}m")
    print(f"{'='*80}")

    if success_count < len(to_process):
        sys.exit(1)


if __name__ == "__main__":
    main()
