#!/usr/bin/env python3
"""
Broccoli Updater - Update classification from GCS broccoli-enricher.

Features:
- Reads SHA1 hashes from database (records needing classification update)
- Fetches classification from GCS broccoli-enricher/latest-reports/
- Updates database records with new classification
- Final cleanup: delete records with unwanted classifications (INDIFFERENT, UNKNOWN)
- Batch processing with progress logging

Usage:
    python3 broccoli_updater.py --limit 1000  # Process first 1000 records
    python3 broccoli_updater.py --sha1-file /path/to/sha1_list.txt  # Use pre-exported list
    python3 broccoli_updater.py --dry-run  # Preview without updating
    python3 broccoli_updater.py --cleanup-only  # Only run cleanup (delete unwanted)
"""
import argparse
import json
import logging
import subprocess
import sys
import time
from typing import Optional, List, Dict, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

# MySQL connector
try:
    import mysql.connector
except ImportError:
    print("Error: mysql-connector-python not installed. Run: pip install mysql-connector-python")
    sys.exit(1)

# ----------------------------
# Constants
# ----------------------------
GCS_BUCKET = "gs://broccoli-enricher/latest-reports"
DEFAULT_BATCH_SIZE = 100
MAX_WORKERS = 10  # Parallel GCS fetches

# Classification mapping from Broccoli to our enum
CLASSIFICATION_MAP = {
    "malware": "MALWARE",
    "ransomware": "RANSOMWARE",
    "hacktool": "HACKTOOL",
    "unwanted": "UNWANTED",
    "suspicious": "SUSPICIOUS",
    "whitelist": "WHITELIST",
    "indifferent": "INDIFFERENT",
    "unknown": "UNKNOWN",
}

# Classifications to delete in final cleanup (not threats)
UNWANTED_CLASSIFICATIONS = {"INDIFFERENT", "UNKNOWN", "WHITELIST"}


# ----------------------------
# Logging setup
# ----------------------------
def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s | %(levelname)s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        handlers=[logging.StreamHandler(sys.stdout)],
    )
    return logging.getLogger(__name__)


logger = setup_logging()


# ----------------------------
# GCS Operations
# ----------------------------
def fetch_broccoli_classification(sha1: str) -> Optional[Dict]:
    """
    Fetch classification from GCS broccoli-enricher.
    
    Returns dict with format:
    {
        "sha1": "...",
        "classification": "malware",  # Top-level classification
        "engines": { ... }
    }
    Or None if not found.
    """
    gcs_path = f"{GCS_BUCKET}/{sha1.lower()}"
    try:
        result = subprocess.run(
            ["gcloud", "storage", "cat", gcs_path],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0 and result.stdout.strip():
            data = json.loads(result.stdout.strip())
            return data
    except subprocess.TimeoutExpired:
        logger.warning(f"Timeout fetching {sha1}")
    except json.JSONDecodeError as e:
        logger.warning(f"Invalid JSON for {sha1}: {e}")
    except Exception as e:
        logger.warning(f"Error fetching {sha1}: {e}")
    return None


def fetch_batch_classifications(sha1_list: List[str]) -> Dict[str, str]:
    """
    Fetch classifications for a batch of SHA1 hashes in parallel.
    Returns dict mapping sha1 -> classification.
    
    Broccoli response format:
    {
        "sha1": "...",
        "classification": "malware",  # Top-level classification
        "engines": {
            "green_olive": { "status": "SUCCESS", "classification": "malware", ... }
        }
    }
    
    Note: ALL classifications are returned (including INDIFFERENT, UNKNOWN).
    Unwanted classifications will be deleted in the final cleanup step.
    """
    results = {}
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_sha1 = {
            executor.submit(fetch_broccoli_classification, sha1): sha1
            for sha1 in sha1_list
        }
        for future in as_completed(future_to_sha1):
            sha1 = future_to_sha1[future]
            try:
                data = future.result()
                # Classification is at top level in broccoli response
                if data and data.get("classification"):
                    classification = data["classification"].lower()
                    # Map to our enum (include ALL, cleanup happens later)
                    mapped = CLASSIFICATION_MAP.get(classification, classification.upper())
                    results[sha1.lower()] = mapped
            except Exception as e:
                logger.warning(f"Error processing {sha1}: {e}")
    return results


# ----------------------------
# Database Operations
# ----------------------------
def get_empty_classification_sha1s(conn, limit: Optional[int] = None) -> List[str]:
    """
    Get SHA1 hashes for records with empty classification.
    Returns list of SHA1 hex strings (lowercase).
    """
    cursor = conn.cursor()
    sql = """
        SELECT LOWER(HEX(sha1)) 
        FROM ioc_file_hashes 
        WHERE (classification IS NULL OR classification = '') 
          AND sha1 IS NOT NULL
    """
    if limit:
        sql += f" LIMIT {limit}"
    
    cursor.execute(sql)
    results = [row[0] for row in cursor.fetchall()]
    cursor.close()
    return results


def update_classifications(conn, updates: Dict[str, str], dry_run: bool = False) -> int:
    """
    Update classification for records by SHA1.
    Returns number of updated records.
    """
    if not updates:
        return 0
    
    if dry_run:
        logger.info(f"[DRY RUN] Would update {len(updates)} records")
        for sha1, classification in list(updates.items())[:5]:
            logger.info(f"  {sha1} -> {classification}")
        if len(updates) > 5:
            logger.info(f"  ... and {len(updates) - 5} more")
        return 0
    
    cursor = conn.cursor()
    updated = 0
    
    for sha1, classification in updates.items():
        try:
            cursor.execute(
                "UPDATE ioc_file_hashes SET classification = %s WHERE sha1 = UNHEX(%s)",
                (classification, sha1)
            )
            updated += cursor.rowcount
        except Exception as e:
            logger.warning(f"Error updating {sha1}: {e}")
    
    conn.commit()
    cursor.close()
    return updated


def cleanup_unwanted_classifications(conn, dry_run: bool = False) -> Tuple[int, Dict[str, int]]:
    """
    Delete records with unwanted classifications (INDIFFERENT, UNKNOWN, WHITELIST).
    
    Returns:
        - Total deleted count
        - Dict mapping classification -> count
    """
    cursor = conn.cursor()
    
    # First, count by classification
    counts = {}
    for classification in UNWANTED_CLASSIFICATIONS:
        cursor.execute(
            "SELECT COUNT(*) FROM ioc_file_hashes WHERE classification = %s",
            (classification,)
        )
        count = cursor.fetchone()[0]
        if count > 0:
            counts[classification] = count
    
    total = sum(counts.values())
    
    if total == 0:
        logger.info("No records with unwanted classifications to delete")
        cursor.close()
        return 0, counts
    
    logger.info(f"Found {total:,} records with unwanted classifications:")
    for classification, count in sorted(counts.items()):
        logger.info(f"  {classification}: {count:,}")
    
    if dry_run:
        logger.info(f"[DRY RUN] Would delete {total:,} records")
        cursor.close()
        return 0, counts
    
    # Delete in batches to avoid long locks
    deleted_total = 0
    batch_size = 10000
    
    for classification in UNWANTED_CLASSIFICATIONS:
        if classification not in counts:
            continue
        
        logger.info(f"Deleting {classification} records...")
        deleted_class = 0
        
        while True:
            cursor.execute(
                f"DELETE FROM ioc_file_hashes WHERE classification = %s LIMIT {batch_size}",
                (classification,)
            )
            deleted = cursor.rowcount
            conn.commit()
            deleted_class += deleted
            deleted_total += deleted
            
            if deleted < batch_size:
                break
            
            logger.info(f"  Deleted {deleted_class:,} / {counts[classification]:,}...")
        
        logger.info(f"  {classification}: deleted {deleted_class:,} records")
    
    cursor.close()
    return deleted_total, counts


# ----------------------------
# Main
# ----------------------------
def main():
    parser = argparse.ArgumentParser(description="Update classification from Broccoli enricher")
    parser.add_argument("--host", default="localhost", help="Database host")
    parser.add_argument("--port", type=int, default=3306, help="Database port")
    parser.add_argument("--user", default="root", help="Database user")
    parser.add_argument("--password", default="", help="Database password")
    parser.add_argument("--database", default="threat_intel", help="Database name")
    parser.add_argument("--limit", type=int, help="Limit number of records to process")
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE, help="Batch size for GCS fetches")
    parser.add_argument("--sha1-file", help="File containing SHA1 hashes (one per line)")
    parser.add_argument("--dry-run", action="store_true", help="Preview without updating")
    parser.add_argument("--cleanup-only", action="store_true", help="Only run cleanup (delete unwanted classifications)")
    parser.add_argument("--skip-cleanup", action="store_true", help="Skip final cleanup step")
    args = parser.parse_args()
    
    logger.info("Starting Broccoli Updater")
    logger.info(f"GCS bucket: {GCS_BUCKET}")
    
    # Connect to database
    conn = mysql.connector.connect(
        host=args.host,
        port=args.port,
        user=args.user,
        password=args.password,
        database=args.database,
    )
    logger.info(f"Connected to {args.host}:{args.port}/{args.database}")
    
    # Cleanup-only mode
    if args.cleanup_only:
        logger.info("Running cleanup only (delete unwanted classifications)")
        deleted, counts = cleanup_unwanted_classifications(conn, args.dry_run)
        logger.info("=" * 60)
        logger.info(f"Cleanup complete: {deleted:,} records deleted")
        conn.close()
        return
    
    # Get SHA1 list
    if args.sha1_file:
        logger.info(f"Reading SHA1 list from {args.sha1_file}")
        with open(args.sha1_file, 'r') as f:
            sha1_list = [line.strip().lower() for line in f if line.strip()]
    else:
        logger.info("Fetching SHA1 hashes with empty classification from database...")
        sha1_list = get_empty_classification_sha1s(conn, args.limit)
    
    logger.info(f"Found {len(sha1_list)} SHA1 hashes to process")
    
    if not sha1_list:
        logger.info("No records to update")
        # Still run cleanup if not skipped
        if not args.skip_cleanup:
            logger.info("")
            logger.info("Running final cleanup...")
            deleted, _ = cleanup_unwanted_classifications(conn, args.dry_run)
            logger.info(f"Cleanup: {deleted:,} records deleted")
        conn.close()
        return
    
    # Process in batches
    total_found = 0
    total_updated = 0
    
    for i in range(0, len(sha1_list), args.batch_size):
        batch = sha1_list[i:i + args.batch_size]
        batch_num = i // args.batch_size + 1
        total_batches = (len(sha1_list) + args.batch_size - 1) // args.batch_size
        
        logger.info(f"Processing batch {batch_num}/{total_batches} ({len(batch)} hashes)...")
        
        # Fetch classifications from GCS
        classifications = fetch_batch_classifications(batch)
        total_found += len(classifications)
        
        # Update database
        updated = update_classifications(conn, classifications, args.dry_run)
        total_updated += updated
        
        logger.info(f"  Found: {len(classifications)}, Updated: {updated}")
        
        # Brief pause to avoid overwhelming GCS
        if i + args.batch_size < len(sha1_list):
            time.sleep(1)
    
    # Summary
    logger.info("=" * 60)
    logger.info("Classification Update Summary:")
    logger.info(f"  Total SHA1s processed: {len(sha1_list)}")
    logger.info(f"  Classifications found in Broccoli: {total_found}")
    logger.info(f"  Records updated: {total_updated}")
    logger.info(f"  Not found in Broccoli: {len(sha1_list) - total_found}")
    
    # Final cleanup
    if not args.skip_cleanup:
        logger.info("")
        logger.info("Running final cleanup (delete unwanted classifications)...")
        deleted, counts = cleanup_unwanted_classifications(conn, args.dry_run)
        logger.info(f"Cleanup: {deleted:,} records deleted")
    else:
        logger.info("")
        logger.info("Skipping cleanup (use --cleanup-only later to delete unwanted)")
    
    conn.close()
    logger.info("=" * 60)
    logger.info("Done!")


if __name__ == "__main__":
    main()
