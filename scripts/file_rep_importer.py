#!/usr/bin/env python3
"""
File Rep Importer - Import processed file_rep NDJSON.gz files into ioc_file_hashes table.

Features:
- Reads gzipped NDJSON files from BSON processor output
- Converts hex hash strings to binary for storage
- Infers classification from detection names when missing
- Batch inserts for performance
- Progress logging and resume support via checkpoint

Usage:
    python3 file_rep_importer.py --input file_rep_r06.ndjson.gz
    python3 file_rep_importer.py --input "file_rep_*.ndjson.gz" --batch-size 5000
    python3 file_rep_importer.py --input file_rep_r01.ndjson.gz --resume
"""
import gzip
import json
import os
import sys
import argparse
import glob
import time
import logging
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass, asdict

# MySQL connector
try:
    import mysql.connector
    from mysql.connector import pooling
except ImportError:
    print("Error: mysql-connector-python not installed. Run: pip install mysql-connector-python")
    sys.exit(1)


# ----------------------------
# Constants
# ----------------------------
VALID_CLASSIFICATIONS = {
    "ransomware", "maltool", "hacktool", "unwanted", "malware",
    "suspicious", "blacklist", "av_detected", "whitelist", "indifferent", "unknown"
}

# Classifications to skip (not useful for threat detection)
SKIP_CLASSIFICATIONS = {"indifferent", "unknown", "whitelist"}

DEFAULT_SOURCE = "VIRUS_TOTAL"

# Skip reason tracking
class SkipReason:
    NO_SHA256 = "no_sha256"
    WHITELIST = "whitelist"
    INDIFFERENT = "indifferent"
    UNKNOWN = "unknown"
    NO_THREAT = "no_threat_indicators"
    DUPLICATE = "duplicate"
    INVALID_JSON = "invalid_json"

# Batch size for inserts
DEFAULT_BATCH_SIZE = 1000


# ----------------------------
# Logging setup
# ----------------------------
def setup_logging(log_file: Optional[str] = None):
    handlers = [logging.StreamHandler(sys.stdout)]
    if log_file:
        handlers.append(logging.FileHandler(log_file, mode='a'))
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s | %(levelname)s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        handlers=handlers,
    )
    return logging.getLogger(__name__)


# ----------------------------
# Data transformation
# ----------------------------
def hex_to_bytes(hex_str: Optional[str]) -> Optional[bytes]:
    """Convert hex string to bytes for BINARY column storage."""
    if not hex_str:
        return None
    try:
        return bytes.fromhex(hex_str.lower())
    except ValueError:
        return None


def infer_classification(classification: Optional[str], detections: Optional[str], positives: int) -> Optional[str]:
    """
    Infer classification when VT classifier didn't provide one.
    Uses detection name patterns to determine likely classification.
    Returns uppercase enum value for TiDB.
    """
    # If valid classification exists, use it (uppercase for DB enum)
    if classification:
        classification_lower = classification.lower()
        if classification_lower in SKIP_CLASSIFICATIONS:
            return None  # Skip clean classifications
        if classification_lower in VALID_CLASSIFICATIONS:
            return classification.upper()
    
    # Infer from detection names
    if detections:
        detections_lower = detections.lower()
        
        # Priority order: ransomware > hacktool > unwanted > malware
        if any(kw in detections_lower for kw in ["ransom", "crypt", "locker", "wannacry", "petya"]):
            return "RANSOMWARE"
        if any(kw in detections_lower for kw in ["hacktool", "hack tool", "exploit", "mimikatz", "metasploit"]):
            return "HACKTOOL"
        if any(kw in detections_lower for kw in ["adware", "pup", "pua", "unwanted", "bundler", "toolbar", "installcore"]):
            return "UNWANTED"
        if any(kw in detections_lower for kw in ["trojan", "malware", "virus", "worm", "backdoor", "spyware", "rootkit", "keylogger"]):
            return "MALWARE"
    
    # Fallback based on positives count
    if positives >= 10:
        return "MALWARE"
    elif positives > 0:
        return "AV_DETECTED"
    
    return None  # No threat indicators, skip


def transform_record(record: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """
    Transform a record from NDJSON format to TiDB format.
    Returns (transformed_record, skip_reason) - skip_reason is None if record is valid.
    """
    sha256 = record.get("sha256")
    sha1 = record.get("sha1")
    md5 = record.get("md5")
    
    # Skip records without sha256 (primary key)
    if not sha256:
        return None, SkipReason.NO_SHA256
    
    positives = record.get("positives", 0)
    if isinstance(positives, float):
        positives = int(positives)
    
    # Check classification for skip reason
    orig_classification = record.get("classification")
    if orig_classification:
        orig_lower = orig_classification.lower()
        if orig_lower == "whitelist":
            return None, SkipReason.WHITELIST
        if orig_lower == "indifferent":
            return None, SkipReason.INDIFFERENT
        if orig_lower == "unknown":
            return None, SkipReason.UNKNOWN
    
    classification = infer_classification(
        orig_classification,
        record.get("detections"),
        positives
    )
    
    # Skip records without valid classification
    if not classification:
        return None, SkipReason.NO_THREAT
    
    return {
        "sha256": hex_to_bytes(sha256),
        "sha1": hex_to_bytes(sha1),
        "md5": hex_to_bytes(md5),
        "classification": classification,
        "source": DEFAULT_SOURCE,
        "detection_names": record.get("detections"),  # Keep original format: "engine:result;..."
    }, None


# ----------------------------
# Checkpoint management
# ----------------------------
@dataclass
class ImportCheckpoint:
    input_file: str
    lines_processed: int
    records_imported: int
    records_skipped: int
    last_update: float


def save_checkpoint(checkpoint: ImportCheckpoint, checkpoint_file: str):
    checkpoint.last_update = time.time()
    with open(checkpoint_file, "w") as f:
        json.dump(asdict(checkpoint), f, indent=2)


def load_checkpoint(checkpoint_file: str) -> Optional[ImportCheckpoint]:
    if not os.path.exists(checkpoint_file):
        return None
    try:
        with open(checkpoint_file, "r") as f:
            data = json.load(f)
        return ImportCheckpoint(**data)
    except Exception as e:
        logging.warning(f"Failed to load checkpoint: {e}")
        return None


# ----------------------------
# TiDB operations
# ----------------------------
class TiDBImporter:
    def __init__(self, host: str, port: int, user: str, password: str, database: str, pool_size: int = 5):
        self.config = {
            "host": host,
            "port": port,
            "user": user,
            "password": password,
            "database": database,
        }
        self.pool = pooling.MySQLConnectionPool(
            pool_name="tidb_pool",
            pool_size=pool_size,
            **self.config
        )
        self.logger = logging.getLogger(__name__)
    
    def test_connection(self) -> bool:
        """Test database connection."""
        try:
            conn = self.pool.get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT 1")
            cursor.fetchone()
            cursor.close()
            conn.close()
            return True
        except Exception as e:
            self.logger.error(f"Connection test failed: {e}")
            return False
    
    def batch_insert(self, records: List[Dict[str, Any]]) -> Tuple[int, int]:
        """
        Batch insert records into ioc_file_hashes table.
        Uses INSERT IGNORE to skip duplicates.
        Returns (inserted_count, skipped_count).
        """
        if not records:
            return 0, 0
        
        sql = """
            INSERT IGNORE INTO ioc_file_hashes 
            (sha256, sha1, md5, classification, source, detection_names)
            VALUES (%s, %s, %s, %s, %s, %s)
        """
        
        values = [
            (
                r["sha256"],
                r["sha1"],
                r["md5"],
                r["classification"],
                r["source"],
                r["detection_names"],
            )
            for r in records
        ]
        
        try:
            conn = self.pool.get_connection()
            cursor = conn.cursor()
            cursor.executemany(sql, values)
            conn.commit()
            inserted = cursor.rowcount
            skipped = len(records) - inserted
            cursor.close()
            conn.close()
            return inserted, skipped
        except Exception as e:
            self.logger.error(f"Batch insert failed: {e}")
            raise
    
    def get_count(self) -> int:
        """Get current record count in table."""
        try:
            conn = self.pool.get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM ioc_file_hashes")
            count = cursor.fetchone()[0]
            cursor.close()
            conn.close()
            return count
        except Exception as e:
            self.logger.error(f"Count query failed: {e}")
            return -1


# ----------------------------
# Main import logic
# ----------------------------
def import_file(
    importer: TiDBImporter,
    input_file: str,
    batch_size: int,
    resume: bool,
    logger: logging.Logger,
) -> Tuple[int, int, int, Dict[str, int]]:
    """
    Import a single NDJSON.gz file into TiDB.
    Returns (lines_processed, records_imported, records_skipped, skip_reasons).
    """
    checkpoint_file = input_file + ".import_checkpoint"
    checkpoint = load_checkpoint(checkpoint_file) if resume else None
    
    start_line = 0
    total_imported = 0
    total_skipped = 0
    skip_reasons: Dict[str, int] = {}
    
    if checkpoint and checkpoint.input_file == input_file:
        start_line = checkpoint.lines_processed
        total_imported = checkpoint.records_imported
        total_skipped = checkpoint.records_skipped
        logger.info(f"Resuming from line {start_line:,} (imported: {total_imported:,}, skipped: {total_skipped:,})")
    
    batch: List[Dict[str, Any]] = []
    lines_processed = 0
    
    start_time = time.time()
    last_log_time = start_time
    
    with gzip.open(input_file, 'rt', encoding='utf-8') as f:
        for line_num, line in enumerate(f):
            if line_num < start_line:
                continue
            
            lines_processed = line_num + 1
            
            try:
                record = json.loads(line.strip())
                transformed, skip_reason = transform_record(record)
                
                if transformed:
                    batch.append(transformed)
                else:
                    total_skipped += 1
                    if skip_reason:
                        skip_reasons[skip_reason] = skip_reasons.get(skip_reason, 0) + 1
                
                # Batch insert
                if len(batch) >= batch_size:
                    inserted, skipped = importer.batch_insert(batch)
                    total_imported += inserted
                    if skipped > 0:
                        skip_reasons[SkipReason.DUPLICATE] = skip_reasons.get(SkipReason.DUPLICATE, 0) + skipped
                    total_skipped += skipped
                    batch = []
                    
                    # Progress logging (every 30 seconds)
                    now = time.time()
                    if now - last_log_time >= 30:
                        elapsed = now - start_time
                        rate = (lines_processed - start_line) / elapsed if elapsed > 0 else 0
                        logger.info(
                            f"Progress: {lines_processed:,} lines | "
                            f"Imported: {total_imported:,} | Skipped: {total_skipped:,} | "
                            f"Rate: {rate:.1f} lines/sec"
                        )
                        last_log_time = now
                        
                        # Save checkpoint
                        save_checkpoint(
                            ImportCheckpoint(
                                input_file=input_file,
                                lines_processed=lines_processed,
                                records_imported=total_imported,
                                records_skipped=total_skipped,
                                last_update=now,
                            ),
                            checkpoint_file,
                        )
            
            except json.JSONDecodeError as e:
                logger.warning(f"Invalid JSON at line {line_num + 1}: {e}")
                total_skipped += 1
                skip_reasons[SkipReason.INVALID_JSON] = skip_reasons.get(SkipReason.INVALID_JSON, 0) + 1
    
    # Final batch
    if batch:
        inserted, skipped = importer.batch_insert(batch)
        total_imported += inserted
        if skipped > 0:
            skip_reasons[SkipReason.DUPLICATE] = skip_reasons.get(SkipReason.DUPLICATE, 0) + skipped
        total_skipped += skipped
    
    # Final checkpoint
    save_checkpoint(
        ImportCheckpoint(
            input_file=input_file,
            lines_processed=lines_processed,
            records_imported=total_imported,
            records_skipped=total_skipped,
            last_update=time.time(),
        ),
        checkpoint_file,
    )
    
    return lines_processed, total_imported, total_skipped, skip_reasons


def main():
    parser = argparse.ArgumentParser(description="Import NDJSON.gz files into TiDB ioc_file_hashes table")
    parser.add_argument("--input", type=str, required=True, help="Input file(s) glob pattern (e.g., 'file_rep_*.ndjson.gz')")
    parser.add_argument("--host", type=str, default="localhost", help="TiDB host (default: localhost)")
    parser.add_argument("--port", type=int, default=4000, help="TiDB port (default: 4000)")
    parser.add_argument("--user", type=str, default="root", help="TiDB user (default: root)")
    parser.add_argument("--password", type=str, default="", help="TiDB password")
    parser.add_argument("--database", type=str, default="threat_intel", help="TiDB database (default: threat_intel)")
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE, help=f"Batch size for inserts (default: {DEFAULT_BATCH_SIZE})")
    parser.add_argument("--resume", action="store_true", help="Resume from checkpoint")
    parser.add_argument("--dry-run", action="store_true", help="Parse and transform only, don't insert")
    args = parser.parse_args()
    
    # Setup logging
    logger = setup_logging("file_rep_importer.log")
    logger.info(f"Starting File Rep importer")
    logger.info(f"Input pattern: {args.input}")
    
    # Find input files
    input_files = sorted(glob.glob(args.input))
    if not input_files:
        logger.error(f"No files found matching: {args.input}")
        sys.exit(1)
    
    logger.info(f"Found {len(input_files)} file(s) to import")
    
    if args.dry_run:
        logger.info("DRY RUN mode - no database operations")
        for input_file in input_files:
            logger.info(f"Would import: {input_file}")
            # Count records
            count = 0
            valid = 0
            with gzip.open(input_file, 'rt') as f:
                for line in f:
                    count += 1
                    record = json.loads(line)
                    if transform_record(record):
                        valid += 1
            logger.info(f"  Total: {count:,}, Valid: {valid:,}, Skip: {count - valid:,}")
        return
    
    # Initialize TiDB connection
    importer = TiDBImporter(
        host=args.host,
        port=args.port,
        user=args.user,
        password=args.password,
        database=args.database,
    )
    
    if not importer.test_connection():
        logger.error("Failed to connect to TiDB")
        sys.exit(1)
    
    logger.info(f"Connected to TiDB at {args.host}:{args.port}/{args.database}")
    initial_count = importer.get_count()
    logger.info(f"Current record count: {initial_count:,}")
    
    # Process each file
    total_lines = 0
    total_imported = 0
    total_skipped = 0
    all_skip_reasons: Dict[str, int] = {}
    start_time = time.time()
    
    for input_file in input_files:
        logger.info(f"========== Importing: {input_file} ==========")
        lines, imported, skipped, skip_reasons = import_file(
            importer, input_file, args.batch_size, args.resume, logger
        )
        total_lines += lines
        total_imported += imported
        total_skipped += skipped
        
        # Merge skip reasons
        for reason, count in skip_reasons.items():
            all_skip_reasons[reason] = all_skip_reasons.get(reason, 0) + count
        
        # Log skip reasons for this file
        if skip_reasons:
            reasons_str = ", ".join(f"{k}: {v:,}" for k, v in sorted(skip_reasons.items(), key=lambda x: -x[1]))
            logger.info(f"Skip reasons: {reasons_str}")
        
        logger.info(f"File complete: {lines:,} lines, {imported:,} imported, {skipped:,} skipped")
    
    # Summary
    elapsed = time.time() - start_time
    final_count = importer.get_count()
    logger.info("=" * 50)
    logger.info(f"Import complete!")
    logger.info(f"Total lines: {total_lines:,}")
    logger.info(f"Total imported: {total_imported:,}")
    logger.info(f"Total skipped: {total_skipped:,}")
    
    # Log overall skip reasons
    if all_skip_reasons:
        logger.info("Skip reasons breakdown:")
        for reason, count in sorted(all_skip_reasons.items(), key=lambda x: -x[1]):
            logger.info(f"  {reason}: {count:,}")
    
    logger.info(f"Time: {elapsed/60:.1f} minutes")
    logger.info(f"Final record count: {final_count:,} (added {final_count - initial_count:,})")


if __name__ == "__main__":
    main()
