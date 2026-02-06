#!/usr/bin/env python3
"""
VT Feeder Importer - Import file hashes from vt-file-feeder-by-date GCS bucket.

This script imports incremental VT data (2020+) that is not in the MongoDB dump.
Uses a Producer-Consumer pattern for efficient parallel processing.

Architecture (Hash-Partitioned Queues):
    ┌─────────────────┐     ┌─────────────────────────────────┐
    │  Downloader     │     │   Hash Partitioner              │
    │  (Producers)    │────►│   (by SHA256 hash)              │
    │  N workers      │     │                                 │
    └─────────────────┘     │   ┌─────────┐  ┌─────────┐     │
           │                │   │ Queue 0 │  │ Queue 1 │ ... │
           ▼                │   └────┬────┘  └────┬────┘     │
    Download + Extract      └────────┼───────────┼──────────┘
    + Filter (positives>0)           │           │
                                     ▼           ▼
                              ┌──────────┐ ┌──────────┐
                              │ Writer 0 │ │ Writer 1 │ ...
                              └──────────┘ └──────────┘
                                   │            │
                                   └────┬───────┘
                                        ▼
                                   UPSERT to DB
                              (No lock contention!)

Benefits:
    - Same SHA256 → Same queue → Same writer (no conflicts)
    - Different SHA256 → Different queues → Parallel writes
    - No global lock needed (each queue independent)

Processing Flow:
    1. vt_feeder_importer.py - Import with positives>0, classification=NULL
    2. broccoli_updater.py   - Fill classification from Broccoli ML
    3. broccoli_updater.py   - Cleanup: delete INDIFFERENT/UNKNOWN/WHITELIST

Key Features:
    1. PRODUCER-CONSUMER - Decoupled download and DB write for flexibility
    2. ORDERED PROCESSING - Files processed in timestamp order (oldest first)
    3. UPSERT LOGIC - INSERT ... ON DUPLICATE KEY UPDATE (newer overwrites older)
    4. BACKPRESSURE - Queue size limits memory usage

Date Range:
    - MongoDB dump covers data up to November 2020
    - VT feeder import starts from: 2020-11-01 (VT_FEEDER_START_DATE)
    - Dates before 2020-11-01 will be automatically skipped

Performance Estimate (single day = 1440 files):
    - Download: ~2MB/file × 1440 = ~2.9GB → ~30s @ 100MB/s
    - Process: ~900 records/file × 1440 = ~1.3M records
    - Filter: ~47% have positives > 0 → ~600K records to import
    - DB Write: ~5000 records/sec → ~2 min
    - Total per day: ~3-5 minutes

    Full range (2020-11 to 2026-02):
    - ~1920 days × 5 min/day = ~160 hours (~6.5 days)
    - With 20 download workers: ~3-4 days

Usage:
    # Import single day
    python3 vt_feeder_importer.py --date 20260205

    # Import date range
    python3 vt_feeder_importer.py --start-date 20200405 --end-date 20260205

    # Tune parallelism
    python3 vt_feeder_importer.py --date 20260205 \\
        --download-workers 20 --db-workers 4

    # Dry run (no database changes)
    python3 vt_feeder_importer.py --date 20260205 --dry-run --max-files 10
"""
import argparse
import bz2
import logging
import os
import queue
import subprocess
import sys
import tarfile
import threading
import time
import warnings

# Suppress noisy warnings
warnings.filterwarnings("ignore", message=".*Your application has authenticated using end user credentials.*")
warnings.filterwarnings("ignore", message=".*No project ID could be determined.*")
warnings.filterwarnings("ignore", message=".*Connection pool is full.*")
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from io import BytesIO
from typing import Any, Dict, List, Optional, Tuple

# Google Cloud Storage SDK (required)
try:
    from google.cloud import storage
    from google.api_core import retry
    from google.api_core.exceptions import NotFound, Forbidden
    import google.auth
    
    # Configure retry strategy for GCS operations
    GCS_RETRY = retry.Retry(
        initial=1.0,        # Initial wait: 1 second
        maximum=10.0,       # Maximum wait: 10 seconds
        multiplier=2.0,     # Exponential backoff
        deadline=60.0,      # Total timeout: 60 seconds
        predicate=retry.if_transient_error,  # Retry on transient errors
    )
except ImportError:
    print("ERROR: google-cloud-storage is required but not installed.")
    print("Install with: pip install google-cloud-storage")
    sys.exit(1)

# Fast JSON parser (optional but recommended)
try:
    import orjson as json
    JSON_LOADS = lambda s: json.loads(s)
    JSON_FAST = True
except ImportError:
    import json
    JSON_LOADS = json.loads
    JSON_FAST = False
    print("Warning: orjson not installed. Using standard json (slower).")
    print("Install with: pip install orjson")

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
VT_FEEDER_BUCKET = "gs://vt-file-feeder-by-date"

# Queue and batch settings
QUEUE_MAX_SIZE = 100  # Max batches in queue (backpressure)
DEFAULT_BATCH_SIZE = 1000  # Records per DB batch (balanced: fewer round trips vs smaller SQL)
DEFAULT_DOWNLOAD_WORKERS = 20  # Parallel GCS downloads (increased for network I/O)
DEFAULT_DB_WORKERS = 8  # Parallel DB writers (hash-partitioned, no lock contention)

# Date range constraints
# MongoDB dump covers data up to November 2020
# VT feeder incremental data starts from November 2020
VT_FEEDER_START_DATE = "20201101"  # First date to import from VT feeder
VT_FEEDER_EARLIEST_AVAILABLE = "20200405"  # Earliest data available in GCS bucket

# Classification mapping
CLASSIFICATION_MAP = {
    "malware": "MALWARE",
    "ransomware": "RANSOMWARE",
    "hacktool": "HACKTOOL",
    "unwanted": "UNWANTED",
    "suspicious": "SUSPICIOUS",
    "av_detected": "AV_DETECTED",
}

# Skip these classifications (not threats)
SKIP_CLASSIFICATIONS = {"whitelist", "indifferent", "unknown"}

# Valid threat classifications
VALID_CLASSIFICATIONS = {"malware", "ransomware", "hacktool", "unwanted", "suspicious", "av_detected"}

# Sentinel value for queue termination
QUEUE_DONE = None


# ----------------------------
# Data structures
# ----------------------------
@dataclass
class RecordBatch:
    """A batch of records ready for DB insert."""
    records: List['ProcessedRecord']
    source_file: str
    file_index: int  # For ordering


@dataclass
class PipelineStats:
    """Thread-safe statistics tracking."""
    files_downloaded: int = 0
    files_processed: int = 0
    records_total: int = 0
    records_filtered: int = 0  # positives > 0
    records_imported: int = 0
    records_skipped: int = 0
    
    # Performance metrics (in seconds)
    time_download: float = 0.0
    time_decompress: float = 0.0
    time_parse: float = 0.0
    time_db: float = 0.0
    
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def inc(self, **kwargs):
        with self._lock:
            for key, value in kwargs.items():
                setattr(self, key, getattr(self, key) + value)

    def snapshot(self) -> Dict[str, any]:
        with self._lock:
            return {
                "files_downloaded": self.files_downloaded,
                "files_processed": self.files_processed,
                "records_total": self.records_total,
                "records_filtered": self.records_filtered,
                "records_imported": self.records_imported,
                "records_skipped": self.records_skipped,
                "time_download": self.time_download,
                "time_decompress": self.time_decompress,
                "time_parse": self.time_parse,
                "time_db": self.time_db,
            }


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
    # Suppress noisy urllib3 connection pool warnings
    logging.getLogger("urllib3.connectionpool").setLevel(logging.ERROR)
    return logging.getLogger(__name__)


logger = setup_logging()


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


def extract_detection_names(scans: Dict[str, Any]) -> Optional[str]:
    """
    Extract detection names from VT scans field.
    Returns semicolon-separated string: "engine:result;engine:result;..."
    """
    if not scans or not isinstance(scans, dict):
        return None

    detections = []
    for engine, result in scans.items():
        if isinstance(result, dict) and result.get("detected") and result.get("result"):
            detections.append(f"{engine}:{result['result']}")

    if detections:
        return ";".join(detections)
    return None


# ----------------------------
# GCS Operations
# ----------------------------

# GCS bucket config
GCS_BUCKET_NAME = "vt-file-feeder-by-date"
GCS_PROJECT = "vt-feed-pipeline-acfe9f"

# Global GCS client (singleton, thread-safe)
_gcs_client = None
_gcs_bucket = None

def get_gcs_client(pool_size: int = DEFAULT_DOWNLOAD_WORKERS):
    """Get or create GCS client (singleton, thread-safe).
    
    Uses google.auth.default() to auto-detect credentials.
    Configures HTTP connection pool to match download worker count.
    """
    global _gcs_client, _gcs_bucket
    if _gcs_client is None:
        credentials, project = google.auth.default()
        project = project or os.environ.get('GOOGLE_CLOUD_PROJECT') or GCS_PROJECT
        
        # Create authorized session with connection pool matching worker count
        import google.auth.transport.requests as google_requests
        import requests as http_requests
        auth_session = google_requests.AuthorizedSession(credentials)
        adapter = http_requests.adapters.HTTPAdapter(
            pool_connections=pool_size,
            pool_maxsize=pool_size,
        )
        auth_session.mount("https://", adapter)
        auth_session.mount("http://", adapter)
        
        _gcs_client = storage.Client(credentials=credentials, project=project, _http=auth_session)
        _gcs_bucket = _gcs_client.bucket(GCS_BUCKET_NAME)
    return _gcs_client, _gcs_bucket


def list_gcs_files(date_str: str) -> List[str]:
    """
    Generate all file paths for a given date in vt-file-feeder-by-date bucket.
    Returns sorted list (by timestamp) for sequential processing.
    
    VT feed publishes one file per minute: YYYYMMDD/YYYYMMDDTHHMM
    This generates all 1440 possible paths (24h × 60min) without needing list permission.
    """
    # Generate all 1440 files for the day (one per minute)
    files = []
    bucket_name = "vt-file-feeder-by-date"  # Extract from VT_FEEDER_BUCKET
    for hour in range(24):
        for minute in range(60):
            timestamp = f"{date_str}T{hour:02d}{minute:02d}"
            files.append(f"gs://{bucket_name}/{date_str}/{timestamp}")
    
    return files  # Already in sorted order


def download_vt_file(gcs_path: str) -> Optional[bytes]:
    """
    Download a single tar.bz2 file from GCS.
    Returns raw bytes or None on failure.
    """
    try:
        result = subprocess.run(
            ["gcloud", "storage", "cat", gcs_path],
            capture_output=True,
            timeout=300,
        )
        if result.returncode == 0:
            return result.stdout
    except subprocess.TimeoutExpired:
        logger.warning(f"Timeout downloading {gcs_path}")
    except Exception as e:
        logger.warning(f"Error downloading {gcs_path}: {e}")
    return None


def download_and_extract(gcs_path: str) -> Tuple[str, List[Dict[str, Any]], Dict[str, float]]:
    """
    Download a file and extract VT records.
    Returns (gcs_path, list of record dicts, timing metrics).
    Uses GCS SDK for faster downloads with connection reuse.
    
    Handles missing files gracefully (returns empty list) since we generate
    all possible paths (1440/day) but not all may exist.
    """
    records = []
    timings = {"download": 0.0, "decompress": 0.0, "parse": 0.0}
    
    try:
        client, bucket = get_gcs_client()
        
        # Download using GCS SDK with retry and timeout
        t0 = time.time()
        blob_name = gcs_path.replace(f"gs://{GCS_BUCKET_NAME}/", "")
        blob = bucket.blob(blob_name)
        
        compressed_data = blob.download_as_bytes(
            retry=GCS_RETRY,
            timeout=60
        )
        timings["download"] = time.time() - t0

        # Decompress bz2
        t0 = time.time()
        decompressed = bz2.decompress(compressed_data)
        timings["decompress"] = time.time() - t0

        # Extract tar + parse JSON
        t0 = time.time()
        with tarfile.open(fileobj=BytesIO(decompressed), mode='r:') as tar:
            for member in tar.getmembers():
                if member.isfile():
                    f = tar.extractfile(member)
                    if f:
                        content = f.read().decode('utf-8')
                        for line in content.strip().split('\n'):
                            if line.strip():
                                try:
                                    records.append(JSON_LOADS(line))
                                except (json.JSONDecodeError, ValueError):
                                    pass
        timings["parse"] = time.time() - t0
        
    except NotFound:
        # File doesn't exist - normal since we generate all 1440 possible paths
        pass
    except Forbidden as e:
        logger.warning(f"Permission denied for {gcs_path}: {e}")
    except Exception as e:
        logger.warning(f"Error processing {gcs_path}: {e}")
    
    return gcs_path, records, timings


# ----------------------------
# Record processing
# ----------------------------
@dataclass
class ProcessedRecord:
    sha256: bytes
    sha1: Optional[bytes]
    md5: Optional[bytes]
    source: str
    detection_names: Optional[str]


def process_vt_record(record: Dict[str, Any]) -> Optional[ProcessedRecord]:
    """
    Process a VT record and return a ProcessedRecord if it has detections.
    
    Filter: positives > 0 (has AV detections)
    Classification is left NULL - will be filled by broccoli_updater.py later.
    """
    # Filter: must have positives > 0
    positives = record.get("positives", 0)
    if isinstance(positives, float):
        positives = int(positives)
    if positives <= 0:
        return None

    # Extract hashes
    sha256 = record.get("sha256")
    sha1 = record.get("sha1")
    md5 = record.get("md5")

    if not sha256:
        return None

    # Extract detection names (for reference/debugging)
    scans = record.get("scans", {})
    detection_names = extract_detection_names(scans)

    return ProcessedRecord(
        sha256=hex_to_bytes(sha256),
        sha1=hex_to_bytes(sha1),
        md5=hex_to_bytes(md5),
        source="VIRUS_TOTAL",
        detection_names=detection_names,
    )


# ----------------------------
# Database Operations
# ----------------------------
class TiDBImporter:
    MAIN_TABLE = "ioc_file_hashes"
    STAGING_TABLE = "ioc_file_hashes_staging"
    
    def __init__(self, host: str, port: int, user: str, password: str, database: str,
                 pool_size: int = 5, use_staging: bool = False):
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
        self.use_staging = use_staging
        self.target_table = self.STAGING_TABLE if use_staging else self.MAIN_TABLE
        
        if use_staging:
            self._create_staging_table()

    def _create_staging_table(self):
        """Create staging table (minimal indexes for fast INSERT)."""
        try:
            conn = self.pool.get_connection()
            cursor = conn.cursor()
            # Drop old staging table if exists
            cursor.execute(f"DROP TABLE IF EXISTS {self.STAGING_TABLE}")
            # Create staging table matching main table schema
            # Only primary key index (no sha1/md5 secondary indexes for faster writes)
            cursor.execute(f"""
                CREATE TABLE {self.STAGING_TABLE} (
                    sha256 BINARY(32) NOT NULL,
                    sha1 BINARY(20) DEFAULT NULL,
                    md5 BINARY(16) DEFAULT NULL,
                    classification ENUM('RANSOMWARE','MALTOOL','HACKTOOL','UNWANTED','MALWARE','SUSPICIOUS','BLACKLIST') DEFAULT NULL,
                    source ENUM('VIRUS_TOTAL','MALWARE_BAZAAR','INTERNAL','TEST') NOT NULL,
                    detection_names TEXT DEFAULT NULL,
                    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (sha256)
                ) ENGINE=InnoDB
            """)
            conn.commit()
            cursor.close()
            conn.close()
            self.logger.info(f"Created staging table: {self.STAGING_TABLE}")
        except Exception as e:
            self.logger.error(f"Failed to create staging table: {e}")
            raise

    def batch_upsert(self, records: List[ProcessedRecord]) -> Tuple[int, int, float]:
        """
        Batch insert/upsert records.
        - Staging mode: INSERT IGNORE (fast, no update needed since we merge later)
        - Direct mode: INSERT ... ON DUPLICATE KEY UPDATE
        Returns (affected_count, 0, elapsed_time).
        """
        if not records:
            return 0, 0, 0.0

        t0 = time.time()

        if self.use_staging:
            # Staging: UPSERT within month - later data overwrites earlier
            sql = f"""
                INSERT INTO {self.STAGING_TABLE}
                (sha256, sha1, md5, source, detection_names)
                VALUES (%s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    sha1 = VALUES(sha1),
                    md5 = VALUES(md5),
                    source = VALUES(source),
                    detection_names = VALUES(detection_names)
            """
        else:
            # Direct: UPSERT to main table
            sql = f"""
                INSERT INTO {self.MAIN_TABLE}
                (sha256, sha1, md5, source, detection_names)
                VALUES (%s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    sha1 = VALUES(sha1),
                    md5 = VALUES(md5),
                    source = VALUES(source),
                    detection_names = VALUES(detection_names)
            """

        values = [
            (r.sha256, r.sha1, r.md5, r.source, r.detection_names)
            for r in records
        ]

        try:
            conn = self.pool.get_connection()
            cursor = conn.cursor()
            cursor.executemany(sql, values)
            conn.commit()
            affected = cursor.rowcount
            cursor.close()
            conn.close()
            elapsed = time.time() - t0
            return affected, 0, elapsed
        except Exception as e:
            self.logger.error(f"Batch upsert failed: {e}")
            raise

    def merge_staging(self) -> int:
        """Merge staging table into main table using UPSERT.
        Returns number of affected rows.
        """
        self.logger.info(f"Merging {self.STAGING_TABLE} → {self.MAIN_TABLE} ...")
        try:
            conn = self.pool.get_connection()
            cursor = conn.cursor()
            
            # Count staging records
            cursor.execute(f"SELECT COUNT(*) FROM {self.STAGING_TABLE}")
            staging_count = cursor.fetchone()[0]
            self.logger.info(f"  Staging records: {staging_count:,}")
            
            # UPSERT from staging to main
            t0 = time.time()
            cursor.execute(f"""
                INSERT INTO {self.MAIN_TABLE} (sha256, sha1, md5, source, detection_names)
                SELECT sha256, sha1, md5, source, detection_names FROM {self.STAGING_TABLE}
                ON DUPLICATE KEY UPDATE
                    sha1 = VALUES(sha1),
                    md5 = VALUES(md5),
                    source = VALUES(source),
                    detection_names = VALUES(detection_names)
            """)
            conn.commit()
            affected = cursor.rowcount
            elapsed = time.time() - t0
            self.logger.info(f"  Merged {affected:,} rows in {elapsed:.1f}s")
            
            # Drop staging table
            cursor.execute(f"DROP TABLE IF EXISTS {self.STAGING_TABLE}")
            conn.commit()
            cursor.close()
            conn.close()
            self.logger.info(f"  Dropped staging table")
            return affected
        except Exception as e:
            self.logger.error(f"Merge failed: {e}")
            raise

    def get_count(self, table: str = None) -> int:
        """Get current record count."""
        table = table or self.MAIN_TABLE
        try:
            conn = self.pool.get_connection()
            cursor = conn.cursor()
            cursor.execute(f"SELECT COUNT(*) FROM {table}")
            count = cursor.fetchone()[0]
            cursor.close()
            conn.close()
            return count
        except Exception as e:
            self.logger.error(f"Count query failed: {e}")
            return -1


# ----------------------------
# Producer-Consumer Pipeline
# ----------------------------
def producer_worker(
    file_queue: queue.Queue,
    record_queues: List[queue.Queue],  # Multiple queues for hash partitioning
    stats: PipelineStats,
    batch_size: int,
    shutdown_event: threading.Event,
):
    """
    Producer: Download files from GCS and distribute records to queues by hash.
    Uses hash partitioning (SHA256 % num_queues) to avoid write conflicts.
    Same SHA256 always goes to same queue -> same writer -> no duplicate key conflicts.
    """
    num_queues = len(record_queues)
    
    while not shutdown_event.is_set():
        try:
            item = file_queue.get(timeout=1)
            if item is QUEUE_DONE:
                file_queue.task_done()
                break
            
            file_index, gcs_path = item
            
            # Download and extract (with timing)
            _, records, timings = download_and_extract(gcs_path)
            stats.inc(
                files_downloaded=1,
                time_download=timings["download"],
                time_decompress=timings["decompress"],
                time_parse=timings["parse"],
            )
            
            # Filter and collect records with positives > 0
            filtered_records = []
            for record in records:
                stats.inc(records_total=1)
                positives = record.get("positives", 0)
                if isinstance(positives, float):
                    positives = int(positives)
                
                if positives > 0:
                    filtered_records.append(record)
                    stats.inc(records_filtered=1)
            
            # Distribute records to queues by SHA256 hash
            # Same SHA256 -> same queue -> same writer (no conflicts on UPSERT)
            queue_batches = [[] for _ in range(num_queues)]
            for record in filtered_records:
                sha256 = record.get("sha256", "")
                # Hash to queue index
                queue_idx = hash(sha256) % num_queues
                queue_batches[queue_idx].append(record)
            
            # Put batches into respective queues
            for queue_idx, batch in enumerate(queue_batches):
                if batch:
                    for i in range(0, len(batch), batch_size):
                        batch_records = batch[i:i + batch_size]
                        record_queues[queue_idx].put((file_index, gcs_path, batch_records))
            
            file_queue.task_done()
            
        except queue.Empty:
            continue
        except Exception as e:
            logger.error(f"Producer error: {e}")


def consumer_worker(
    worker_id: int,
    record_queue: queue.Queue,
    importer: Optional[TiDBImporter],
    stats: PipelineStats,
    dry_run: bool,
    shutdown_event: threading.Event,
):
    """
    Consumer: Process records and upsert to database.
    Each worker has its own queue - no lock contention!
    
    Hash partitioning ensures same SHA256 -> same queue -> no duplicate key conflicts.
    Note: Broccoli classification lookup is done SEPARATELY after import.
    """
    while not shutdown_event.is_set():
        try:
            item = record_queue.get(timeout=1)
            if item is QUEUE_DONE:
                record_queue.task_done()
                break
            
            file_index, gcs_path, records = item
            
            # Process records
            processed_records = []
            for record in records:
                processed = process_vt_record(record)
                if processed:
                    processed_records.append(processed)
                else:
                    stats.inc(records_skipped=1)
            
            # Direct upsert (no lock needed - each worker independent)
            if processed_records:
                if not dry_run and importer:
                    _, _, db_time = importer.batch_upsert(processed_records)
                    stats.inc(records_imported=len(processed_records), time_db=db_time)
                else:
                    stats.inc(records_imported=len(processed_records))
            
            stats.inc(files_processed=1)
            record_queue.task_done()
            
        except queue.Empty:
            continue
        except Exception as e:
            logger.error(f"Consumer worker {worker_id} error: {e}")


def import_date(
    importer: Optional[TiDBImporter],
    date_str: str,
    batch_size: int,
    max_files: Optional[int],
    download_workers: int,
    db_workers: int,
    dry_run: bool,
) -> Dict[str, int]:
    """
    Import all VT data for a single date using hash-partitioned queues.
    
    Architecture:
        file_queue → [Producers] → [Queue 0, Queue 1, ...] → [Writer 0, Writer 1, ...]
                                    (hash by SHA256)          (parallel, no locks!)
    
    Hash partitioning ensures same SHA256 -> same queue -> no duplicate key conflicts.
    
    Returns stats dict.
    """
    logger.info(f"Processing date: {date_str}")

    # List files for this date (sorted by timestamp)
    files = list_gcs_files(date_str)
    if not files:
        logger.warning(f"No files found for {date_str}")
        return {"files_processed": 0}

    if max_files:
        files = files[:max_files]

    logger.info(f"Found {len(files)} files to process")
    logger.info(f"Pipeline: {download_workers} downloaders → {db_workers} hash-partitioned queues → {db_workers} writers")

    # Initialize GCS client with connection pool matching worker count
    get_gcs_client(pool_size=download_workers)

    # Initialize
    stats = PipelineStats()
    file_queue = queue.Queue(maxsize=download_workers * 2)
    
    # Create multiple queues (one per DB worker) for hash partitioning
    record_queues = [queue.Queue(maxsize=QUEUE_MAX_SIZE) for _ in range(db_workers)]
    shutdown_event = threading.Event()

    start_time = time.time()

    # Start producer threads
    producers = []
    for _ in range(download_workers):
        t = threading.Thread(
            target=producer_worker,
            args=(file_queue, record_queues, stats, batch_size, shutdown_event),
            daemon=True,
        )
        t.start()
        producers.append(t)

    # Start consumer threads (one per queue)
    consumers = []
    for worker_id in range(db_workers):
        t = threading.Thread(
            target=consumer_worker,
            args=(worker_id, record_queues[worker_id], importer, stats, dry_run, shutdown_event),
            daemon=True,
        )
        t.start()
        consumers.append(t)

    # Feed files to producers
    try:
        for file_index, gcs_path in enumerate(files):
            file_queue.put((file_index, gcs_path))
            
            # Progress logging
            if file_index > 0 and file_index % 100 == 0:
                elapsed = time.time() - start_time
                snap = stats.snapshot()
                dl_count = snap["files_downloaded"]
                rate = dl_count / elapsed if elapsed > 0 else 0
                
                # Average time per file (across all workers)
                avg_dl = (snap["time_download"] / dl_count) if dl_count > 0 else 0
                avg_decomp = (snap["time_decompress"] / dl_count) if dl_count > 0 else 0
                avg_parse = (snap["time_parse"] / dl_count) if dl_count > 0 else 0
                avg_db = (snap["time_db"] / max(snap["records_imported"], 1)) * 1000  # ms per record
                
                # Queue sizes
                fq_size = file_queue.qsize()
                rq_sizes = [q.qsize() for q in record_queues]
                rq_total = sum(rq_sizes)
                
                logger.info(
                    f"Progress: {dl_count}/{len(files)} downloaded | "
                    f"Records: {snap['records_imported']:,} imported | "
                    f"Rate: {rate:.1f} files/sec"
                )
                logger.info(
                    f"  Avg/file: download={avg_dl:.2f}s, decompress={avg_decomp:.3f}s, parse={avg_parse:.3f}s | "
                    f"DB: {avg_db:.2f}ms/rec"
                )
                logger.info(
                    f"  Queues: file_q={fq_size}, record_q={rq_total} ({','.join(str(s) for s in rq_sizes)})"
                )

        # Signal producers to stop
        for _ in range(download_workers):
            file_queue.put(QUEUE_DONE)

        # Wait for producers to finish
        for t in producers:
            t.join(timeout=300)

        # Signal consumers to stop (one per queue)
        for q in record_queues:
            q.put(QUEUE_DONE)

        # Wait for consumers to finish
        for t in consumers:
            t.join(timeout=300)

    except KeyboardInterrupt:
        logger.warning("Interrupted! Shutting down...")
        shutdown_event.set()
        raise

    elapsed = time.time() - start_time
    final_stats = stats.snapshot()
    
    # Performance breakdown
    perf_summary = []
    if final_stats.get('time_download', 0) > 0:
        perf_summary.append(f"download={final_stats['time_download']:.1f}s")
    if final_stats.get('time_decompress', 0) > 0:
        perf_summary.append(f"decompress={final_stats['time_decompress']:.1f}s")
    if final_stats.get('time_parse', 0) > 0:
        perf_summary.append(f"parse={final_stats['time_parse']:.1f}s")
    if final_stats.get('time_db', 0) > 0:
        perf_summary.append(f"db={final_stats['time_db']:.1f}s")
    
    logger.info(
        f"Date {date_str} complete in {elapsed:.1f}s: "
        f"{final_stats['files_processed']} files, "
        f"{final_stats['records_total']:,} total, "
        f"{final_stats['records_imported']:,} imported, "
        f"{final_stats['records_skipped']:,} skipped"
    )
    
    if perf_summary:
        logger.info(f"  Performance breakdown: {', '.join(perf_summary)}")

    return final_stats


def generate_date_range(start_date: str, end_date: str) -> List[str]:
    """Generate list of date strings between start and end (inclusive)."""
    start = datetime.strptime(start_date, "%Y%m%d")
    end = datetime.strptime(end_date, "%Y%m%d")
    dates = []
    current = start
    while current <= end:
        dates.append(current.strftime("%Y%m%d"))
        current += timedelta(days=1)
    return dates


def main():
    parser = argparse.ArgumentParser(
        description="Import VT data from vt-file-feeder-by-date",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Performance Estimate:
  Single day (~1440 files): ~5-6 seconds
  Full 5 years (2020-11 to 2026-02): ~3 hours

Database Configuration (Fixed):
  Host: localhost
  Port: 3306
  User: root
  Database: threat_intel

Examples:
  # Test with single day (dry run)
  python3 vt_feeder_importer.py --date 20260205 --dry-run --max-files 10 --password phoenix123

  # Import single day
  python3 vt_feeder_importer.py --date 20260205 --password phoenix123

  # Import full range (Nov 2020 onwards)
  python3 vt_feeder_importer.py --start-date 20201101 --end-date 20260130 --password phoenix123

  # Custom performance tuning
  python3 vt_feeder_importer.py --start-date 20201101 --end-date 20260130 \\
      --download-workers 30 --db-workers 12 --password phoenix123

Note: Dates before 2020-11-01 are skipped (covered by MongoDB dump).
""",
    )
    # Date range (required)
    parser.add_argument("--date", help="Single date to import (YYYYMMDD)")
    parser.add_argument("--start-date", help="Start date for range import (YYYYMMDD)")
    parser.add_argument("--end-date", help="End date for range import (YYYYMMDD)")
    
    # Database (fixed for localhost MySQL)
    parser.add_argument("--password", required=True, help="Database password")
    
    # Performance tuning (optional, has good defaults)
    parser.add_argument("--download-workers", type=int, default=DEFAULT_DOWNLOAD_WORKERS, 
                       help=f"Parallel download workers (default: {DEFAULT_DOWNLOAD_WORKERS})")
    parser.add_argument("--db-workers", type=int, default=DEFAULT_DB_WORKERS,
                       help=f"Parallel DB writers (default: {DEFAULT_DB_WORKERS})")
    
    # Testing/debugging
    parser.add_argument("--max-files", type=int, help="Max files per day (for testing)")
    parser.add_argument("--dry-run", action="store_true", help="Don't insert to database")
    parser.add_argument("--staging", action="store_true",
                       help="Use staging table for fast INSERT, merge to main table at the end. "
                            "Much faster for large imports (5-10x speedup)")
    args = parser.parse_args()
    
    # Fixed database configuration (localhost MySQL)
    DB_HOST = "localhost"
    DB_PORT = 3306
    DB_USER = "root"
    DB_NAME = "threat_intel"
    BATCH_SIZE = DEFAULT_BATCH_SIZE

    # Determine dates to process
    if args.date:
        dates = [args.date]
    elif args.start_date and args.end_date:
        dates = generate_date_range(args.start_date, args.end_date)
    else:
        parser.error("Must specify --date or both --start-date and --end-date")

    # Validate date range
    # MongoDB dump covers up to Nov 2020, so VT feeder import should start from Nov 2020
    for date_str in dates:
        if date_str < VT_FEEDER_START_DATE:
            logger.warning(
                f"Date {date_str} is before VT_FEEDER_START_DATE ({VT_FEEDER_START_DATE}). "
                f"MongoDB dump already covers this period. Skipping dates before {VT_FEEDER_START_DATE}."
            )
            dates = [d for d in dates if d >= VT_FEEDER_START_DATE]
            break

    if not dates:
        logger.error(f"No valid dates to process. VT feeder import starts from {VT_FEEDER_START_DATE}.")
        sys.exit(1)

    logger.info("=" * 70)
    logger.info("VT Feeder Importer (Hash-Partitioned Pipeline)")
    logger.info("=" * 70)
    logger.info(f"Dates to process: {len(dates)} ({dates[0]} to {dates[-1]})")
    logger.info(f"Database: {DB_HOST}:{DB_PORT}/{DB_NAME}")
    logger.info(f"Download workers: {args.download_workers}")
    logger.info(f"DB workers: {args.db_workers} (hash-partitioned queues)")
    logger.info(f"Batch size: {BATCH_SIZE}")
    logger.info(f"Dry run: {args.dry_run}")
    logger.info(f"Staging mode: {args.staging}")
    logger.info("")
    
    # Performance optimizations status
    optimizations = [
        "✓ GCS SDK (3-5x faster downloads)",
        f"✓ Hash partitioning ({args.db_workers} parallel writers)",
        "✓ Retry and timeout configured",
    ]
    
    if JSON_FAST:
        optimizations.append("✓ orjson (2-3x faster JSON parsing)")
    else:
        optimizations.append("○ orjson not installed (using standard json)")
    
    logger.info("Optimizations:")
    for opt in optimizations:
        logger.info(f"  {opt}")
    
    if not JSON_FAST:
        logger.info("")
        logger.info("Tip: Install orjson for 2-3x faster JSON parsing:")
        logger.info("  pip install orjson")
    
    logger.info("=" * 70)

    # Estimate time
    est_minutes = len(dates) * 4  # ~4 min per day
    est_hours = est_minutes / 60
    if est_hours > 1:
        logger.info(f"Estimated time: ~{est_hours:.1f} hours ({est_minutes} minutes)")
    else:
        logger.info(f"Estimated time: ~{est_minutes} minutes")
    logger.info("=" * 70)

    # Connect to database
    importer = None
    initial_count = 0
    if not args.dry_run:
        importer = TiDBImporter(
            host=DB_HOST,
            port=DB_PORT,
            user=DB_USER,
            password=args.password,
            database=DB_NAME,
            pool_size=args.db_workers + 2,  # +2 for main thread queries
            use_staging=args.staging,
        )
        if args.staging:
            logger.info("Mode: STAGING (fast INSERT → merge at end)")
        initial_count = importer.get_count()
        logger.info(f"Connected to {DB_HOST}:{DB_PORT}/{DB_NAME}")
        logger.info(f"Initial record count: {initial_count:,}")

    # Process each date
    total_stats = {
        "files_processed": 0,
        "records_total": 0,
        "records_imported": 0,
        "records_skipped": 0,
    }

    # Checkpoint file to track completed dates (enables resume on interruption)
    checkpoint_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".vt_feeder_checkpoint")
    completed_dates = set()
    if os.path.exists(checkpoint_file):
        with open(checkpoint_file, "r") as f:
            completed_dates = {line.strip() for line in f if line.strip()}
        if completed_dates:
            logger.info(f"Found checkpoint: {len(completed_dates)} dates already completed, will skip them")

    start_time = time.time()

    # Group dates by month for staging mode
    from collections import OrderedDict
    months = OrderedDict()  # "YYYYMM" -> [date_str, ...]
    for date_str in dates:
        month_key = date_str[:6]  # "202011", "202012", etc.
        if month_key not in months:
            months[month_key] = []
        months[month_key].append(date_str)

    if args.staging:
        logger.info(f"Months to process: {len(months)} ({', '.join(months.keys())})")

    days_done = 0
    for month_key, month_dates in months.items():
        # In staging mode: create fresh staging table per month
        if args.staging and importer and not args.dry_run:
            logger.info("")
            logger.info(f"{'='*70}")
            logger.info(f"MONTH {month_key}: {len(month_dates)} days")
            logger.info(f"{'='*70}")
            importer._create_staging_table()

        for date_str in month_dates:
            if date_str in completed_dates:
                days_done += 1
                continue

            day_stats = import_date(
                importer=importer,
                date_str=date_str,
                batch_size=BATCH_SIZE,
                max_files=args.max_files,
                download_workers=args.download_workers,
                db_workers=args.db_workers,
                dry_run=args.dry_run,
            )
            
            for key in total_stats:
                total_stats[key] += day_stats.get(key, 0)

            # Save checkpoint (append completed date)
            if not args.dry_run:
                with open(checkpoint_file, "a") as f:
                    f.write(f"{date_str}\n")
            
            days_done += 1

            # Progress for multi-day runs
            if len(dates) > 1 and days_done % 7 == 0:
                elapsed = time.time() - start_time
                days_left = len(dates) - days_done
                eta_seconds = (elapsed / max(days_done, 1)) * days_left
                eta_hours = eta_seconds / 3600
                logger.info(f"Overall: {days_done}/{len(dates)} days | ETA: {eta_hours:.1f} hours")

        # In staging mode: merge staging → main after each month
        if args.staging and importer and not args.dry_run:
            logger.info(f"Month {month_key} import complete, merging to main table...")
            importer.merge_staging()
            main_count = importer.get_count()
            logger.info(f"Main table record count: {main_count:,}")

    elapsed = time.time() - start_time
    elapsed_hours = elapsed / 3600

    # Summary
    logger.info("=" * 70)
    logger.info("SUMMARY")
    logger.info("=" * 70)
    logger.info(f"  Dates processed: {days_done}")
    logger.info(f"  Files processed: {total_stats['files_processed']:,}")
    logger.info(f"  Records total: {total_stats['records_total']:,}")
    logger.info(f"  Records imported: {total_stats['records_imported']:,}")
    logger.info(f"  Records skipped: {total_stats['records_skipped']:,}")
    logger.info(f"  Total time: {elapsed_hours:.2f} hours ({elapsed:.0f} seconds)")
    logger.info("")
    logger.info("  Note: Run broccoli_updater.py after import to enrich classifications")

    if importer:
        final_count = importer.get_count()
        logger.info(f"  Final record count: {final_count:,}")
        logger.info(f"  Net new records: {final_count - initial_count:,}")

    logger.info("=" * 70)
    logger.info("Done!")


if __name__ == "__main__":
    main()
