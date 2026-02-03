#!/usr/bin/env python3
"""
Parallel BSON Processor - Extract threat intelligence from VT file_rep BSON dumps.

Processes large MongoDB BSON dumps from GCS, extracts threat records, and outputs
compressed NDJSON files suitable for TiDB import or Broccoli ML reclassification.

Features:
- Parallel chunked download from GCS (42 workers by default)
- No-overlap mode with leftover resolver for cross-boundary documents
- Checkpoint/resume support for fault tolerance
- Live progress logging with ETA (based on download speed)
- Outputs full VT value object (compatible with Broccoli ML service)

Filtering:
- Keeps records with response_code == 1 (valid VT response)
- EXCLUDES 'indifferent' and 'unknown' classifications (trust ML over AV count)
- Keeps records with valid threat classification (malware, ransomware, etc.)
- Keeps records with null classification but positives > 0 (can be inferred later)

Output: file_rep_{shard}_full.ndjson.gz

Usage:
    python3 parallel_bson_processor.py --shard r01
    python3 parallel_bson_processor.py --shard r01 --resume
    python3 parallel_bson_processor.py  # Process all 6 shards
"""
import struct
import gzip
import json
import os
import sys
import argparse
import signal
import threading
import time
import queue
import random
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any, Tuple


def setup_logging(log_file: Optional[str] = None, name: str = __name__):
    """Setup logging to both console and file. Returns a logger instance."""
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    
    # Clear existing handlers to avoid duplicates
    logger.handlers.clear()
    
    # Console handler (always)
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(logging.Formatter('%(asctime)s | %(message)s', datefmt='%Y-%m-%d %H:%M:%S'))
    logger.addHandler(console)
    
    # File handler (if specified)
    if log_file:
        file_handler = logging.FileHandler(log_file, mode='a')
        file_handler.setFormatter(logging.Formatter('%(asctime)s | %(message)s', datefmt='%Y-%m-%d %H:%M:%S'))
        logger.addHandler(file_handler)
    
    return logger

import bson
import orjson
from google.cloud import storage


# ----------------------------
# Data structures
# ----------------------------
@dataclass
class RangeInfo:
    worker_id: int
    start: int
    end: int          # physical end (== logical_end in no-overlap mode)
    is_first: bool
    is_last: bool
    logical_end: int  # boundary for ownership (no-overlap => end == logical_end)


@dataclass
class ProcessingStats:
    total_docs: int = 0
    valid_docs: int = 0
    decode_errors: int = 0
    invalid_len: int = 0
    resync_scans: int = 0
    bytes_read: int = 0
    leftovers: int = 0


@dataclass(frozen=True)
class LeftoverDoc:
    global_start: int
    owner_worker_id: int


@dataclass
class Checkpoint:
    gcs_path: str
    output_file: str
    num_workers: int
    file_size: int
    completed_ranges: List[int] = field(default_factory=list)
    valid_docs: int = 0
    bytes_processed: int = 0
    net_bytes_downloaded: int = 0  # Actual network bytes downloaded (includes resync/leftovers)
    start_time: float = 0.0
    last_update: float = 0.0


@dataclass
class GlobalProgress:
    start_time: float
    base_bytes_downloaded: int = 0  # Base offset for resume (for accurate throughput calculation)
    base_valid_docs: int = 0  # Base offset for resume
    bytes_downloaded: int = 0
    bytes_written: int = 0
    total_docs: int = 0
    valid_docs: int = 0
    decode_errors: int = 0
    invalid_len: int = 0
    leftovers: int = 0
    resync_scans: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def inc_downloaded(self, n: int):
        with self._lock:
            self.bytes_downloaded += n

    def inc_written(self, n: int):
        with self._lock:
            self.bytes_written += n

    def inc_total_docs(self, n: int = 1):
        with self._lock:
            self.total_docs += n

    def inc_valid_docs(self, n: int = 1):
        with self._lock:
            self.valid_docs += n

    def inc_decode_errors(self, n: int = 1):
        with self._lock:
            self.decode_errors += n

    def inc_invalid_len(self, n: int = 1):
        with self._lock:
            self.invalid_len += n

    def inc_leftovers(self, n: int = 1):
        with self._lock:
            self.leftovers += n

    def inc_resync_scans(self, n: int = 1):
        with self._lock:
            self.resync_scans += n

    def snapshot(self) -> Dict[str, int]:
        with self._lock:
            return {
                "bytes_downloaded": self.bytes_downloaded,
                "bytes_written": self.bytes_written,
                "total_docs": self.total_docs,
                "valid_docs": self.valid_docs,
                "decode_errors": self.decode_errors,
                "invalid_len": self.invalid_len,
                "leftovers": self.leftovers,
                "resync_scans": self.resync_scans,
            }


# ----------------------------
# Constants
# ----------------------------
BYTES_PER_GB = 1024 ** 3
MAX_DOC_SIZE = 16 * 1024 * 1024  # 16MB MongoDB limit-ish
MIN_DOC_SIZE = 5
QUEUE_MAX_SIZE = 50000

# Default chunk size in MB (can override via env BSON_CHUNK_MB)
DEFAULT_CHUNK_MB = int(os.getenv("BSON_CHUNK_MB", "256"))
DEFAULT_CHUNK_BYTES = DEFAULT_CHUNK_MB * 1024 * 1024

# ----------------------------
# BSON helpers
# ----------------------------


def read_length(data: bytes, offset: int) -> int:
    if offset + 4 > len(data):
        return -1
    # Use unpack_from for zero-copy (avoids allocating new bytes slice)
    return struct.unpack_from("<i", data, offset)[0]


def is_valid_document(data: bytes, offset: int) -> bool:
    if not data or offset < 0:
        return False
    doc_len = read_length(data, offset)
    if doc_len < MIN_DOC_SIZE or doc_len > MAX_DOC_SIZE:
        return False
    end = offset + doc_len
    if end > len(data) or end == 0:
        return False
    # BSON ends with 0x00
    return data[end - 1] == 0


# Convert BSON types to JSON-serializable types
def bson_to_json_serializable(obj: Any) -> Any:
    """Recursively convert BSON-specific types to JSON-compatible types."""
    if obj is None:
        return None
    if isinstance(obj, dict):
        return {k: bson_to_json_serializable(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [bson_to_json_serializable(v) for v in obj]
    if isinstance(obj, bytes):
        # Binary data -> hex string
        return obj.hex()
    if hasattr(obj, 'isoformat'):
        # datetime -> ISO string
        return obj.isoformat()
    if hasattr(obj, '__str__') and type(obj).__name__ == 'ObjectId':
        # bson.ObjectId -> string
        return str(obj)
    return obj


# JSON line serializer (orjson is ~10x faster than stdlib json)
def to_ndjson_line(obj: Dict[str, Any]) -> bytes:
    # Convert BSON types first, then serialize with orjson
    clean_obj = bson_to_json_serializable(obj)
    return orjson.dumps(clean_obj, option=orjson.OPT_APPEND_NEWLINE)


# ----------------------------
# File Processor
# ----------------------------
class FileProcessor:
    def __init__(self, gcs_path: str, num_workers: int, progress: Optional[GlobalProgress] = None, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(__name__)
        if not gcs_path.startswith("gs://"):
            raise ValueError("gcs_path must start with gs://")

        bucket_and_path = gcs_path[5:].split("/", 1)
        bucket_name = bucket_and_path[0]
        object_path = bucket_and_path[1] if len(bucket_and_path) > 1 else ""

        project_id = os.getenv("GCP_PROJECT_ID", "cr-core-host-project-c320755e")
        self.client = storage.Client(project=project_id)
        self.bucket = self.client.bucket(bucket_name)
        self.blob = self.bucket.blob(object_path)
        self.blob.reload()

        if self.blob.size is None:
            raise ValueError(f"File not found: {gcs_path}")

        self.file_size = int(self.blob.size)
        self.num_workers = num_workers
        self.progress = progress

        self._download_lock = threading.Lock()
        self.total_downloaded = 0

    def read_chunk(self, start: int, end: int) -> bytes:
        """
        Download [start, end) bytes. Uses retry with exponential backoff + jitter.
        Always raises on failure, never returns None.
        """
        if end <= start:
            return b""

        # GCS download_as_bytes uses inclusive end param, so we pass end-1
        # Retry only for transient errors.
        last_err = None
        for attempt in range(1, 6):
            try:
                data = self.blob.download_as_bytes(start=start, end=end - 1)
                with self._download_lock:
                    self.total_downloaded += len(data)
                if self.progress is not None:
                    self.progress.inc_downloaded(len(data))
                return data
            except Exception as e:
                last_err = e
                msg = str(e).lower()
                transient = (
                    "429" in msg or
                    "503" in msg or
                    "500" in msg or
                    "timeout" in msg or
                    "temporarily" in msg or
                    "connection" in msg or
                    "broken pipe" in msg
                )
                if not transient or attempt == 5:
                    raise RuntimeError(f"Failed to download chunk {start}-{end}: {e}") from e
                # exponential backoff with jitter
                sleep_s = (0.5 * (2 ** (attempt - 1))) + random.random() * 0.3
                time.sleep(sleep_s)
        
        # Should never reach here, but ensure we always raise on failure
        if last_err:
            raise RuntimeError(f"Failed to download chunk {start}-{end}: {last_err}") from last_err
        raise RuntimeError(f"Failed to download chunk {start}-{end}: unknown error")

    def calculate_ranges(self) -> List[RangeInfo]:
        chunk_size = self.file_size // self.num_workers
        ranges: List[RangeInfo] = []
        for i in range(self.num_workers):
            start = i * chunk_size
            logical_end = (i + 1) * chunk_size if i < self.num_workers - 1 else self.file_size
            # no-overlap mode: end == logical_end
            end = logical_end
            ranges.append(RangeInfo(i, start, end, i == 0, i == self.num_workers - 1, logical_end))
        return ranges

    # ----------------------------
    # Domain-specific extraction
    # ----------------------------
    # Classifications to always exclude (even if positives > 0)
    # These are ML-determined "not a threat" - trust the model over low AV counts
    EXCLUDE_CLASSIFICATIONS = {"indifferent", "unknown"}

    def filter_and_extract(self, doc: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Filter and extract VT scan report.
        
        Returns the FULL value object (for Broccoli ML compatibility) with:
        - vtClassifierV2Classification added as 'broccoli_classification'
        - _id (sha1) added if not present in value
        
        Filtering criteria:
        - response_code == 1 (valid VT response)
        - classification NOT IN {indifferent, unknown} (trust ML model)
        - AND (positives > 0 OR has valid threat classification)
        """
        if not doc:
            return None
        value = doc.get("value", {})
        if not isinstance(value, dict):
            return None
        if value.get("response_code") != 1:
            return None

        # Get threat indicators first
        positives = value.get("positives", 0)
        # Handle float values (some records have 0.0 instead of 0)
        if isinstance(positives, float):
            positives = int(positives)

        vt = doc.get("vtClassifierV2Classification")
        classification = None
        if isinstance(vt, dict):
            classification = vt.get("classification")

        # Skip if ML model says "indifferent" or "unknown" - trust the model
        # These have low positives and the ML determined they're not threats
        classification_lower = classification.lower() if classification else None
        if classification_lower in self.EXCLUDE_CLASSIFICATIONS:
            return None  # Skip ML-determined non-threats
        
        # Keep if:
        # - Has valid threat classification (malware, ransomware, hacktool, unwanted, etc.)
        # - OR has AV detections (positives > 0) with null classification (can be inferred later)
        if classification_lower is None and positives <= 0:
            return None  # Skip: no classification and no AV detections

        # Return full value object with additional fields
        result = dict(value)  # Copy the full value object
        
        # Add Broccoli classification from vtClassifierV2Classification
        if classification:
            result["broccoli_classification"] = classification
        
        # Ensure sha1 is present (fallback to _id which is sha1)
        if not result.get("sha1") and doc.get("_id"):
            result["sha1"] = doc.get("_id")
        
        # Normalize float fields to int
        if isinstance(result.get("positives"), float):
            result["positives"] = int(result["positives"])
        if isinstance(result.get("total"), float):
            result["total"] = int(result["total"])
        
        return result

    # ----------------------------
    # Resync helpers (no-overlap mode)
    # ----------------------------
    def resync_start(self, start: int, logical_end: int, scan_window: int = 8 * 1024 * 1024) -> int:
        """
        Find the next valid document start at or after 'start' within [start, logical_end).
        This is critical for no-overlap mode to avoid starting from middle of a doc.

        We scan in windows and look for a valid BSON document signature using is_valid_document.
        Returns a new start position; if not found, returns logical_end (meaning nothing to process).
        """
        pos = start
        while pos < logical_end:
            end = min(pos + scan_window, logical_end)
            data = self.read_chunk(pos, end)
            if len(data) < 8:
                return logical_end
            # scan for a doc start - optimize with 4-byte alignment first (BSON docs usually aligned)
            # Try 4-byte aligned offsets first (much faster)
            for off in range(0, len(data) - 5, 4):
                if is_valid_document(data, off):
                    return pos + off
            # Fallback: scan byte-by-byte if 4-byte aligned scan didn't find anything
            for off in range(1, len(data) - 5):
                if off % 4 == 0:  # Skip already checked offsets
                    continue
                if is_valid_document(data, off):
                    return pos + off
            # Move forward; keep overlap so boundary docs aren't missed.
            # 8 bytes overlap (header + slack) is safer than 4/5 and still cheap.
            pos = end - 8
            if pos < start:
                pos = start
        return logical_end

    def find_next_valid_offset(self, data: bytes, start_off: int, max_scan: int = 2 * 1024 * 1024) -> Optional[int]:
        """
        Inside a downloaded chunk: scan forward from start_off to find next valid doc start.
        max_scan bounds CPU cost on corrupted regions.
        Increased to 2MB to avoid skipping valid docs after large corrupted regions.
        """
        end_off = min(len(data) - 5, start_off + max_scan)
        for off in range(start_off, end_off):
            if is_valid_document(data, off):
                return off
        return None

    # ----------------------------
    # Range processing (no overlap + leftovers)
    # ----------------------------
    def process_range(
        self,
        range_info: RangeInfo,
        q: queue.Queue,
        shutdown_event: threading.Event,
        worker_done_events: Dict[int, threading.Event],
        chunk_size: int = DEFAULT_CHUNK_BYTES,
    ) -> Dict[str, Any]:
        worker_id = range_info.worker_id
        stats = ProcessingStats()
        leftovers: List[LeftoverDoc] = []

        logical_end = range_info.logical_end

        start_pos = range_info.start
        if not range_info.is_first:
            start_pos = self.resync_start(range_info.start, logical_end)
            stats.resync_scans += 1
            if self.progress:
                self.progress.inc_resync_scans(1)

        if start_pos >= logical_end:
            # nothing to do, but still signal writer flush marker
            worker_done_events[worker_id].clear()
            q.put(("worker_done", worker_id))
            return {"worker_id": worker_id, "stats": stats, "leftovers": leftovers, "complete": True}

        self.logger.info(f"[Worker {worker_id}] Start: {(logical_end-range_info.start)/BYTES_PER_GB:.2f}GB ({range_info.start:,}-{logical_end:,})")

        current_pos = start_pos
        carry = b""  # Carryover buffer for cross-chunk docs (within same range)
        carry_base = 0  # Global base position for carry bytes

        while current_pos < logical_end and not shutdown_event.is_set():
            chunk_end = min(current_pos + chunk_size, logical_end)
            if chunk_end <= current_pos:
                break

            chunk_data = self.read_chunk(current_pos, chunk_end)
            stats.bytes_read += len(chunk_data)

            # Prepend carryover from previous chunk
            if carry:
                chunk_data = carry + chunk_data
                chunk_global_base = carry_base
                carry = b""
                carry_base = 0
            else:
                chunk_global_base = current_pos

            chunk_local = 0

            # Parse documents inside this chunk
            while chunk_local <= len(chunk_data) - 5 and not shutdown_event.is_set():
                doc_start_global = chunk_global_base + chunk_local
                if doc_start_global >= logical_end:
                    break

                doc_len = read_length(chunk_data, chunk_local)

                if doc_len < MIN_DOC_SIZE or doc_len > MAX_DOC_SIZE:
                    stats.invalid_len += 1
                    if self.progress:
                        self.progress.inc_invalid_len(1)
                    nxt = self.find_next_valid_offset(chunk_data, chunk_local + 1)
                    if nxt is None:
                        # Move forward with smaller step to avoid skipping valid docs
                        # Don't blindly jump 2MB - might skip valid region near chunk end
                        chunk_local += 256 * 1024  # 256KB step
                        continue
                    chunk_local = nxt
                    continue

                doc_end_local = chunk_local + doc_len
                
                # Check if doc crosses chunk boundary (but still within range)
                if doc_end_local > len(chunk_data):
                    # Only mark as leftover if it crosses range boundary
                    if doc_start_global + doc_len > logical_end:
                        leftovers.append(LeftoverDoc(global_start=doc_start_global, owner_worker_id=worker_id))
                        stats.leftovers += 1
                        if self.progress:
                            self.progress.inc_leftovers(1)
                    else:
                        # Cross-chunk but within range => carry it (allow up to MAX_DOC_SIZE)
                        carry = chunk_data[chunk_local:]
                        carry_base = doc_start_global
                        if len(carry) > MAX_DOC_SIZE:
                            # Clamp carry defensively (should be rare, but prevents pathological memory)
                            carry = carry[:MAX_DOC_SIZE]
                    break

                if chunk_data[doc_end_local - 1] != 0:
                    stats.invalid_len += 1
                    if self.progress:
                        self.progress.inc_invalid_len(1)
                    nxt = self.find_next_valid_offset(chunk_data, chunk_local + 1)
                    if nxt is None:
                        # Move forward with smaller step to avoid skipping valid docs
                        chunk_local += 256 * 1024  # 256KB step
                        continue
                    chunk_local = nxt
                    continue

                stats.total_docs += 1
                if self.progress:
                    self.progress.inc_total_docs(1)
                doc_bytes = chunk_data[chunk_local:doc_end_local]
                try:
                    doc = bson.decode(doc_bytes)
                    extracted = self.filter_and_extract(doc)
                    if extracted:
                        stats.valid_docs += 1
                        if self.progress:
                            self.progress.inc_valid_docs(1)
                        # Backpressure: check queue only every 1024 docs to reduce lock contention
                        if (stats.valid_docs & 0x3FF) == 0:  # Every 1024 docs
                            if q.full():
                                time.sleep(0.01)
                        q.put(("line", to_ndjson_line(extracted)), block=True)
                except Exception:
                    stats.decode_errors += 1
                    if self.progress:
                        self.progress.inc_decode_errors(1)

                chunk_local = doc_end_local

            current_pos = chunk_end
            del chunk_data  # free memory
        
        # Handle any remaining carryover at end of range
        # Only meaningful case: doc crosses range boundary (incomplete doc that spans to next range)
        if carry and not shutdown_event.is_set():
            if len(carry) >= 4:
                doc_len = read_length(carry, 0)
                if MIN_DOC_SIZE <= doc_len <= MAX_DOC_SIZE:
                    # Only record as leftover if it crosses range boundary
                    if carry_base + doc_len > logical_end:
                        leftovers.append(LeftoverDoc(global_start=carry_base, owner_worker_id=worker_id))
                        stats.leftovers += 1
                        if self.progress:
                            self.progress.inc_leftovers(1)
                    # Otherwise, carry is incomplete doc within range but no more chunks - discard
                    # (This shouldn't happen normally, but handle gracefully)

        # If shutdown, do not mark worker complete.
        if shutdown_event.is_set():
            return {"worker_id": worker_id, "stats": stats, "leftovers": leftovers, "complete": False}

        # Signal writer: all lines from this worker have been enqueued; writer will flush and ack.
        worker_done_events[worker_id].clear()
        q.put(("worker_done", worker_id), block=True)

        return {"worker_id": worker_id, "stats": stats, "leftovers": leftovers, "complete": True}

    def process_leftover_doc(self, leftover: LeftoverDoc) -> Optional[Dict[str, Any]]:
        if leftover.global_start < 0 or leftover.global_start + 4 > self.file_size:
            return None

        # 1) read length (4 bytes)
        hdr = self.read_chunk(leftover.global_start, leftover.global_start + 4)
        if len(hdr) != 4:
            return None
        doc_len = struct.unpack_from("<i", hdr, 0)[0]
        if doc_len < MIN_DOC_SIZE or doc_len > MAX_DOC_SIZE:
            return None
        if leftover.global_start + doc_len > self.file_size:
            return None

        # 2) read full doc
        data = self.read_chunk(leftover.global_start, leftover.global_start + doc_len)

        # Cheap validation before decode: trailing 0x00
        if not data or data[-1] != 0:
            return None

        try:
            doc = bson.decode(data)
            return self.filter_and_extract(doc)
        except Exception:
            return None


# ----------------------------
# Checkpoint I/O
# ----------------------------
def save_checkpoint(checkpoint: Checkpoint, checkpoint_file: str):
    checkpoint.last_update = time.time()
    tmp = checkpoint_file + ".tmp"
    with open(tmp, "w") as f:
        json.dump(asdict(checkpoint), f, indent=2)
    os.replace(tmp, checkpoint_file)


def load_checkpoint(checkpoint_file: str) -> Optional[Checkpoint]:
    try:
        with open(checkpoint_file, "r") as f:
            data = json.load(f)
            # Handle old checkpoints without net_bytes_downloaded
            if "net_bytes_downloaded" not in data:
                data["net_bytes_downloaded"] = data.get("bytes_processed", 0)
            return Checkpoint(**data)
    except Exception:
        return None


# ----------------------------
# Worker scaling
# ----------------------------
def calculate_optimal_workers(file_size_bytes: int) -> int:
    # With chunked download and KB-level docs, network dominates.
    # 16~48 workers typical; cap to prevent too many parallel range reads.
    file_size_gb = file_size_bytes / BYTES_PER_GB
    return max(8, min(48, max(1, int(file_size_gb / 20.0))))


# ----------------------------
# Main file processing
# ----------------------------
def process_file(gcs_path: str, output_file: str, resume: bool = False, logger: Optional[logging.Logger] = None):
    # Use provided logger or create a default one
    if logger is None:
        logger = logging.getLogger(__name__)
    checkpoint_file = output_file + ".checkpoint"
    checkpoint = load_checkpoint(checkpoint_file) if resume else None

    # Read actual file size
    temp = FileProcessor(gcs_path, 1, None)
    actual_size = temp.file_size

    if checkpoint:
        # Validate checkpoint matches target
        if checkpoint.gcs_path != gcs_path or checkpoint.output_file != output_file:
            raise RuntimeError("Checkpoint does not match this job (gcs_path/output_file mismatch).")
        # IMPORTANT FIX: do not resume if blob size changed (ranges would differ)
        if checkpoint.file_size != actual_size:
            raise RuntimeError(
                f"Blob size changed ({checkpoint.file_size} -> {actual_size}); cannot resume safely."
            )
        num_workers = checkpoint.num_workers  # IMPORTANT: keep worker partitioning consistent
        completed_workers = set(checkpoint.completed_ranges)
        logger.info(f"Resuming: {len(completed_workers)}/{num_workers} workers done")
    else:
        num_workers = calculate_optimal_workers(actual_size)
        completed_workers = set()

    # Global progress snapshotter - restore from checkpoint if resuming
    # Use current time for accurate throughput (don't count downtime)
    if checkpoint:
        progress = GlobalProgress(
            start_time=time.time(),  # Current run start time (not checkpoint.start_time)
            base_bytes_downloaded=checkpoint.net_bytes_downloaded,  # Use net_bytes_downloaded for base
            base_valid_docs=checkpoint.valid_docs,
            bytes_downloaded=checkpoint.net_bytes_downloaded,  # Initialize with checkpoint value
            valid_docs=checkpoint.valid_docs,
        )
    else:
        progress = GlobalProgress(start_time=time.time())
    
    processor = FileProcessor(gcs_path, num_workers, progress, logger=logger)
    logger.info(f"Processing: {gcs_path}")
    logger.info(f"Size: {processor.file_size/BYTES_PER_GB:.2f} GB | Workers: {num_workers} | Output: {output_file}")
    logger.info(f"Mode: no-overlap + leftover resolver | Chunk: {DEFAULT_CHUNK_MB}MB | gzip compresslevel=1")

    if checkpoint is None:
        checkpoint = Checkpoint(
            gcs_path=gcs_path,
            output_file=output_file,
            num_workers=num_workers,
            file_size=processor.file_size,
            completed_ranges=[],
            valid_docs=0,
            bytes_processed=0,
            net_bytes_downloaded=0,
            start_time=time.time(),
        )
        save_checkpoint(checkpoint, checkpoint_file)

    ranges_all = processor.calculate_ranges()
    ranges = [r for r in ranges_all if r.worker_id not in completed_workers]

    if not ranges:
        logger.info("All workers completed (per checkpoint).")
        return

    shutdown_event = threading.Event()

    def _handle_sig(_s, _f):
        shutdown_event.set()
        logger.warning("[!] Interrupted (SIGINT/SIGTERM). Will stop scheduling new work and save checkpoint...")

    signal.signal(signal.SIGINT, _handle_sig)
    signal.signal(signal.SIGTERM, _handle_sig)

    # Writer: open gzip in binary mode; write bytes for max speed.
    # If resume and file exists: append mode.
    out_mode = "ab" if (resume and os.path.exists(output_file)) else "wb"
    output_fd = gzip.open(output_file, out_mode, compresslevel=1)

    # Result queue: holds ("line", bytes|str) or ("worker_done", worker_id) or ("DONE", None)
    result_queue: queue.Queue = queue.Queue(maxsize=QUEUE_MAX_SIZE)

    # For safer checkpointing: writer will ack worker_done after flushing all prior lines.
    worker_done_events: Dict[int, threading.Event] = {r.worker_id: threading.Event() for r in ranges_all}

    # Live progress logger thread (30s interval to reduce log volume)
    LOG_INTERVAL_SECONDS = 30
    
    def progress_logger():
        last = time.time()
        last_written = 0
        while not shutdown_event.is_set():
            time.sleep(LOG_INTERVAL_SECONDS)
            snap = progress.snapshot()
            now = time.time()
            elapsed = now - progress.start_time
            if elapsed <= 0:
                continue

            delta_bytes = snap["bytes_downloaded"] - progress.base_bytes_downloaded
            
            downloaded_gb = snap["bytes_downloaded"] / BYTES_PER_GB
            written_gb = snap["bytes_written"] / BYTES_PER_GB
            # Throughput based on this run's delta (not total, which includes downtime)
            mbps = (delta_bytes / elapsed) / (1024 ** 2) if elapsed > 0 else 0

            # writer speed since last log
            written_delta = snap["bytes_written"] - last_written
            dt = now - last
            writer_mbps = (written_delta / dt) / (1024 ** 2) if dt > 0 else 0
            last_written = snap["bytes_written"]
            last = now

            # Worker completion stats (for display only, not used for ETA)
            done_workers = len(checkpoint.completed_ranges)
            worker_pct = (done_workers / num_workers * 100.0) if num_workers > 0 else 0.0
            
            # Progress and ETA based on download bytes (stable, doesn't fluctuate with worker completion)
            dl_pct = (snap["bytes_downloaded"] / processor.file_size * 100.0) if processor.file_size > 0 else 0.0
            
            # ETA based on download speed (stable, doesn't fluctuate with worker completion)
            remaining_bytes = processor.file_size - snap["bytes_downloaded"]
            if delta_bytes > 0 and elapsed > 0:
                bytes_per_sec = delta_bytes / elapsed
                eta_min = (remaining_bytes / bytes_per_sec) / 60 if bytes_per_sec > 0 else 0
            else:
                eta_min = 0

            err_rate = (snap["decode_errors"] / snap["total_docs"] * 100.0) if snap["total_docs"] > 0 else 0.0
            valid_rate = (snap["valid_docs"] / snap["total_docs"] * 100.0) if snap["total_docs"] > 0 else 0.0
            logger.info(
                f"[Live] {elapsed/60:.1f}min | Workers: {done_workers}/{num_workers} ({worker_pct:.1f}%) | "
                f"Progress: {dl_pct:.1f}% | "
                f"DL: {downloaded_gb:.2f}GB @ {mbps:.1f}MB/s | "
                f"Wrote: {written_gb:.2f}GB @ {writer_mbps:.1f}MB/s | "
                f"Valid: {snap['valid_docs']:,}/{snap['total_docs']:,} ({valid_rate:.1f}%) | "
                f"DecodeErr: {snap['decode_errors']:,} ({err_rate:.2f}%) | "
                f"InvalidLen: {snap['invalid_len']:,} | Resync: {snap['resync_scans']:,} | "
                f"Leftovers: {snap['leftovers']:,} | Queue: {result_queue.qsize():,} | ETA: {eta_min:.1f}min"
            )

    logger_thread = threading.Thread(target=progress_logger, daemon=True)
    logger_thread.start()

    # Writer thread (IMPORTANT: runs until it receives DONE; never exits early)
    def result_writer():
        batch: List[bytes] = []
        BATCH_BYTES_FLUSH = 8 * 1024 * 1024
        batch_bytes = 0

        def _flush():
            nonlocal batch, batch_bytes
            if not batch:
                return
            out = bytearray()
            for item in batch:
                out.extend(item)  # Always bytes from orjson
            try:
                output_fd.write(out)
                progress.inc_written(len(out))
            except Exception as e:
                logger.error(f"[Writer Error] flush failed: {e}")
                shutdown_event.set()  # CRITICAL: stop workers on write failure
            finally:
                batch = []
                batch_bytes = 0

        while True:
            if shutdown_event.is_set():
                _flush()
                try:
                    output_fd.flush()
                except Exception:
                    pass
                return

            try:
                msg = result_queue.get(timeout=0.2)
            except queue.Empty:
                continue

            try:
                if msg[0] == "DONE":
                    _flush()
                    try:
                        output_fd.flush()
                    except Exception:
                        pass
                    return

                if msg[0] == "line":
                    payload = msg[1]
                    batch.append(payload)
                    batch_bytes += len(payload)  # Always bytes from orjson
                    if batch_bytes >= BATCH_BYTES_FLUSH:
                        _flush()
                    continue

                if msg[0] == "worker_done":
                    worker_id = msg[1]
                    _flush()
                    try:
                        output_fd.flush()
                    except Exception:
                        pass
                    worker_done_events[worker_id].set()
                    continue
            finally:
                result_queue.task_done()

    writer_thread = threading.Thread(target=result_writer, daemon=True)
    writer_thread.start()

    # Processing loop
    all_leftovers: List[LeftoverDoc] = []
    last_checkpoint_save = time.time()

    try:
        max_concurrent = min(32, len(ranges), num_workers)  # tune if you see 429/503
        logger.info(f"[Starting] {len(ranges)} workers pending, max_concurrent={max_concurrent}")

        with ThreadPoolExecutor(max_workers=max_concurrent) as executor:
            futures = {
                executor.submit(processor.process_range, r, result_queue, shutdown_event, worker_done_events): r.worker_id
                for r in ranges
            }
            logger.info(f"[Started] Submitted {len(futures)} workers.")

            for future in as_completed(futures):
                wid = futures[future]

                if shutdown_event.is_set():
                    # stop waiting; allow running tasks to notice shutdown_event
                    break

                result = future.result()
                s: ProcessingStats = result["stats"]
                complete: bool = result["complete"]
                # Note: progress is updated incrementally during processing, no need to add_worker_stats

                if not complete:
                    logger.warning(f"[Worker {wid}] stopped early due to shutdown.")
                    continue

                # Wait until writer confirms all this worker's enqueued lines are flushed
                if not worker_done_events[wid].wait(timeout=600):
                    logger.warning(f"[Warning] Worker {wid} done event timeout, proceeding anyway")

                # Only now mark worker complete in checkpoint
                checkpoint.completed_ranges.append(wid)
                checkpoint.valid_docs += s.valid_docs
                checkpoint.bytes_processed += s.bytes_read
                # Update net_bytes_downloaded from progress (includes resync/leftovers)
                checkpoint.net_bytes_downloaded = progress.bytes_downloaded

                all_leftovers.extend(result["leftovers"])

                # Save checkpoint on every worker completion for better recovery
                now = time.time()
                save_checkpoint(checkpoint, checkpoint_file)
                last_checkpoint_save = now

                # Worker completion log (still useful)
                elapsed = now - checkpoint.start_time
                speed_mbps = (checkpoint.bytes_processed / elapsed / (1024 ** 2)) if elapsed > 0 else 0
                pct = (checkpoint.bytes_processed / processor.file_size * 100.0) if processor.file_size > 0 else 0.0
                logger.info(f"[Done] Worker {wid} | {len(checkpoint.completed_ranges)}/{num_workers} | "
                      f"{checkpoint.bytes_processed/BYTES_PER_GB:.2f}GB/{processor.file_size/BYTES_PER_GB:.2f}GB ({pct:.1f}%) | "
                      f"Valid: {checkpoint.valid_docs:,} | Speed: {speed_mbps:.1f}MB/s")

        # IMPORTANT: wait all queued messages consumed (task_done called) BEFORE sending DONE
        result_queue.join()
        result_queue.put(("DONE", None))
        writer_thread.join(timeout=300)

        save_checkpoint(checkpoint, checkpoint_file)

    finally:
        try:
            output_fd.close()
        except Exception:
            pass

    if shutdown_event.is_set():
        logger.warning("Interrupted or writer failed. Checkpoint saved. Resume with --resume")
        return

    # Deduplicate leftovers by global_start
    if all_leftovers:
        uniq: Dict[int, LeftoverDoc] = {}
        for lo in all_leftovers:
            if lo.global_start not in uniq:
                uniq[lo.global_start] = lo
        deduped = list(uniq.values())
        logger.info(f"[Leftovers] {len(all_leftovers)} collected, {len(deduped)} deduped. Resolving...")

        # Append resolved leftovers to output
        out_mode2 = "ab"
        with gzip.open(output_file, out_mode2, compresslevel=1) as f:
            resolved = 0
            dl_bytes = 0
            for lo in deduped:
                if shutdown_event.is_set():
                    break
                doc = processor.process_leftover_doc(lo)
                if doc:
                    line = to_ndjson_line(doc)  # Always bytes from orjson
                    f.write(line)
                    progress.inc_written(len(line))
                    resolved += 1
                # Extra downloads are tracked in processor.total_downloaded via read_chunk calls
            f.flush()
        logger.info(f"[Leftovers] Resolved: {resolved:,} valid docs")

    total_time = time.time() - checkpoint.start_time
    out_size = os.path.getsize(output_file) if os.path.exists(output_file) else 0
    snap = progress.snapshot()
    valid_rate = (snap["valid_docs"] / snap["total_docs"] * 100.0) if snap["total_docs"] > 0 else 0.0
    logger.info(f"Complete: valid={snap['valid_docs']:,}/{snap['total_docs']:,} ({valid_rate:.1f}%) | "
          f"Downloaded: {snap['bytes_downloaded']/BYTES_PER_GB:.2f}GB | "
          f"Output: {out_size/BYTES_PER_GB:.2f}GB | Time: {total_time/60:.1f}min")


def main():
    parser = argparse.ArgumentParser(description="Parallel BSON Processor (no-overlap + leftovers + live logs)")
    parser.add_argument("--shard", type=str, choices=["r01", "r02", "r03", "r04", "r05", "r06"],
                        help="Process specific shard (default: all 6 shards)")
    parser.add_argument("--resume", action="store_true", help="Resume from checkpoint")
    args = parser.parse_args()

    base_bucket_path = "gs://sage_prod_dump"
    collection_path = "cybereason/file_rep.bson"
    shards = [args.shard] if args.shard else ["r01", "r02", "r03", "r04", "r05", "r06"]

    for shard in shards:
        # Setup per-shard logging (auto-named: bson_processor_r01.log, etc.)
        log_file = f"bson_processor_{shard}.log"
        logger = setup_logging(log_file, name=f"bson_{shard}")
        logger.info(f"Logging to: {log_file}")

        shard_gcs_path = f"{base_bucket_path}/cr-mongo-shard-{shard}.cybereason.net/{collection_path}"
        shard_output = f"file_rep_{shard}_full.ndjson.gz"  # "_full" suffix: contains complete VT value object
        logger.info(f"========== [Shard {shard}] ==========")
        try:
            process_file(shard_gcs_path, shard_output, args.resume, logger=logger)
            logger.info(f"Shard {shard} completed successfully")
        except Exception as e:
            logger.error(f"Shard {shard} failed: {e}")


if __name__ == "__main__":
    main()
