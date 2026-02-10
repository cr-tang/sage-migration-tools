#!/usr/bin/env python3
"""
VT Feeder → Parquet Exporter v5 — Download + Dedup Only

Downloads VT file hash data from vt-file-feeder-by-date, deduplicates
(newest-first), outputs Parquet + zstd. Classification column is left
NULL — can be backfilled later in a separate pass.

Optimized for e2-standard-32 (32 vCPU, 128GB RAM):
    - ProcessPoolExecutor for CPU-bound download+decompress+parse
    - Main thread does dedup (fast hash set lookup) + write

Usage:
    python vt_parquet_exporter.py -o /data/vt_export              # full export
    python vt_parquet_exporter.py -o /data/vt_export --max-days 3 # test 3 days
    python vt_parquet_exporter.py -o /data/vt_export --dry-run    # dry run
"""

import argparse
import bz2
import logging
import multiprocessing
import os
import signal
import sys
import tarfile
import threading
import time
import urllib3
import warnings
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from io import BytesIO
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

warnings.filterwarnings("ignore", message=".*Your application has authenticated using end user credentials.*")
warnings.filterwarnings("ignore", message=".*No project ID could be determined.*")
warnings.filterwarnings("ignore", message=".*Connection pool is full.*")
logging.getLogger("urllib3.connectionpool").setLevel(logging.ERROR)

try:
    from google.cloud import storage
    from google.api_core import retry
    from google.api_core.exceptions import NotFound
except ImportError:
    print("ERROR: google-cloud-storage required. Install: pip install google-cloud-storage")
    sys.exit(1)

try:
    import pyarrow as pa
    import pyarrow.parquet as pq
except ImportError:
    print("ERROR: pyarrow required. Install: pip install pyarrow")
    sys.exit(1)

try:
    import orjson
    json_loads = orjson.loads
except ImportError:
    import json
    json_loads = json.loads

# ─── Constants ───────────────────────────────────────────────────────────────

GCS_BUCKET_NAME = "vt-file-feeder-by-date"
GCS_PROJECT = "vt-feed-pipeline-acfe9f"
VT_FEEDER_START_DATE = "20201101"

DOWNLOAD_WORKERS = 30  # Processes — 32 vCPU, leave 2 for main thread + OS

GCS_RETRY = retry.Retry(
    initial=1.0, maximum=10.0, multiplier=2.0,
    deadline=60.0, predicate=retry.if_transient_error,
)

PARQUET_ROW_GROUP_SIZE = 500_000
PARQUET_FLUSH_SIZE = 2_000_000

PARQUET_SCHEMA = pa.schema([
    ("sha256", pa.string()),
    ("sha1", pa.string()),
    ("md5", pa.string()),
    ("positives", pa.int32()),
    ("total", pa.int32()),
    ("scan_date", pa.string()),
    ("detection_names", pa.string()),
    ("classification", pa.string()),  # NULL for now, backfill later
    ("date", pa.string()),
])

# ─── Logging ─────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("vt_export")

# ─── Graceful Shutdown ───────────────────────────────────────────────────────

shutdown_event = threading.Event()


def _signal_handler(sig, frame):
    logger.warning(">>> Shutdown requested. Finishing current day...")
    shutdown_event.set()


if multiprocessing.current_process().name == "MainProcess":
    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)


# ─── Download Worker (subprocess) ────────────────────────────────────────────

_worker_bucket = None


def _worker_init():
    """Called once per subprocess to create a reusable GCS client."""
    global _worker_bucket
    client = storage.Client(project=GCS_PROJECT)
    _worker_bucket = client.bucket(GCS_BUCKET_NAME)


def _download_and_process(blob_name: str) -> Tuple[str, Optional[List[Dict]], int]:
    """Download tar.bz2, decompress, parse JSON, filter positives>0. Runs in subprocess."""
    try:
        blob = _worker_bucket.blob(blob_name)
        compressed = blob.download_as_bytes(retry=GCS_RETRY, timeout=60)
        data_size = len(compressed)
        decompressed = bz2.decompress(compressed)

        # ── Optimized: skip tarfile overhead, read NDJSON directly ────
        # The tar contains a single NDJSON file. Instead of full tarfile parsing,
        # find the data payload after the tar header (512 bytes per header block).
        # Fallback to tarfile if this fails.
        processed = []
        try:
            raw_bytes = _extract_tar_fast(decompressed)
        except Exception:
            raw_bytes = _extract_tar_safe(decompressed)

        # ── Optimized: parse + filter in single pass, minimal allocations ──
        _get = dict.get  # local reference avoids repeated LOAD_ATTR
        for line in raw_bytes.split(b"\n"):
            if not line or line.isspace():
                continue
            try:
                rec = json_loads(line)
            except Exception:
                continue

            positives = _get(rec, "positives", 0)
            if isinstance(positives, float):
                positives = int(positives)
            if positives <= 0:
                continue

            sha256 = _get(rec, "sha256")
            if not sha256 or len(sha256) != 64:
                continue

            total = _get(rec, "total", 0)
            if isinstance(total, float):
                total = int(total)

            # ── Optimized: build detection_names without intermediate list ──
            scans = _get(rec, "scans")
            det = None
            if scans:
                parts = []
                for eng, res in scans.items():
                    if isinstance(res, dict) and _get(res, "detected") and _get(res, "result"):
                        parts.append(eng)
                        parts.append(":")
                        parts.append(res["result"])
                        parts.append(";")
                if parts:
                    parts.pop()  # remove trailing ";"
                    det = "".join(parts)

            processed.append({
                "sha256": sha256.lower(),
                "sha1": (_get(rec, "sha1") or "").lower() or None,
                "md5": (_get(rec, "md5") or "").lower() or None,
                "positives": positives,
                "total": total,
                "scan_date": _get(rec, "scan_date"),
                "detection_names": det,
            })
        return blob_name, processed, data_size
    except NotFound:
        return blob_name, None, 0
    except Exception:
        return blob_name, None, -1


def _extract_tar_fast(data: bytes) -> bytes:
    """Fast tar extraction: skip headers, grab file content directly.

    tar format: 512-byte header blocks. First header at offset 0.
    File size at header[124:136] in octal. Data follows header.
    """
    # Read file size from tar header (octal string at offset 124-136)
    size_field = data[124:136].rstrip(b"\x00").strip()
    if not size_field:
        raise ValueError("empty size field")
    file_size = int(size_field, 8)
    # Data starts at offset 512 (after the header block)
    return data[512:512 + file_size]


def _extract_tar_safe(data: bytes) -> bytes:
    """Fallback: use tarfile module."""
    with tarfile.open(fileobj=BytesIO(data), mode="r:") as tar:
        for member in tar.getmembers():
            if member.isfile():
                f = tar.extractfile(member)
                if f:
                    return f.read()
    return b""


# ─── Parquet Writer ──────────────────────────────────────────────────────────


class ParquetWriter:
    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.buffer: List[Dict] = []
        self.part_index = self._find_next_part_index()
        self.total_written = 0

    def _find_next_part_index(self) -> int:
        existing = sorted(self.output_dir.glob("part_*.parquet"))
        if existing:
            return int(existing[-1].stem.split("_")[1]) + 1
        return 0

    def add(self, record: Dict):
        self.buffer.append(record)
        if len(self.buffer) >= PARQUET_FLUSH_SIZE:
            self.flush()

    def flush(self):
        if not self.buffer:
            return
        table = pa.table(
            {col: [r.get(col) for r in self.buffer] for col in PARQUET_SCHEMA.names},
            schema=PARQUET_SCHEMA,
        )
        path = self.output_dir / f"part_{self.part_index:04d}.parquet"
        pq.write_table(
            table, path, compression="zstd", compression_level=3,
            row_group_size=PARQUET_ROW_GROUP_SIZE,
            use_dictionary=["detection_names", "classification", "sha1", "md5"],
        )
        size_mb = path.stat().st_size / (1024 * 1024)
        self.total_written += len(self.buffer)
        logger.info(
            f"  [parquet] {len(self.buffer):,} → {path.name} "
            f"({size_mb:.0f}MB) | Total: {self.total_written:,}"
        )
        self.buffer.clear()
        self.part_index += 1

    def close(self):
        self.flush()


# ─── Dedup Set ───────────────────────────────────────────────────────────────


class DedupSet:
    """Deduplication using SHA1 hashes (20 bytes vs SHA256's 32 bytes).
    
    Memory savings: ~37% reduction (60GB → 38GB for 460M hashes)
    Collision risk: negligible at this scale (~10^-32)
    """
    CHECKPOINT_FILE = ".dedup_checkpoint"

    def __init__(self):
        self._set: Set[bytes] = set()
        self._save_thread: Optional[threading.Thread] = None

    def add_if_new(self, sha1_hex: str) -> bool:
        """Check if SHA1 is new, add if not seen before.
        
        Args:
            sha1_hex: 40-char hex string (SHA1)
        
        Returns:
            True if new (added), False if duplicate
        """
        if not sha1_hex:
            return False
        b = bytes.fromhex(sha1_hex)
        if b in self._set:
            return False
        self._set.add(b)
        return True

    def __len__(self):
        return len(self._set)

    def rebuild_from_parquet(self, output_dir: str):
        """Rebuild dedup set from existing Parquet files using SHA1."""
        d = Path(output_dir)
        files = sorted(d.glob("part_*.parquet"))
        if not files:
            return
        logger.info(f"  Rebuilding dedup from {len(files)} Parquet files (using SHA1)...")
        t0 = time.time()
        for f in files:
            try:
                col = pq.read_table(f, columns=["sha1"]).column("sha1")
                for v in col.to_pylist():
                    if v:
                        self._set.add(bytes.fromhex(v))
            except Exception as e:
                logger.warning(f"  Skipping corrupted file {f.name}: {e}")
                f.unlink()  # delete corrupted file
                logger.info(f"  Deleted {f.name}")
        logger.info(f"  Rebuilt: {len(self._set):,} SHA1 hashes in {time.time()-t0:.1f}s")


# ─── Progress Tracker ────────────────────────────────────────────────────────


class ProgressTracker:
    def __init__(self, path: str, output_dir: str):
        self.path = path
        self.completed: Set[str] = set()
        if os.path.exists(path):
            with open(path) as f:
                self.completed = {line.strip() for line in f if line.strip()}

        # Note: auto-repair removed — it incorrectly deleted progress entries
        # for days with 0 new records (all duplicates or all 404s). Those days
        # are legitimately completed and don't need reprocessing.
        if self.completed:
            logger.info(f"  Loaded {len(self.completed)} completed days from .progress")

    @staticmethod
    def _dates_in_parquet(output_dir: str) -> Optional[Set[str]]:
        """Read all unique dates from existing parquet files."""
        d = Path(output_dir)
        files = sorted(d.glob("part_*.parquet"))
        if not files:
            return set()
        dates: Set[str] = set()
        for f in files:
            try:
                col = pq.read_table(f, columns=["date"]).column("date")
                dates.update(v for v in col.to_pylist() if v)
            except Exception:
                pass  # corrupted files handled by DedupSet.rebuild_from_parquet
        return dates

    def _rewrite(self):
        """Rewrite .progress from current completed set."""
        with open(self.path, "w") as f:
            for d in sorted(self.completed, reverse=True):
                f.write(d + "\n")

    def mark_done(self, date_str: str):
        self.completed.add(date_str)
        with open(self.path, "a") as f:
            f.write(date_str + "\n")

    def is_done(self, d: str) -> bool:
        return d in self.completed


# ─── Date Utils ──────────────────────────────────────────────────────────────


def date_range(start: str, end: str) -> List[str]:
    s, e = datetime.strptime(start, "%Y%m%d"), datetime.strptime(end, "%Y%m%d")
    dates = []
    c = s
    while c <= e:
        dates.append(c.strftime("%Y%m%d"))
        c += timedelta(days=1)
    dates.reverse()  # newest first
    return dates


def file_paths_for_day(date_str: str) -> List[str]:
    return [f"{date_str}/{date_str}T{h:02d}{m:02d}" for h in range(24) for m in range(60)]


# ─── Process One Day ─────────────────────────────────────────────────────────


def process_day(
    pool: ProcessPoolExecutor,
    date_str: str,
    dedup: DedupSet,
    writer: Optional[ParquetWriter],
    dry_run: bool,
) -> Dict[str, int]:
    """Download all files for one day, dedup, write Parquet."""
    paths = file_paths_for_day(date_str)
    stats = {"dl_ok": 0, "dl_miss": 0, "dl_err": 0, "dl_bytes": 0,
             "rec_detected": 0, "rec_new": 0, "rec_dup": 0, "rec_written": 0}

    t0 = time.time()
    done = 0

    futs = {pool.submit(_download_and_process, p): p for p in paths}
    for fut in as_completed(futs):
        if shutdown_event.is_set():
            for f in futs:
                f.cancel()
            break

        blob_name, processed, data_size = fut.result()
        done += 1

        if processed is None:
            if data_size == 0:
                stats["dl_miss"] += 1
            else:
                stats["dl_err"] += 1
        else:
            stats["dl_ok"] += 1
            stats["dl_bytes"] += data_size
            stats["rec_detected"] += len(processed)

            for rec in processed:
                # Use SHA1 for deduplication (37% less memory than SHA256)
                sha1 = rec.get("sha1")
                if sha1 and dedup.add_if_new(sha1):
                    rec["date"] = date_str
                    rec["classification"] = None  # backfill later
                    stats["rec_new"] += 1
                    stats["rec_written"] += 1
                    if not dry_run and writer:
                        writer.add(rec)
                else:
                    stats["rec_dup"] += 1

        if done % 100 == 0:
            elapsed = time.time() - t0
            rate = stats["dl_ok"] / elapsed if elapsed > 0 else 0
            dl_mb = stats["dl_bytes"] / (1024 * 1024)
            logger.info(
                f"    [dl+write] {done}/1440 | "
                f"{stats['dl_ok']} ok {stats['dl_miss']} miss {stats['dl_err']} err | "
                f"{stats['rec_detected']:,}→{stats['rec_new']:,} new {stats['rec_dup']:,} dup | "
                f"{rate:.0f} f/s {dl_mb:.0f}MB | {elapsed:.0f}s"
            )

    elapsed = time.time() - t0
    dl_mb = stats["dl_bytes"] / (1024 * 1024)
    logger.info(
        f"    [DONE] {elapsed:.0f}s | {stats['dl_ok']} files {dl_mb:.0f}MB | "
        f"{stats['rec_detected']:,}→{stats['rec_new']:,} new {stats['rec_dup']:,} dup | "
        f"{stats['rec_written']:,} written"
    )
    return stats


# ─── Main ────────────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(description="VT Feeder → Parquet Exporter v5")
    parser.add_argument("-o", "--output", required=True, help="Output directory")
    parser.add_argument("--max-days", type=int, help="Max days (for testing)")
    parser.add_argument("--dry-run", action="store_true", help="Stats only, no output")
    args = parser.parse_args()

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    all_dates = date_range(VT_FEEDER_START_DATE, datetime.now().strftime("%Y%m%d"))
    if args.max_days:
        all_dates = all_dates[:args.max_days]

    progress = ProgressTracker(str(output_dir / ".progress"), str(output_dir))
    remaining = [d for d in all_dates if not progress.is_done(d)]

    logger.info("=" * 72)
    logger.info("VT Feeder → Parquet Exporter v5 — Download + Dedup (SHA1)")
    logger.info("=" * 72)
    logger.info(f"Date range      : {VT_FEEDER_START_DATE} → today ({len(all_dates)} days)")
    logger.info(f"Completed       : {len(all_dates) - len(remaining)}")
    logger.info(f"Remaining       : {len(remaining)}")
    logger.info(f"Download procs  : {DOWNLOAD_WORKERS}")
    logger.info(f"Classification  : SKIPPED (backfill later)")
    logger.info(f"Dry run         : {args.dry_run}")
    logger.info("=" * 72)

    writer = ParquetWriter(str(output_dir)) if not args.dry_run else None
    dedup = DedupSet()

    # Auto-resume
    if progress.completed:
        logger.info(f"Resuming: {len(progress.completed)} days done")
        dedup.rebuild_from_parquet(str(output_dir))
        logger.info(f"Dedup ready: {len(dedup):,} hashes")
    logger.info("=" * 72)

    g_days = 0
    g_written = 0
    g_dup = 0
    g_bytes = 0
    t_start = time.time()

    # Progress reporter
    def reporter():
        while not shutdown_event.is_set():
            shutdown_event.wait(timeout=60)
            if shutdown_event.is_set():
                break
            h = (time.time() - t_start) / 3600
            left = len(remaining) - g_days
            eta = (left * (time.time() - t_start) / g_days / 3600) if g_days > 0 else 0
            logger.info(
                f"[GLOBAL] {g_days}/{len(remaining)} days ({left} left) | "
                f"ETA: {eta:.1f}h | Written: {g_written:,} | Dup: {g_dup:,} | "
                f"Unique: {len(dedup):,} | DL: {g_bytes/(1024**3):.1f}GB | {h:.1f}h"
            )

    threading.Thread(target=reporter, daemon=True).start()

    # Main loop
    try:
        logger.info(f"Starting {DOWNLOAD_WORKERS} download processes...")
        with ProcessPoolExecutor(max_workers=DOWNLOAD_WORKERS, initializer=_worker_init) as pool:
            logger.info("Process pool ready.")
            for i, date_str in enumerate(remaining):
                if shutdown_event.is_set():
                    logger.warning("Shutdown. Progress saved.")
                    break

                logger.info(f"[{i+1}/{len(remaining)}] ── {date_str} ──")
                stats = process_day(pool, date_str, dedup, writer, args.dry_run)

                progress.mark_done(date_str)
                g_days += 1
                g_written += stats["rec_written"]
                g_dup += stats["rec_dup"]
                g_bytes += stats["dl_bytes"]

                # Checkpoint removed: only save on exit
                # dedup.save_checkpoint(str(output_dir))

                logger.info(f"  ✓ {date_str} | Unique: {len(dedup):,}")

    except KeyboardInterrupt:
        logger.warning("Interrupted!")
    finally:
        if writer:
            writer.close()
        logger.info("Exit complete. Dedup will be rebuilt from Parquet on next start.")

    # Summary
    h = (time.time() - t_start) / 3600
    logger.info("=" * 72)
    logger.info("COMPLETE")
    logger.info(f"Days: {g_days} | Written: {g_written:,} | Dup: {g_dup:,}")
    logger.info(f"Unique: {len(dedup):,} | DL: {g_bytes/(1024**3):.1f}GB | {h:.1f}h")
    if not args.dry_run:
        total_size = sum(f.stat().st_size for f in output_dir.glob("*.parquet"))
        logger.info(f"Output: {total_size/(1024**3):.1f}GB")
    logger.info("=" * 72)


if __name__ == "__main__":
    multiprocessing.set_start_method("spawn", force=True)
    main()
