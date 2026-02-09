#!/usr/bin/env python3
"""
Broccoli Classification Backfill — Multi-Process High-Performance GCS Lookup

Reads existing Parquet files produced by vt_parquet_exporter.py,
extracts unique SHA1 hashes, looks up classification from
gs://broccoli-enricher/latest-reports/{sha1} using raw aiohttp
(bypassing the slow GCS Python SDK), and updates the Parquet files
IN-PLACE with the classification column filled in.

Architecture:
    - N worker processes (default 4), each running its own asyncio event loop
    - Each process handles separate parquet files (no contention)
    - Each process has 500 concurrent aiohttp connections
    - Expected throughput: N × 800 QPS ≈ 3200 QPS with 4 processes

Usage:
    python broccoli_backfill.py /data/vt_export              # auto-resume, 4 processes
    python broccoli_backfill.py /data/vt_export --workers 8   # 8 processes
    python broccoli_backfill.py /data/vt_export --dry-run     # just count, no lookup
"""

import argparse
import asyncio
import fcntl
import logging
import multiprocessing
import os
import signal
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import google.auth
import google.auth.transport.requests
import pyarrow as pa
import pyarrow.parquet as pq

# ─── Configuration ────────────────────────────────────────────────────────────

GCS_BUCKET = "broccoli-enricher"
GCS_BASE_URL = f"https://storage.googleapis.com/{GCS_BUCKET}/latest-reports"

CONCURRENT_PER_PROCESS = 500     # aiohttp connections per process
TOKEN_REFRESH_INTERVAL = 1800    # refresh OAuth token every 30 min
NUM_WORKERS = 4                  # number of parallel processes

PARQUET_ROW_GROUP_SIZE = 500_000

# Queue backpressure: keep enough items queued to avoid worker starvation
QUEUE_MAX_SIZE = 100_000


# ─── Logging (per-process safe) ──────────────────────────────────────────────

def setup_logging(worker_id: Optional[int] = None):
    prefix = f"W{worker_id}" if worker_id is not None else "main"
    logging.basicConfig(
        level=logging.INFO,
        format=f"%(asctime)s [{prefix}] %(message)s",
        datefmt="%H:%M:%S",
        force=True,
    )
    return logging.getLogger("broccoli_backfill")


# ─── Token Manager ────────────────────────────────────────────────────────────

class TokenManager:
    """Async-safe OAuth2 token manager with auto-refresh."""

    def __init__(self):
        self._credentials, self._project = google.auth.default()
        self._lock = asyncio.Lock()
        self._token: Optional[str] = None
        self._expiry: float = 0

    async def get_token(self) -> str:
        now = time.time()
        if self._token and now < self._expiry:
            return self._token
        async with self._lock:
            if self._token and time.time() < self._expiry:
                return self._token
            self._credentials.refresh(google.auth.transport.requests.Request())
            self._token = self._credentials.token
            self._expiry = time.time() + TOKEN_REFRESH_INTERVAL
            return self._token


# ─── Async GCS Lookup ─────────────────────────────────────────────────────────

async def lookup_classifications(
    sha1_list: List[str],
    token_mgr: TokenManager,
    logger: logging.Logger,
) -> Dict[str, Optional[str]]:
    """Look up classifications using raw aiohttp with worker pool pattern."""
    import aiohttp

    results: Dict[str, Optional[str]] = {}
    total = len(sha1_list)
    done = 0
    errors = 0
    not_found = 0
    t0 = time.time()
    last_log = t0

    connector = aiohttp.TCPConnector(
        limit=CONCURRENT_PER_PROCESS,
        limit_per_host=CONCURRENT_PER_PROCESS,
        ttl_dns_cache=300,
        keepalive_timeout=60,           # longer keepalive = more connection reuse
        enable_cleanup_closed=True,
    )
    timeout = aiohttp.ClientTimeout(
        total=60,       # overall timeout per request
        connect=30,     # TCP connect timeout (was 10 — too short under load)
        sock_read=30,   # read timeout
    )

    queue: asyncio.Queue = asyncio.Queue(maxsize=QUEUE_MAX_SIZE)
    producer_done = asyncio.Event()

    async def producer():
        """Feed SHA1s into queue with backpressure."""
        for sha1 in sha1_list:
            await queue.put(sha1)
        producer_done.set()

    async def worker(session: aiohttp.ClientSession, wid: int):
        nonlocal done, errors, not_found, last_log
        while True:
            # Check if producer is done AND queue is empty
            if producer_done.is_set() and queue.empty():
                break
            try:
                sha1 = await asyncio.wait_for(queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                if producer_done.is_set() and queue.empty():
                    break
                continue

            token = await token_mgr.get_token()
            url = f"{GCS_BASE_URL}/{sha1}"
            headers = {"Authorization": f"Bearer {token}"}

            max_retries = 3
            success = False
            for attempt in range(max_retries):
                try:
                    async with session.get(url, headers=headers) as resp:
                        if resp.status == 200:
                            data = await resp.json(content_type=None)
                            response = data.get("response", {})
                            results[sha1] = response.get("class")
                            success = True
                            break
                        elif resp.status == 404:
                            results[sha1] = None
                            not_found += 1
                            success = True
                            break
                        elif resp.status in (429, 500, 502, 503):
                            # Exponential backoff: 1s, 2s, 4s
                            await asyncio.sleep(min(1.0 * (2 ** attempt), 8.0))
                        else:
                            results[sha1] = None
                            errors += 1
                            if errors <= 5:
                                logger.warning(f"  [http {resp.status}] {sha1}")
                            success = True
                            break
                except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                    # Connection timeout, server disconnect, etc — retry with backoff
                    if attempt == max_retries - 1:
                        results[sha1] = None
                        errors += 1
                        if errors <= 5:
                            logger.warning(f"  [err] {sha1}: {type(e).__name__}")
                    else:
                        await asyncio.sleep(min(0.5 * (2 ** attempt), 4.0))
                except Exception as e:
                    results[sha1] = None
                    errors += 1
                    if errors <= 5:
                        logger.warning(f"  [err] {sha1}: {type(e).__name__}: {e}")
                    break

            done += 1
            now = time.time()
            if now - last_log >= 10.0:
                elapsed = now - t0
                qps = done / elapsed if elapsed > 0 else 0
                pct = done * 100 // total if total > 0 else 0
                logger.info(
                    f"  [lookup] {done:,}/{total:,} "
                    f"({pct}%) | "
                    f"{qps:.0f} QPS | "
                    f"{not_found:,} miss {errors:,} err | "
                    f"{elapsed:.0f}s"
                )
                last_log = now

    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        # Start producer and workers concurrently
        producer_task = asyncio.create_task(producer())
        worker_tasks = [asyncio.create_task(worker(session, i))
                        for i in range(CONCURRENT_PER_PROCESS)]

        # Wait for producer to finish feeding
        await producer_task
        # Wait for all workers to drain the queue and finish
        await asyncio.gather(*worker_tasks)

    elapsed = time.time() - t0
    qps = total / elapsed if elapsed > 0 else 0
    logger.info(
        f"  [DONE] {total:,} lookups in {elapsed:.0f}s "
        f"({qps:.0f} QPS) | "
        f"{not_found:,} miss {errors:,} err"
    )
    return results


# ─── In-Place Parquet Update ─────────────────────────────────────────────────

def update_parquet_inplace(
    parquet_file: str,
    classifications: Dict[str, Optional[str]],
) -> Tuple[int, int]:
    """Update classification column in-place (write tmp → atomic rename)."""
    table = pq.read_table(parquet_file)
    sha1_col = table.column("sha1").to_pylist()

    new_classifications = []
    filled = 0
    for sha1 in sha1_col:
        if sha1 and sha1 in classifications:
            cls = classifications[sha1]
            new_classifications.append(cls)
            if cls is not None:
                filled += 1
        else:
            new_classifications.append(None)

    col_idx = table.schema.get_field_index("classification")
    new_col = pa.array(new_classifications, type=pa.string())
    table = table.set_column(col_idx, "classification", new_col)

    tmp_path = parquet_file + ".tmp"
    pq.write_table(
        table, tmp_path, compression="zstd", compression_level=3,
        row_group_size=PARQUET_ROW_GROUP_SIZE,
        use_dictionary=["detection_names", "classification", "sha1", "md5"],
    )
    os.replace(tmp_path, parquet_file)

    return len(sha1_col), filled


# ─── Progress Tracking (file-level locking for multi-process safety) ─────────

class ProgressTracker:
    """Multi-process safe progress tracker using file locking."""

    def __init__(self, progress_file: str):
        self._path = progress_file
        self._lock_path = progress_file + ".lock"

    def _read(self) -> Set[str]:
        if not os.path.exists(self._path):
            return set()
        with open(self._path, "r") as f:
            return set(line.strip() for line in f if line.strip())

    def _write(self, completed: Set[str]):
        with open(self._path, "w") as f:
            for name in sorted(completed):
                f.write(name + "\n")

    def get_completed(self) -> Set[str]:
        return self._read()

    def mark_done(self, filename: str):
        """Atomically add a filename to the progress file."""
        with open(self._lock_path, "w") as lock_f:
            fcntl.flock(lock_f, fcntl.LOCK_EX)
            try:
                completed = self._read()
                completed.add(filename)
                self._write(completed)
            finally:
                fcntl.flock(lock_f, fcntl.LOCK_UN)


# ─── Worker Process ──────────────────────────────────────────────────────────

def process_file(args_tuple: Tuple) -> Tuple[str, int, int, float]:
    """Process a single parquet file in a worker process.

    Each worker process runs its own asyncio event loop with its own
    aiohttp connection pool — no GIL contention between processes.
    """
    parquet_file, worker_id, dry_run = args_tuple
    logger = setup_logging(worker_id)
    pf = Path(parquet_file)

    logger.info(f"Processing {pf.name}")

    t0 = time.time()
    try:
        table = pq.read_table(str(pf), columns=["sha1"])
    except Exception as e:
        logger.warning(f"  Skipping corrupted file {pf.name}: {e}")
        return pf.name, 0, 0, 0.0

    sha1s = table.column("sha1").to_pylist()
    unique_sha1s = list(set(s for s in sha1s if s))
    logger.info(f"  {len(sha1s):,} rows, {len(unique_sha1s):,} unique SHA1s")
    del table

    if dry_run:
        logger.info(f"  [dry-run] Would lookup {len(unique_sha1s):,} SHA1s")
        return pf.name, len(sha1s), 0, time.time() - t0

    # Each process gets its own token manager and event loop
    token_mgr = TokenManager()
    classifications = asyncio.run(
        lookup_classifications(unique_sha1s, token_mgr, logger)
    )

    total, filled = update_parquet_inplace(str(pf), classifications)
    elapsed = time.time() - t0

    logger.info(
        f"  [DONE] {total:,} rows, {filled:,} classified "
        f"({filled*100//total if total else 0}%) | {elapsed:.0f}s"
    )
    return pf.name, total, filled, elapsed


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Broccoli classification backfill (multi-process, in-place)")
    parser.add_argument("parquet_dir", help="Parquet directory to update in-place")
    parser.add_argument("--workers", type=int, default=NUM_WORKERS, help=f"Number of parallel processes (default {NUM_WORKERS})")
    parser.add_argument("--dry-run", action="store_true", help="Just count SHA1s, don't lookup")
    args = parser.parse_args()

    logger = setup_logging()

    parquet_dir = Path(args.parquet_dir)
    progress = ProgressTracker(str(parquet_dir / ".backfill_progress"))

    # Find parquet files
    parquet_files = sorted(parquet_dir.glob("part_*.parquet"))
    if not parquet_files:
        logger.error(f"No parquet files in {args.parquet_dir}")
        return

    completed = progress.get_completed()
    remaining = [f for f in parquet_files if f.name not in completed]

    logger.info("=" * 72)
    logger.info("Broccoli Classification Backfill (Multi-Process, In-Place)")
    logger.info("=" * 72)
    logger.info(f"Directory       : {args.parquet_dir}")
    logger.info(f"Parquet files   : {len(parquet_files)} total, {len(remaining)} remaining")
    logger.info(f"Worker processes : {args.workers}")
    logger.info(f"Connections/proc: {CONCURRENT_PER_PROCESS}")
    logger.info("=" * 72)

    if not remaining:
        logger.info("All files already processed!")
        return

    grand_total = 0
    grand_filled = 0
    grand_t0 = time.time()

    # Build work items: (parquet_file, worker_id, dry_run)
    work_items = [
        (str(pf), i % args.workers, args.dry_run)
        for i, pf in enumerate(remaining)
    ]

    # Each process gets its own asyncio loop, aiohttp session, token manager
    with multiprocessing.Pool(processes=args.workers) as pool:
        try:
            for filename, total, filled, elapsed in pool.imap_unordered(process_file, work_items):
                grand_total += total
                grand_filled += filled

                if not args.dry_run and total > 0:
                    progress.mark_done(filename)

                completed.add(filename)
                grand_elapsed = time.time() - grand_t0
                avg_qps = grand_total / grand_elapsed if grand_elapsed > 0 else 0

                logger.info(
                    f"[progress] {len(completed)}/{len(parquet_files)} files | "
                    f"{grand_total:,} rows | {grand_filled:,} classified | "
                    f"avg {avg_qps:.0f} QPS | {grand_elapsed:.0f}s"
                )
        except KeyboardInterrupt:
            logger.info("Shutdown requested — terminating workers...")
            pool.terminate()
            pool.join()

    grand_elapsed = time.time() - grand_t0
    logger.info("\n" + "=" * 72)
    logger.info("BACKFILL COMPLETE")
    logger.info(f"Total rows      : {grand_total:,}")
    logger.info(f"Classified      : {grand_filled:,}")
    logger.info(f"Time            : {grand_elapsed:.0f}s ({grand_elapsed/3600:.1f}h)")
    avg_qps = grand_total / grand_elapsed if grand_elapsed > 0 else 0
    logger.info(f"Avg QPS         : {avg_qps:.0f}")
    logger.info("=" * 72)


if __name__ == "__main__":
    main()
