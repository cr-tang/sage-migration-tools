#!/usr/bin/env python3
"""Upload filtered parquet files to OCI Object Storage bucket.

Uses the OCI Python SDK which handles token refresh automatically,
avoiding the orphan process issues of the bash/xargs approach.

Usage:
    python3 upload_to_oci.py                                # Upload all VT files
    python3 upload_to_oci.py --parallel 2                   # 2 parallel uploads
    python3 upload_to_oci.py --dir ~/Downloads/other        # Different source dir
    python3 upload_to_oci.py --prefix mongo_data/           # Upload to subfolder
    python3 upload_to_oci.py --dry-run                      # Show what would upload
"""

import argparse
import os
import sys
import time
import fcntl
import subprocess
import threading
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

import oci


# === Configuration ===
NAMESPACE = "id9uy08ld7kh"
BUCKET = "vt-raw-data-tidb"
REGION = "us-ashburn-1"
PROFILE = "dev"
DEFAULT_SOURCE_DIR = os.path.expanduser("~/Downloads/vt_filtered_batch")


def refresh_session():
    """Refresh OCI session token using CLI."""
    try:
        result = subprocess.run(
            ["oci", "session", "refresh", "--profile", PROFILE],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0:
            print(f"  🔄 Session refreshed at {time.strftime('%H:%M:%S')}", flush=True)
            return True
        else:
            print(f"  ⚠️  Session refresh failed: {result.stderr.strip()}", flush=True)
            return False
    except Exception as e:
        print(f"  ⚠️  Session refresh error: {e}", flush=True)
        return False


def create_client() -> oci.object_storage.ObjectStorageClient:
    """Create OCI ObjectStorage client with security token auth."""
    config = oci.config.from_file(profile_name=PROFILE)
    token_file = config["security_token_file"]
    token = None
    with open(token_file, "r") as f:
        token = f.read()
    private_key = oci.signer.load_private_key_from_file(config["key_file"])
    signer = oci.auth.signers.SecurityTokenSigner(token, private_key)
    client = oci.object_storage.ObjectStorageClient(
        config={"region": REGION}, signer=signer
    )
    return client


def start_token_refresher(client_holder: list, interval_minutes: int = 45):
    """Background thread that refreshes the token and recreates client periodically."""
    def _refresher():
        while True:
            time.sleep(interval_minutes * 60)
            print(f"\n  ⏰ Auto-refreshing token (every {interval_minutes}m)...", flush=True)
            if refresh_session():
                try:
                    client_holder[0] = create_client()
                    print(f"  ✅ Client recreated with fresh token", flush=True)
                except Exception as e:
                    print(f"  ❌ Client recreation failed: {e}", flush=True)

    t = threading.Thread(target=_refresher, daemon=True)
    t.start()
    return t


def list_existing_objects(client: oci.object_storage.ObjectStorageClient, prefix: str) -> set:
    """List all objects already in the bucket under the given prefix."""
    existing = set()
    next_start = None
    while True:
        resp = client.list_objects(
            namespace_name=NAMESPACE,
            bucket_name=BUCKET,
            prefix=prefix,
            start=next_start,
            limit=1000,
        )
        for obj in resp.data.objects:
            name = obj.name
            # Extract basename from prefix path
            basename = name.split("/")[-1] if "/" in name else name
            if basename.endswith(".parquet"):
                existing.add(basename)
        next_start = resp.data.next_start_with
        if not next_start:
            break
    return existing


def mark_done(progress_file: Path, filename: str):
    """Thread-safe append to progress file."""
    with open(progress_file, "a") as f:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        f.write(filename + "\n")
        fcntl.flock(f.fileno(), fcntl.LOCK_UN)


def upload_file(
    client_holder: list,
    filepath: Path,
    prefix: str,
    progress_file: Path,
    total: int,
    max_retries: int = 5,
) -> bool:
    """Upload a single file to OCI. Refreshes client on auth failure. Returns True on success."""
    basename = filepath.name
    object_name = f"{prefix}{basename}"
    file_size_mb = filepath.stat().st_size / (1024 * 1024)

    for attempt in range(1, max_retries + 1):
        start = time.time()
        try:
            with open(filepath, "rb") as f:
                client_holder[0].put_object(
                    namespace_name=NAMESPACE,
                    bucket_name=BUCKET,
                    object_name=object_name,
                    put_object_body=f,
                    content_type="application/octet-stream",
                )
            elapsed = time.time() - start
            speed_mbps = file_size_mb / elapsed if elapsed > 0 else 0
            mark_done(progress_file, basename)
            done = sum(1 for _ in open(progress_file))
            print(
                f"  ✅ {basename} ({file_size_mb:.0f} MB, {elapsed:.0f}s, {speed_mbps:.1f} MB/s) [{done}/{total}]",
                flush=True,
            )
            return True
        except oci.exceptions.ServiceError as e:
            elapsed = time.time() - start
            if "authentication" in str(e.message).lower() or e.status == 401:
                print(f"  ⚠️  {basename}: Auth expired, refreshing client (attempt {attempt}/{max_retries})...", flush=True)
                time.sleep(5)
                try:
                    client_holder[0] = create_client()
                    print(f"  🔄 Client refreshed, retrying...", flush=True)
                except Exception as re:
                    print(f"  ⚠️  Client refresh failed: {re}, waiting 60s...", flush=True)
                    time.sleep(60)
                    try:
                        client_holder[0] = create_client()
                    except:
                        pass
                continue
            print(f"  ❌ {basename} FAILED ({elapsed:.0f}s): {e.message}", flush=True)
            return False
        except Exception as e:
            elapsed = time.time() - start
            print(f"  ❌ {basename} FAILED ({elapsed:.0f}s): {e}", flush=True)
            return False
    print(f"  ❌ {basename} FAILED after {max_retries} auth retries", flush=True)
    return False


def main():
    parser = argparse.ArgumentParser(description="Upload parquet files to OCI Object Storage")
    parser.add_argument("--dir", "-d", default=DEFAULT_SOURCE_DIR, help="Source directory")
    parser.add_argument("--prefix", default="vt_data/", help="OCI object prefix (subfolder)")
    parser.add_argument("--parallel", "-p", type=int, default=1, help="Parallel uploads")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be uploaded")
    parser.add_argument("--glob", default="*.parquet", help="File pattern to match")
    args = parser.parse_args()

    source_dir = Path(args.dir).expanduser()
    progress_file = source_dir / ".upload_progress"
    progress_file.touch()

    print("=" * 60)
    print("OCI Object Storage Upload")
    print("=" * 60)
    print(f"Source:   {source_dir}")
    print(f"Bucket:   oci://{NAMESPACE}/{BUCKET}")
    print(f"Region:   {REGION}")
    print(f"Prefix:   {args.prefix}")
    print(f"Parallel: {args.parallel}")
    print()

    # Create client
    print("Connecting to OCI...", flush=True)
    client = create_client()

    # Check what's already in the bucket
    print("Checking existing objects in bucket...", flush=True)
    existing_in_bucket = list_existing_objects(client, args.prefix)
    print(f"Objects already in bucket: {len(existing_in_bucket)}")

    # Merge into progress file
    if existing_in_bucket:
        already_in_progress = set()
        with open(progress_file) as f:
            already_in_progress = {line.strip() for line in f if line.strip()}
        new_entries = existing_in_bucket - already_in_progress
        if new_entries:
            with open(progress_file, "a") as f:
                for entry in sorted(new_entries):
                    f.write(entry + "\n")
            print(f"Synced {len(new_entries)} entries from bucket to progress file")

    # Read progress
    done_set = set()
    with open(progress_file) as f:
        done_set = {line.strip() for line in f if line.strip()}

    # Find all files
    all_files = sorted(source_dir.glob(args.glob))
    remaining = [f for f in all_files if f.name not in done_set]
    total = len(all_files)

    print(f"\nTotal files:      {total}")
    print(f"Already uploaded: {len(done_set)}")
    print(f"Remaining:        {len(remaining)}")
    print()

    if not remaining:
        print("✅ All files already uploaded!")
        return

    if args.dry_run:
        print("[DRY RUN] Would upload:")
        for f in remaining[:10]:
            print(f"  {f.name}")
        if len(remaining) > 10:
            print(f"  ... and {len(remaining) - 10} more")
        return

    # Upload
    start_time = time.time()
    success = 0
    failed = 0

    print(f"Starting upload at {time.strftime('%H:%M:%S')}...")
    print()

    # Use a mutable list so auth refresh propagates to all threads
    client_holder = [client]

    # Start background token refresher (every 45 min, token expires at 60 min)
    start_token_refresher(client_holder, interval_minutes=45)
    print("Started background token refresher (every 45 min)\n", flush=True)

    if args.parallel <= 1:
        # Sequential
        for filepath in remaining:
            if upload_file(client_holder, filepath, args.prefix, progress_file, total):
                success += 1
            else:
                failed += 1
    else:
        # Parallel with ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=args.parallel) as executor:
            futures = {
                executor.submit(
                    upload_file, client_holder, filepath, args.prefix, progress_file, total
                ): filepath
                for filepath in remaining
            }
            for future in as_completed(futures):
                if future.result():
                    success += 1
                else:
                    failed += 1

    # Summary
    elapsed = time.time() - start_time
    hours, remainder = divmod(int(elapsed), 3600)
    minutes, seconds = divmod(remainder, 60)
    print()
    print("=" * 60)
    print(f"Upload complete: {success} succeeded, {failed} failed")
    print(f"Total time: {hours}h {minutes}m {seconds}s")
    print(f"Finished at {time.strftime('%H:%M:%S')}")
    print("=" * 60)


if __name__ == "__main__":
    main()
