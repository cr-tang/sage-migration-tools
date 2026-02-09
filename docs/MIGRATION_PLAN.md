# VT Data Migration Plan - Parquet Export Pipeline

> **Updated Architecture**: Direct Parquet export with in-place classification backfill for TiDB Lightning import

## Overview

Export VirusTotal file reputation data from GCS to Parquet format, with three distinct steps:

1. **Export** - Download, decompress, deduplicate, and export VT data to Parquet
2. **Backfill** - Enrich Parquet files with Broccoli ML classification (in-place)
3. **Import** - Bulk import Parquet files to TiDB using Lightning

---

## Step 1: Export VT Data to Parquet ⏳ IN PROGRESS

Download VT reports from GCS, decompress, deduplicate, and export to Parquet format.

**Script**: `vt_parquet_exporter.py`

```bash
# Export VT data (2020-11 to 2026-01)
python3 vt_parquet_exporter.py \
  --output-dir /data/vt_export \
  --start-date 20201101 \
  --end-date 20260130 \
  --workers 30

# Auto-resume from checkpoint (default behavior)
python3 vt_parquet_exporter.py --output-dir /data/vt_export
```

**Architecture**:
- **Multi-process**: 30 worker processes for CPU-bound tar.bz2 decompression + JSON parsing
- **Deduplication**: In-memory SHA256 set (binary checkpoint for fast restarts)
- **Checkpointing**: `.progress` (per-day status) + `.dedup_checkpoint` (SHA256 set)
- **Output Format**: Parquet with zstd compression, 500K rows per file

**Performance**:
- **Throughput**: ~17-18 files/sec on 32-vCPU GCE VM
- **Data Coverage**: 2020-11-01 to 2026-01-30 (~1570 days)
- **Dedup Rebuild**: 10-20 seconds (from binary checkpoint)
- **ETA**: ~30 hours for full export

**Key Fields Extracted**:
| Field | Description |
|-------|-------------|
| sha256 | Primary key |
| sha1 | Secondary index |
| md5 | Secondary index |
| positives | Number of AV detections |
| total | Total AV engines scanned |
| scan_date | VT scan timestamp |
| detection_names | Extracted from `scans`: `engine:result;engine:result;...` |
| classification | Initially NULL, filled by broccoli_backfill.py |
| date | Export date (YYYYMMDD) |

**Status**: ⏳ In Progress (Day 125/1570)

---

---

## Step 2: Backfill Classification ⏳ IN PROGRESS

Enrich Parquet files with Broccoli ML classification data from GCS (in-place updates).

**Script**: `broccoli_backfill.py`

```bash
# Backfill classification (4 worker processes, auto-resume)
python3 broccoli_backfill.py /data/vt_export --workers 4

# Custom worker count (e.g., 8 processes)
python3 broccoli_backfill.py /data/vt_export --workers 8

# Dry run (count SHA1s without GCS lookup)
python3 broccoli_backfill.py /data/vt_export --dry-run
```

**Architecture**:
- **Multi-process**: 4 worker processes (default), each with independent asyncio event loop
- **Concurrency**: 500 aiohttp connections per process (2000 total)
- **GCS Access**: Raw HTTP XML API (bypasses slow GCS Python SDK)
- **Lookup**: `gs://broccoli-enricher/latest-reports/{sha1}` → JSON with classification
- **Update Strategy**: In-place Parquet modification (no disk doubling)
- **Progress Tracking**: Multi-process safe with `fcntl` file locking

**Performance**:
- **Throughput**: ~6800 QPS aggregate (4 processes × ~1700 QPS each)
- **Error Rate**: 0% (with exponential backoff retry)
- **Timeouts**: 30s connect, 30s read, 60s total
- **ETA**: ~4.7 hours for 77 Parquet files (~2M unique SHA1s)

**Status**: ⏳ In Progress (16/77 files completed)

---

## Step 3: Import to TiDB ⏳ PENDING

Bulk import Parquet files to TiDB using Lightning.

**Transfer Parquet Files** (GCP → OCI):
```bash
# Option 1: rsync over SSH
rsync -avz --progress /data/vt_export/*.parquet \
  user@oci-tidb-host:/data/tidb_import/vt_export/

# Option 2: scp
scp /data/vt_export/*.parquet \
  user@oci-tidb-host:/data/tidb_import/vt_export/
```

**TiDB Lightning Import**:
```bash
# On OCI TiDB host
tiup tidb-lightning \
  --backend local \
  --sorted-kv-dir /data/tidb_import/sorted \
  --data-source-dir /data/vt_export/ \
  --tidb-host tidb-prod.cybereason.net \
  --tidb-port 4000 \
  --pd-addr pd-prod.cybereason.net:2379 \
  --config lightning.toml
```

**Lightning Config** (`lightning.toml`):
```toml
[lightning]
level = "info"

[tikv-importer]
backend = "local"
sorted-kv-dir = "/data/tidb_import/sorted"

[mydumper]
data-source-dir = "/data/vt_export"
no-schema = true

[tidb]
host = "tidb-prod.cybereason.net"
port = 4000
user = "root"
status-port = 10080
pd-addr = "pd-prod.cybereason.net:2379"
```

**Estimated Transfer**:
- **Data Size**: ~50-70 GB (compressed Parquet)
- **Transfer Time**: 2-4 hours over public internet (GCP → OCI)
- **Import Time**: 1-2 hours (Lightning local backend)

**Status**: ⏳ Pending (waiting for Step 2 completion)

---

## Data Sources Summary

| Source | Type | Location | Use |
|--------|------|----------|-----|
| vt-file-feeder-by-date | VT Reports | `gs://vt-file-feeder-by-date/{YYYYMMDD}/` | Step 1: Export raw scan data |
| broccoli-enricher | ML Classification | `gs://broccoli-enricher/latest-reports/{sha1}` | Step 2: Backfill classification |

---

## Scripts

| Script | Step | Purpose | Status |
|--------|------|---------|--------|
| `vt_parquet_exporter.py` | 1 | Export VT data to Parquet | ⏳ In Progress |
| `broccoli_backfill.py` | 2 | Backfill classification (in-place) | ⏳ In Progress |
| TiDB Lightning | 3 | Bulk import to TiDB | ⏳ Pending |

**Execution Order**:
1. `vt_parquet_exporter.py` - Export VT data with deduplication
2. `broccoli_backfill.py` - Fill classification from Broccoli ML
3. Transfer Parquet files (GCP → OCI)
4. TiDB Lightning import

---

## Current Progress

| Step | Description | Status | Progress |
|------|-------------|--------|----------|
| 1. Export | VT data → Parquet | ⏳ In Progress | Day 125/1570 (~8%) |
| 2. Backfill | Broccoli classification | ⏳ In Progress | 16/77 files (~21%) |
| 3. Transfer | Parquet (GCP → OCI) | ⏳ Pending | - |
| 4. Import | TiDB Lightning | ⏳ Pending | - |

---

## VM Environment

```
Host: phoenix-vt-feeder (GCE, 32 vCPU, 128 GB RAM)
IP: 34.26.16.84
SSH: ssh -i ~/path/to/ppem.pem centos@34.26.16.84
Data Dir: /data/vt_export/
Logs: /data/vt_export/export.log, /data/vt_export/backfill.log
```

---

## Quick Reference

```bash
# Check export progress
tail -f /data/vt_export/export.log

# Check backfill progress
tail -f /data/vt_export/backfill.log

# Check Parquet file count
ls -1 /data/vt_export/*.parquet | wc -l

# Check total output size
du -sh /data/vt_export/

# Check CPU/memory usage
top -b -n 1 | head -20
```

---

## Notes

1. **Detection Names Format**: Extracted from VT `scans` field as `engine:result;engine:result;...`
2. **Classification**: From Broccoli ML (MALWARE, RANSOMWARE, PUA, etc.) or NULL
3. **Deduplication**: SHA256-based in-memory set with binary checkpoint
4. **Case Sensitivity**: SHA1/SHA256 hashes are lowercase in GCS filenames
5. **Resume Support**: Both scripts auto-resume from checkpoints
6. **Parallel Execution**: `vt_parquet_exporter.py` and `broccoli_backfill.py` can run concurrently
